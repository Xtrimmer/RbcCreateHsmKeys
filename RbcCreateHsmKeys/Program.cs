using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;
using Microsoft.Data.SqlClient.AlwaysEncrypted.AzureKeyVaultProvider;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace AKVEnclaveExample
{
    class Program
    {
        static readonly string s_algorithm = "RSA_OAEP";

        // ********* Provide details here ***********
        static readonly string s_akvUrl = "https://{KeyVaultName}.managedhsm-preview.azure.net/keys/{Key}/{KeyIdentifier}";
        static readonly string s_clientId = "{Application_Client_ID}";
        static readonly string s_clientSecret = "{Application_Client_Secret}";
        static readonly string s_connectionString = "Server={Server}; Database={database}; Integrated Security=true; Column Encryption Setting=Enabled; Attestation Protocol={protocol}; Enclave Attestation Url = {attestation_url};";
        static readonly string s_trustedEndPoint = "https://managedhsm-preview.azure.net";
        // ******************************************

        static void Main(string[] args)
        {
            // Initialize AKV provider
            SqlColumnEncryptionAzureKeyVaultProvider sqlColumnEncryptionAzureKeyVaultProvider = new SqlColumnEncryptionAzureKeyVaultProvider(AzureActiveDirectoryAuthenticationCallback, s_trustedEndPoint);

            // Register AKV provider
            SqlConnection.RegisterColumnEncryptionKeyStoreProviders(customProviders: new Dictionary<string, SqlColumnEncryptionKeyStoreProvider>(capacity: 1, comparer: StringComparer.OrdinalIgnoreCase)
                {
                    { SqlColumnEncryptionAzureKeyVaultProvider.ProviderName, sqlColumnEncryptionAzureKeyVaultProvider}
                });
            Console.WriteLine("AKV provider Registered");

            // Create connection to database
            using (SqlConnection sqlConnection = new SqlConnection(s_connectionString))
            {
                string cmkName = "CMK_WITH_AKV";
                string cekName = "CEK_WITH_AKV";
                string tblName = "AKV_TEST_TABLE";
                    sqlConnection.Open();

                    // Create Column Master Key with AKV Url
                    createCMK(sqlConnection, cmkName, sqlColumnEncryptionAzureKeyVaultProvider);
                    Console.WriteLine("Column Master Key created.");

                    // Create Column Encryption Key
                    createCEK(sqlConnection, cmkName, cekName, sqlColumnEncryptionAzureKeyVaultProvider);
                    Console.WriteLine("Column Encryption Key created.");

                    // Create Table with Encrypted Columns
                    createTbl(sqlConnection, cekName, tblName);
                    Console.WriteLine("Table created with Encrypted columns.");
            }
        }

        public static async Task<string> AzureActiveDirectoryAuthenticationCallback(string authority, string resource, string scope)
        {
            var authContext = new AuthenticationContext(authority);
            ClientCredential clientCred = new ClientCredential(s_clientId, s_clientSecret);
            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);
            if (result == null)
            {
                throw new InvalidOperationException($"Failed to retrieve an access token for {resource}");
            }

            return result.AccessToken;
        }

        private static void createCMK(SqlConnection sqlConnection, string cmkName, SqlColumnEncryptionAzureKeyVaultProvider sqlColumnEncryptionAzureKeyVaultProvider)
        {
            string KeyStoreProviderName = SqlColumnEncryptionAzureKeyVaultProvider.ProviderName;

            byte[] cmkSign = sqlColumnEncryptionAzureKeyVaultProvider.SignColumnMasterKeyMetadata(s_akvUrl, true);
            string cmkSignStr = string.Concat("0x", BitConverter.ToString(cmkSign).Replace("-", string.Empty));

            string sql =
                $@"CREATE COLUMN MASTER KEY [{cmkName}]
                    WITH (
                        KEY_STORE_PROVIDER_NAME = N'{KeyStoreProviderName}',
                        KEY_PATH = N'{s_akvUrl}',
                        ENCLAVE_COMPUTATIONS (SIGNATURE = {cmkSignStr})
                    );";

            using (SqlCommand command = sqlConnection.CreateCommand())
            {
                command.CommandText = sql;
                command.ExecuteNonQuery();
            }
        }

        private static void createCEK(SqlConnection sqlConnection, string cmkName, string cekName, SqlColumnEncryptionAzureKeyVaultProvider sqlColumnEncryptionAzureKeyVaultProvider)
        {
            string sql =
                $@"CREATE COLUMN ENCRYPTION KEY [{cekName}] 
                    WITH VALUES (
                        COLUMN_MASTER_KEY = [{cmkName}],
                        ALGORITHM = '{s_algorithm}', 
                        ENCRYPTED_VALUE = {GetEncryptedValue(sqlColumnEncryptionAzureKeyVaultProvider)}
                    )";

            using (SqlCommand command = sqlConnection.CreateCommand())
            {
                command.CommandText = sql;
                command.ExecuteNonQuery();
            }
        }

        private static string GetEncryptedValue(SqlColumnEncryptionAzureKeyVaultProvider sqlColumnEncryptionAzureKeyVaultProvider)
        {
            byte[] plainTextColumnEncryptionKey = new byte[32];
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(plainTextColumnEncryptionKey);

            byte[] encryptedColumnEncryptionKey = sqlColumnEncryptionAzureKeyVaultProvider.EncryptColumnEncryptionKey(s_akvUrl, s_algorithm, plainTextColumnEncryptionKey);
            string EncryptedValue = string.Concat("0x", BitConverter.ToString(encryptedColumnEncryptionKey).Replace("-", string.Empty));
            return EncryptedValue;
        }

        private static void createTbl(SqlConnection sqlConnection, string cekName, string tblName)
        {
            string ColumnEncryptionAlgorithmName = @"AEAD_AES_256_CBC_HMAC_SHA_256";

            string sql =
                    $@"CREATE TABLE [dbo].[{tblName}]
                (
                    [CustomerId] [int] ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY = [{cekName}], ENCRYPTION_TYPE = RANDOMIZED, ALGORITHM = '{ColumnEncryptionAlgorithmName}'),
                    [FirstName] [nvarchar](50) COLLATE Latin1_General_BIN2 ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY = [{cekName}], ENCRYPTION_TYPE = RANDOMIZED, ALGORITHM = '{ColumnEncryptionAlgorithmName}'),
                    [LastName] [nvarchar](50) COLLATE Latin1_General_BIN2 ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY = [{cekName}], ENCRYPTION_TYPE = RANDOMIZED, ALGORITHM = '{ColumnEncryptionAlgorithmName}')
                )";

            using (SqlCommand command = sqlConnection.CreateCommand())
            {
                command.CommandText = sql;
                command.ExecuteNonQuery();
            }
        }
    }
}