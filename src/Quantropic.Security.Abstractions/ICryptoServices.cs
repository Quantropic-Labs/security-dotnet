using Quantropic.Security.Configuration;

namespace Quantropic.Security.Abstractions
{
    public interface ICryptoServices
    {
        string EncryptedData<T>(T data, byte[] key);
        public string EncryptedData<T>(T data, byte[] key, int? pbkdf2Iterations = null);
        public string EncryptedData<T>(T data, byte[] key, CryptoOptions? options = null);
        T? DecryptData<T>(string encryptedBase64, byte[] key);
        T? DecryptData<T>(string encryptedBase64, byte[] key, CryptoOptions? options = null);
        byte[] GenerateRandomBytes(int length = 32);
    }
}