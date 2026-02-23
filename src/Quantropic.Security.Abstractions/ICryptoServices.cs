namespace Quantropic.Security.Abstractions
{
    public interface ICryptoServices
    {
        string EncryptedData<T>(T data, byte[] key);
        T? DecryptedData<T>(string encryptedBase64, byte[] key);
        byte[] GenerateRandomBytes(int length = 32);
    }
}