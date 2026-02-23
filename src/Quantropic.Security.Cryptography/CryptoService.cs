using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Quantropic.Security.Abstractions;
using Quantropic.Security.Utilities;

namespace Quantropic.Security.Cryptography
{
    public class CryptoService : ICryptoServices
    {
        public string EncryptedData<T>(T data, byte[] key)
        {
            string jsonString = JsonSerializer.Serialize(data);
            byte[] plainBytes = Encoding.UTF8.GetBytes(jsonString);

            var nonce = new byte[SecurityConstants.NonceSize];
            RandomNumberGenerator.Fill(nonce);

            var cipherText = new byte[plainBytes.Length];
            var tag = new byte[SecurityConstants.TagSize];

            using var aes = new AesGcm(key, SecurityConstants.TagSize);
            aes.Encrypt(nonce, plainBytes, cipherText, tag);

            var result = new byte[SecurityConstants.NonceSize + cipherText.Length + SecurityConstants.TagSize];
            
            Buffer.BlockCopy(nonce, 0, result, 0, SecurityConstants.NonceSize);
            Buffer.BlockCopy(cipherText, 0, result, SecurityConstants.NonceSize, cipherText.Length);
            Buffer.BlockCopy(tag, 0, result, SecurityConstants.NonceSize + cipherText.Length, SecurityConstants.TagSize);

            return Convert.ToBase64String(result);
        }

        public T? DecryptedData<T>(string encryptedBase64, byte[] key)
        {
            if (string.IsNullOrEmpty(encryptedBase64)) 
                return default;

            byte[] encryptedBytes = Convert.FromBase64String(encryptedBase64);

            if (encryptedBytes.Length < SecurityConstants.NonceSize + SecurityConstants.TagSize)
                throw new ArgumentException($"Encrypted data is too short. Expected at least {SecurityConstants.NonceSize + SecurityConstants.TagSize} bytes, but got {encryptedBytes.Length}");

            var nonce = encryptedBytes.AsSpan(0, SecurityConstants.NonceSize);
            var tag = encryptedBytes.AsSpan(encryptedBytes.Length - SecurityConstants.TagSize, SecurityConstants.TagSize);
            var cipherText = encryptedBytes.AsSpan(SecurityConstants.NonceSize, encryptedBytes.Length - SecurityConstants.NonceSize - SecurityConstants.TagSize);

            var plainBytes = new byte[cipherText.Length];

            using var aes = new AesGcm(key, SecurityConstants.TagSize);
            aes.Decrypt(nonce, cipherText, tag, plainBytes);

            string jsonString = Encoding.UTF8.GetString(plainBytes);

            return JsonSerializer.Deserialize<T>(jsonString);
        }

        public byte[] GenerateRandomBytes(int length = 32)
        {
            var bytes = new byte[length];
            RandomNumberGenerator.Fill(bytes);
            return bytes;
        }
    }
}