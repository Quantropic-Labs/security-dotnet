using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Quantropic.Security.Abstractions;
using Quantropic.Security.Configuration;

namespace Quantropic.Security.Cryptography
{
    public class CryptoService : ICryptoServices
    {
        public string EncryptedData<T>(T data, byte[] key)
        {
            string jsonString = JsonSerializer.Serialize(data);
            byte[] plainBytes = Encoding.UTF8.GetBytes(jsonString);

            var nonce = new byte[SecurityConstants.AesGcmNonceSize];
            RandomNumberGenerator.Fill(nonce);

            var cipherText = new byte[plainBytes.Length];
            var tag = new byte[SecurityConstants.AesGcmTagSize];

            using var aes = new AesGcm(key, SecurityConstants.AesGcmTagSize);
            aes.Encrypt(nonce, plainBytes, cipherText, tag);

            var result = new byte[SecurityConstants.AesGcmNonceSize + cipherText.Length + SecurityConstants.AesGcmTagSize];
            
            Buffer.BlockCopy(nonce, 0, result, 0, SecurityConstants.AesGcmNonceSize);
            Buffer.BlockCopy(cipherText, 0, result, SecurityConstants.AesGcmNonceSize, cipherText.Length);
            Buffer.BlockCopy(tag, 0, result, SecurityConstants.AesGcmNonceSize + cipherText.Length, SecurityConstants.AesGcmTagSize);

            return Convert.ToBase64String(result);
        }

        public T? DecryptedData<T>(string encryptedBase64, byte[] key)
        {
            if (string.IsNullOrEmpty(encryptedBase64)) 
                return default;

            byte[] encryptedBytes = Convert.FromBase64String(encryptedBase64);

            if (encryptedBytes.Length < SecurityConstants.AesGcmNonceSize + SecurityConstants.AesGcmTagSize)
                throw new ArgumentException($"Encrypted data is too short. Expected at least {SecurityConstants.AesGcmNonceSize + SecurityConstants.AesGcmTagSize} bytes, but got {encryptedBytes.Length}");

            var nonce = encryptedBytes.AsSpan(0, SecurityConstants.AesGcmNonceSize);
            var tag = encryptedBytes.AsSpan(encryptedBytes.Length - SecurityConstants.AesGcmTagSize, SecurityConstants.AesGcmTagSize);
            var cipherText = encryptedBytes.AsSpan(SecurityConstants.AesGcmNonceSize, encryptedBytes.Length - SecurityConstants.AesGcmNonceSize - SecurityConstants.AesGcmTagSize);

            var plainBytes = new byte[cipherText.Length];

            using var aes = new AesGcm(key, SecurityConstants.AesGcmTagSize);
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