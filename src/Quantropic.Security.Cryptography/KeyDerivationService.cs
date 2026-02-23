using System.Security.Cryptography;
using System.Text;
using Quantropic.Security.Abstractions;
using Quantropic.Security.Configuration;

namespace Quantropic.Security.Cryptography
{
    public class KeyDerivationService: IKeyDerivationService
    {
        public (byte[] Kek, string AuthHash) DeriveKeysFromPassword(string password, byte[] salt)
        {
            byte[] masterKey = Rfc2898DeriveBytes.Pbkdf2(password, salt, SecurityConstants.Pbkdf2IterationsDefault, HashAlgorithmName.SHA256, SecurityConstants.KeySizeBytes);
         
            byte[] emptySalt = []; 
            byte[] kek = HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, SecurityConstants.KeySizeBytes, emptySalt, Encoding.UTF8.GetBytes("AES-GCM-KEK-v1"));
            byte[] authBytes = HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, SecurityConstants.KeySizeBytes, emptySalt, Encoding.UTF8.GetBytes("SERVER-AUTH-HASH-v1"));

            Array.Clear(masterKey, 0, masterKey.Length);
            string authHashString = Convert.ToBase64String(authBytes);
            return (kek, authHashString);
        }
    }
}