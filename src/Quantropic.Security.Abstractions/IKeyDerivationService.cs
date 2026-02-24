using Quantropic.Security.Configuration;

namespace Quantropic.Security.Abstractions
{
    public interface IKeyDerivationService
    {
        (byte[] Kek, string AuthHash) DeriveKeysFromPassword(string password, byte[] salt);
        (byte[] Kek, string AuthHash) DeriveKeysFromPassword(string password, byte[] salt, int? pbkdf2Iterations = null);
        public (byte[] Kek, string AuthHash) DeriveKeysFromPassword(string password, byte[] salt, CryptoOptions? options = null);
    }
}