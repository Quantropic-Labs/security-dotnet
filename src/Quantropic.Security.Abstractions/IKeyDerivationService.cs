namespace Quantropic.Security.Abstractions
{
    public interface IKeyDerivationService
    {
        (byte[] Kek, string AuthHash) DeriveKeysFromPassword(string password, byte[] salt);
    }
}