namespace Quantropic.Security.Abstractions
{
    public record SrpSessionState(string Login, string PrivateKeyB, string Verifier, string PublicKeyB);
}