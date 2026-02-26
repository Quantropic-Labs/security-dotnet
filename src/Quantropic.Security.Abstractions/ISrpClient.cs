namespace Quantropic.Security.Abstractions
{
    public interface ISrpClient
    {
        string GenerateSrpVerifier(string authHash);
        (string A, string M1, string S) GenerateSrpProof(string password, string saltBase65, string bBase65);
        bool VerifyServerM2(string A, string M1, string S, string ServerM2);
    }
}