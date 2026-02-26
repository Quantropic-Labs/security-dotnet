namespace Quantropic.Security.Abstractions
{
    public interface ISrpServer
    {
        SrpSessionState GetSrpChallenge(string login, byte[] verifierBytes);
        string VerifySrpProof(SrpSessionState sessionState, string a, string m1);
    }
}