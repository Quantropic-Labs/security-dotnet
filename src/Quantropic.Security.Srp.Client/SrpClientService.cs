using System.Numerics;
using Quantropic.Security.Abstractions;
using Quantropic.Security.Configuration;
using Quantropic.Security.Cryptography;
using Quantropic.Security.Utilities;

namespace Quantropic.Security.Srp.Client
{
    public class SrpClientService : ISrpClient
    {
        public (string A, string M1, string S) GenerateSrpProof(string password, string saltBase64, string B_base64)    
        {
            KeyDerivationService keyDerivationService = new();
            CryptoService cryptoService = new();

            string cleanSalt = saltBase64.Replace('-', '+').Replace('_', '/');
            byte[] salt = Convert.FromBase64String(cleanSalt);
            var (_, AuthHash) = keyDerivationService.DeriveKeysFromPassword(password, salt);
            byte[] authHashBytes = Convert.FromBase64String(AuthHash);
            BigInteger x = new(authHashBytes, isBigEndian: true, isUnsigned: true);

            byte[] aBytes = cryptoService.GenerateRandomBytes(32);
            BigInteger a = new(aBytes, isBigEndian: true, isUnsigned: true);

            BigInteger A = BigInteger.ModPow(SecurityConstants.g, a, SecurityConstants.N);

            byte[] B_bytes = Convert.FromBase64String(B_base64);
            BigInteger B = new(B_bytes, isBigEndian: true, isUnsigned: true);

            BigInteger u = SrpEncoding.HashModuli(A, B); 
            
            BigInteger gX = BigInteger.ModPow(SecurityConstants.g, x, SecurityConstants.N);
            BigInteger term = (SecurityConstants.k * gX) % SecurityConstants.N;
            BigInteger baseBigInt = (B - term + SecurityConstants.N) % SecurityConstants.N;
            BigInteger exponent = a + (u * x);
            BigInteger S = BigInteger.ModPow(baseBigInt, exponent, SecurityConstants.N);

            BigInteger M1 = SrpEncoding.ComputeM1(A, B, S); 

            return (
                A: Convert.ToBase64String(SrpEncoding.ToModulusBytes(A)),
                M1: Convert.ToBase64String(SrpEncoding.ToHashBytes(M1)),
                S: Convert.ToBase64String(SrpEncoding.ToModulusBytes(S)));
        }

        public string GenerateSrpVerifier(string authHash)
        {
            byte[] authHashBytes = Convert.FromBase64String(authHash);
            BigInteger x = new(authHashBytes, isUnsigned: true, isBigEndian: true);
            BigInteger v = BigInteger.ModPow(SecurityConstants.g, x, SecurityConstants.N);

            return Convert.ToBase64String(SrpEncoding.ToModulusBytes(v));
        }

        public bool VerifyServerM2(string a, string m1, string s, string serverM2)
        {
            BigInteger A = BigIntegerUtilities.FromBase64(a);
            BigInteger M1 = BigIntegerUtilities.FromBase64(m1);
            BigInteger S = BigIntegerUtilities.FromBase64(s);
            
            BigInteger computedM2 = SrpEncoding.ComputeM2(A, M1, S);

            string computedM2Base64 = Convert.ToBase64String(SrpEncoding.ToHashBytes(computedM2));
            return serverM2 == computedM2Base64;
        }
    }
}