using System.Numerics;
using System.Security.Cryptography;
using Quantropic.Security.Abstractions;
using Quantropic.Security.Configuration;
using Quantropic.Security.Exceptions;

namespace Quantropic.Security.Srp.Server
{
    public class SrpServerService : ISrpServer
    {
        public SrpSessionState GetSrpChallenge(string login, byte[] verifierBytes)
        {
            BigInteger v = new(verifierBytes, isUnsigned: true, isBigEndian: true);

            byte[] bBytes = new byte[32];
            RandomNumberGenerator.Fill(bBytes);
            BigInteger b = new(bBytes, isUnsigned: true, isBigEndian: true);

            BigInteger gB = BigInteger.ModPow(SecurityConstants.g, b, SecurityConstants.N);
            BigInteger B = (SecurityConstants.k * v + gB) % SecurityConstants.N;

            var session = new SrpSessionState(
                login,
                Convert.ToBase64String(bBytes),
                Convert.ToBase64String(verifierBytes),
                Convert.ToBase64String(B.ToByteArray(isUnsigned: true, isBigEndian: true))
            );

            return session;
        }

        public string VerifySrpProof(SrpSessionState sessionState, string a, string m1)
        {
            BigInteger A = new(Convert.FromBase64String(a), isUnsigned: true, isBigEndian: true);
            BigInteger M1_client = new(Convert.FromBase64String(m1), isUnsigned: true, isBigEndian: true);
            BigInteger b = new(Convert.FromBase64String(sessionState!.PrivateKeyB), isUnsigned: true, isBigEndian: true);
            BigInteger v = new(Convert.FromBase64String(sessionState.Verifier), isUnsigned: true, isBigEndian: true);
            BigInteger B = new(Convert.FromBase64String(sessionState.PublicKeyB), isUnsigned: true, isBigEndian: true);

            if (v <= 0)
                throw new SrpVerificationException("Верификатор поврежден");

            if (A % SecurityConstants.N == 0)
                throw new SrpVerificationException("Не верное значение А");

            if (A <= 0 || A >= SecurityConstants.N)
                throw new SrpVerificationException("Некорректное значение A (out of range)");

            BigInteger u = CalculateSrpHash((A, 384), (B, 384));

            if (u == 0)
                throw new SrpVerificationException("Ошибка вычисления параметра u");

            BigInteger vU = BigInteger.ModPow(v, u, SecurityConstants.N);
            BigInteger S = BigInteger.ModPow((A * vU) % SecurityConstants.N, b, SecurityConstants.N);

            BigInteger M1_server = SrpEncoding.ComputeM1(A, B, S);
            
            byte[] m1ServerBytes = SrpEncoding.ToHashBytes(M1_server);
            byte[] m1ClientBytes = SrpEncoding.ToHashBytes(M1_client);
            
             if (!CryptographicOperations.FixedTimeEquals(m1ServerBytes, m1ClientBytes))
                throw new SrpVerificationException("Неверный пароль");

            BigInteger M2_server = SrpEncoding.ComputeM2(A, M1_client, S);

            return Convert.ToBase64String(SrpEncoding.ToHashBytes(M2_server));
        }

         private byte[] ToFixedLength(BigInteger value, int length)
        {
            byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);

            if (bytes.Length > length)
                throw new ArgumentException("Значение слишком большое для заданной длины", nameof(value));

            if (bytes.Length == length)
                return bytes;

            byte[] padded = new byte[length];
            Buffer.BlockCopy(bytes, 0, padded, length - bytes.Length, bytes.Length);

            return padded;
        }

        private BigInteger CalculateSrpHash(params (BigInteger value, int length)[] values)
        {
            using var sha256 = SHA256.Create();
            var all = new List<byte>();

            foreach (var (val, len) in values)
                all.AddRange(ToFixedLength(val, len));

            byte[] hash = sha256.ComputeHash(all.ToArray());
            return new BigInteger(hash, isUnsigned: true, isBigEndian: true);
        }
    }
}