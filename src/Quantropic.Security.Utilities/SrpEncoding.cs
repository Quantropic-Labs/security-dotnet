using System.Numerics;
using Quantropic.Security.Utilities;

namespace Quantropic.Security.Configuration
{
 public static class SrpEncoding
    {
        /// <summary>
        /// Публичные ключи A, B и модуль N всегда сериализуются как ModulusSize байт
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static byte[] ToModulusBytes(BigInteger value) =>
            BigIntegerUtilities.ToFixedLengthBytes(value, SecurityConstants.ModulusSize);

        /// <summary>
        /// Хеши (u, M1, M2, x и т.д.) — всегда 32 байта (SHA-256)
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static byte[] ToHashBytes(BigInteger value) =>
            BigIntegerUtilities.ToFixedLengthBytes(value, 32);

        /// <summary>
        /// Хеш из публичных ключей (например, u = H(A, B))
        /// </summary>
        /// <param name="values"></param>
        /// <returns></returns>
        public static BigInteger HashModuli(params BigInteger[] values) =>
            BigIntegerUtilities.Hash(values.Select(ToModulusBytes).ToArray());

        /// <summary>
        ///  Хеш из смешанных значений: например, M1 = H(A, B, S)
        /// </summary>
        /// <param name="values"></param>
        /// <returns></returns>
        public static BigInteger HashMixed(params BigInteger[] values)
        {
            var buffers = new List<byte[]>();

            for (int i = 0; i < values.Length; i++)
                buffers.Add(ToModulusBytes(values[i]));

            return BigIntegerUtilities.Hash(buffers.ToArray());
        }

        public static BigInteger HashExplicit(params (BigInteger Value, bool IsModulus)[] args) =>
            BigIntegerUtilities.Hash(
                args.Select(x => x.IsModulus ? ToModulusBytes(x.Value) : ToHashBytes(x.Value)).ToArray()
            );

        public static BigInteger ComputeM1(BigInteger A, BigInteger B, BigInteger S) =>
        BigIntegerUtilities.Hash(
            ToModulusBytes(A),
            ToModulusBytes(B),
            ToModulusBytes(S)
        );

        public static BigInteger ComputeM2(BigInteger A, BigInteger M1, BigInteger S) =>
        BigIntegerUtilities.Hash(
            ToModulusBytes(A),
            ToHashBytes(M1),
            ToModulusBytes(S)
        );
    }
}