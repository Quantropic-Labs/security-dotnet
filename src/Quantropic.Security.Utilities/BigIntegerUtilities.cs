using System.Numerics;
using System.Security.Cryptography;

namespace Quantropic.Security.Utilities
{
    public static class BigIntegerUtilities
    {
        /// <summary>
        /// Преобразует BigInteger в big-endian байтовый массив фиксированной длины.
        /// Если значение слишком большое — обрезается слева (MSB).
        /// Если слишком короткое — дополняется нулями слева.
        /// </summary>
        public static byte[] ToFixedLengthBytes(BigInteger value, int length)
        {
            if (length <= 0) throw 
                new ArgumentException("Длина должна быть положительной.", nameof(length));

            byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);

            if (bytes.Length == length)
                return bytes;

            byte[] result = new byte[length];

            if (bytes.Length > length)
                Buffer.BlockCopy(bytes, bytes.Length - length, result, 0, length);
            else
                Buffer.BlockCopy(bytes, 0, result, length - bytes.Length, bytes.Length);

            return result;
        }

        public static BigInteger FromBase64(string base64)
        {
            if (string.IsNullOrEmpty(base64))
                throw new ArgumentNullException(nameof(base64));

            string cleaned = base64.Replace('-', '+').Replace('_', '/');
            int mod = cleaned.Length % 4;

            if (mod != 0)
                cleaned += new string('=', 4 - mod);

            byte[] bytes = Convert.FromBase64String(cleaned);

            return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        }

        /// <summary>
        /// Хэширует набор байтовых массивов с помощью SHA-256 и возвращает результат как BigInteger.
        /// </summary>
        public static BigInteger Hash(params byte[][] buffers)
        {
            using var ms = new MemoryStream();

            foreach (var buffer in buffers)
                ms.Write(buffer);
                
            byte[] hash = SHA256.HashData(ms.ToArray());

            return new BigInteger(hash, isUnsigned: true, isBigEndian: true);
        }
    }
}