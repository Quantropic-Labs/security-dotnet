using System.Security.Cryptography;
using System.Text;
using Quantropic.Security.Exceptions;

namespace Quantropic.Security.Configuration
{
    /// <summary>
    /// Configuration options for cryptographic operations.
    /// </summary>
    public class CryptoOptions
    {
        // === AES-GCM Parameters ===

        private int _nonceSiz = SecurityConstants.AesGcmNonceSize;
        public int NonceSize
        {
            get => _nonceSiz;
            set
            {
                if (_nonceSiz != SecurityConstants.AesGcmNonceSize)
                    throw new ArgumentOutOfRangeException(nameof(value), $"AES-GCM requires {SecurityConstants.AesGcmNonceSize}-byte nonce for standard compliance.");

                _nonceSiz = value;
            }
        }

        private int _tagSize = SecurityConstants.AesGcmTagSize;
        public int TagSize
        {
            get => _tagSize;
            set
            {
                if (value < SecurityConstants.AesGcmTagSizeMin || value > SecurityConstants.AesGcmTagSizeMax)
                    throw new ArgumentOutOfRangeException(nameof(value), $"Tag size must be between {SecurityConstants.AesGcmTagSizeMin} and {SecurityConstants.AesGcmTagSizeMax} bytes.");
                
                _tagSize = value;
            }
        }

        // === KDF Parameters ===

        private int _pbkdf2Iterations = SecurityConstants.Pbkdf2IterationsDefault;
        public int Pbkdf2Iterations
        {
            get => _pbkdf2Iterations;
            set
            {
                if (value < SecurityConstants.Pbkdf2IterationsMinimum)
                    throw new ArgumentOutOfRangeException(nameof(value), $"PBKDF2 iterations must be at least {SecurityConstants.Pbkdf2IterationsMinimum} for security.");

                _pbkdf2Iterations = value;
            }
        }

         // === Additional Features ===

        public byte[]? AssociatedData { get; set; }
        public bool CompressBeforeEncrypt { get; set; } = false;

        // === Validation ===
        public void Validate()
        {
            if (Pbkdf2Iterations < SecurityConstants.Pbkdf2IterationsMinimum)
                throw new SecurityException($"Pbkdf2Iterations ({Pbkdf2Iterations}) is below minimum safe value.");
            
            if (TagSize < SecurityConstants.AesGcmTagSizeMin || TagSize > SecurityConstants.AesGcmTagSizeMax)
                throw new SecurityException($"Tag size must be between {SecurityConstants.AesGcmTagSizeMin} and {SecurityConstants.AesGcmTagSizeMax} bytes.");
        }

         // === Presets ===

         public static CryptoOptions Default { get; } = new();

         public static CryptoOptions HightSecurity { get; } = new()
         {
            Pbkdf2Iterations = SecurityConstants.Pbkdf2IterationsRecommended  
         };

         public static CryptoOptions Legacy { get; } = new()
         {
            Pbkdf2Iterations = 100_000
         };

        // === Builder ===

        public static CryptoOptionsBuilder Create() => new();

        public sealed class CryptoOptionsBuilder
        {
            private readonly CryptoOptions _options = new();

            public CryptoOptionsBuilder WithNonceSize(int size)
            {
                _options.NonceSize = size;
                return this;
            }

            public CryptoOptionsBuilder WithTagSize(int size)
            {
                _options.TagSize = size;
                return this;
            }

             public CryptoOptionsBuilder WithPbkdf2Iterations(int iterations)
            {
                _options.Pbkdf2Iterations = iterations;
                return this;
            }

            public CryptoOptionsBuilder WithHighSecurityKdf()
            {
                _options.Pbkdf2Iterations = SecurityConstants.Pbkdf2IterationsRecommended;
                return this;
            }

            public CryptoOptionsBuilder WithAssociatedData(byte[]? aad)
            {
                _options.AssociatedData = aad;
                return this;
            }

            public CryptoOptionsBuilder WithAssociatedData(string aadText)
            {
                _options.AssociatedData = Encoding.UTF8.GetBytes(aadText);
                return this;
            }

            public CryptoOptions Build()
            {
                _options.Validate();
                return _options;
            }
        }
    }
}