namespace Quantropic.Security.Exceptions
{
    public class DecryptionException : SecurityException
    {
        public DecryptionException() : base("Decrypted failed: authentication tag mismatch or corrupted data.") { }
        public DecryptionException(string message) : base(message) { }
        public DecryptionException(string message, Exception inner) : base(message, inner) { }
    }
}