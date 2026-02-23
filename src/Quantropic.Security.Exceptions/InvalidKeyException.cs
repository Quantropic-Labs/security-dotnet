namespace Quantropic.Security.Exceptions
{
    public class InvalidKeyException : SecurityException
    {
        public InvalidKeyException() : base("Invalid key: incorrect length or format.") { }
        public InvalidKeyException(string message) : base(message) { }
        public InvalidKeyException(string message, Exception inner) : base(message, inner) { }
    }
}