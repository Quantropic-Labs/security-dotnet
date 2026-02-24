namespace Quantropic.Security.Exceptions
{
    /// <summary>
    /// Base exception for all Quantropic Security library errors.
    /// </summary>
    public class SecurityException : Exception
    {
        public SecurityException() : base() { }
        public SecurityException(string message) : base(message) { }
        public SecurityException(string message, Exception inner) : base(message, inner) { }
    }
}