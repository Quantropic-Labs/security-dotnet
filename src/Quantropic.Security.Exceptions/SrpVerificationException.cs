namespace Quantropic.Security.Exceptions
{
    public class SrpVerificationException : SecurityException
    {
        public SrpVerificationException() : base("Внутренняя ошибка данных: верификатор поврежден.") { }
        public SrpVerificationException(string message) : base(message) { }
        public SrpVerificationException(string message, Exception inner) : base(message, inner) { }
    }
}