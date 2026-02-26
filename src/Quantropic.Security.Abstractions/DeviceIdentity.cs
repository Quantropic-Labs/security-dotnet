namespace Quantropic.Security.Abstractions
{
    public class DeviceIdentity
    {
        public string DeviceId { get; set; } = Guid.NewGuid().ToString();
        public string FingerprintHash { get; set; }
    }
}