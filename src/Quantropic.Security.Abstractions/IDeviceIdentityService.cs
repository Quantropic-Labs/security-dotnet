namespace Quantropic.Security.Abstractions
{
    public interface IDeviceIdentityService
    {
        Task<DeviceIdentity> GetOrCreateAsync();
    }
}