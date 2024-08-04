namespace DemoIdentityFull.Services;

public interface ISMSSender
{
    Task<bool> SendSmsAsync(string to, string message);
}
