namespace DemoIdentityFull.Services;

public interface ISenderEmail
{
    Task SendEmailAsync(string ToEmail, string Subject, string Body, bool IsBodyHtml = false);
}
