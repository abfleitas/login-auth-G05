using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace LoginAuthentication.LOGICA;

public interface IEmailServicio
{
    Task EnviarEmailAsync(string email, string subject, string message);
}

public class EmailServicio : IEmailServicio
{
    private readonly SmtpClient _smtpClient;
    private readonly IConfiguration _configuration;

    public EmailServicio(IConfiguration configuration)
    {
        _configuration = configuration;
        _smtpClient = new SmtpClient
        {
            Host = "smtp.sendgrid.net",
            Port = 587,
            EnableSsl = true,
            Credentials = new NetworkCredential("apikey", _configuration["SendGrid:ApiKey"])
        };
    }

    public async Task EnviarEmailAsync(string email, string subject, string message)
    {
        var mailMessage = new MailMessage
        {
            From = new MailAddress("ignacio.disney.api@gmail.com"),
            To = { email },
            Subject = subject,
            Body = message
        };

        await _smtpClient.SendMailAsync(mailMessage);
    }
}