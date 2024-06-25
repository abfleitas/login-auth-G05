using Microsoft.Extensions.Configuration;

namespace LoginAuthentication.LOGICA;

public interface IOAuthConfigServicio
{
    string ObtenerClientId();
    string ObtenerUrl();
    string ObtenerClientSecret();
}

public class OAuthConfigServicio : IOAuthConfigServicio
{
    private readonly IConfiguration _configuration;

    public OAuthConfigServicio(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public string ObtenerClientId()
    {
        return _configuration["OAuth:ClientID"];
    }

    public string ObtenerUrl()
    {
        return _configuration["OAuth:Url"];
    }

    public string ObtenerClientSecret()
    {
        return _configuration["OAuth:ClientSecret"];
    }
}