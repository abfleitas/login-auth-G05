using System.Threading.Tasks;
using LoginAuthentication.DATA.EntidadesEF;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using GoogleAuthentication.Services;

namespace LoginAuthentication.LOGICA
{
    public interface IGoogleAuthService
    {
        Task<GoogleUserData> GetGoogleUserDataAsync(string code);
        string GetGoogleAuthUrl();
    }
    public class GoogleAuthService:IGoogleAuthService
    {
        private readonly IConfiguration _configuration;

        public GoogleAuthService(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        public async Task<GoogleUserData> GetGoogleUserDataAsync(string code)
        {
            var clientId = _configuration["OAuth:ClientID"];
            var url = _configuration["OAuth:Url"];
            var clientSecret = _configuration["OAuth:ClientSecret"];

            var token = await GoogleAuth.GetAuthAccessToken(code, clientId, clientSecret, url);
            var userProfile = await GoogleAuth.GetProfileResponseAsync(token.AccessToken.ToString());
            return JsonConvert.DeserializeObject<GoogleUserData>(userProfile);
        }

        public string GetGoogleAuthUrl()
        {
            var clientId = _configuration["OAuth:ClientID"];
            var url = _configuration["OAuth:Url"];
            return GoogleAuth.GetAuthUrl(clientId, url);
        }
    }
}
