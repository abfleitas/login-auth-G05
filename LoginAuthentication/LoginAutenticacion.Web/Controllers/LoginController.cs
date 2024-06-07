using LoginAuthentication.LOGICA;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using GoogleAuthentication.Services;
using System;
using LoginAuthentication.DATA.EntidadesEF;

namespace LoginAutenticacion.Web.Controllers;

public class LoginController : Controller
{
    private IConfiguration _configuration;
    private readonly IUsuarioServicio _usuarioServicio;

    public LoginController(IConfiguration configuration, IUsuarioServicio usuarioServicio)
    {
        _configuration = configuration;
        _usuarioServicio = usuarioServicio;
    }
    public IActionResult Inicio()
    {
        var clientId = _configuration["OAuth:ClientID"];
        var url = _configuration["OAuth:Url"];

        var response = GoogleAuth.GetAuthUrl(clientId, url);
        ViewBag.response = response;
        return View();
    }
    [HttpGet]
    public IActionResult Test()
    {
        var usuarios = _usuarioServicio.ObtenerTodos();
        return Json(usuarios);
    }

    [HttpPost]
    public IActionResult Autenticar(Models.UsuarioModel usuario)
    {
        if (ModelState.IsValid)
        {
            if (usuario.Username == "admin" && usuario.Password == "admin")
            {
                var claims = new[]
                {
                new Claim(JwtRegisteredClaimNames.Sub, usuario.Username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var token = new JwtSecurityToken(_configuration["Jwt:Issuer"],
                    _configuration["Jwt:Issuer"],
                    claims,
                    expires: DateTime.Now.AddMinutes(30),
                    signingCredentials: creds);

                //return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
                return RedirectToAction("Bienvenida");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Usuario o contraseña incorrectos");
            }
        }
        return RedirectToAction("Error");
    }

    public async Task<ActionResult> RedirectGoogle(string code)
    {
        var clientId = _configuration["OAuth:ClientID"];
        var url = _configuration["OAuth:Url"];
        var clientSecret = _configuration["OAuth:ClientSecret"];

        var token = await GoogleAuth.GetAuthAccessToken(code, clientId, clientSecret, url);
        var userProfile = await GoogleAuth.GetProfileResponseAsync(token.AccessToken.ToString());
        return RedirectToAction("Bienvenida");
    }

    [HttpPost]
    public IActionResult RegistrarUsuario(Usuario usuario)
    {
        if (!ModelState.IsValid)
            return RedirectToAction("Error");

        _usuarioServicio.RegistrarUsuario(usuario);

        return RedirectToAction("Bienvenida");

    }

    public IActionResult Bienvenida()
    {
        return View();
    }

    public IActionResult Logout()
    {
        return RedirectToAction("Inicio");
    }

    public IActionResult Error()
    {
        return View();
    }
}

