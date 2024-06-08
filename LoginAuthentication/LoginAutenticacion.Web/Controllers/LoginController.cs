using LoginAuthentication.LOGICA;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.Security.Claims;
using System.Text;
using GoogleAuthentication.Services;
using System;
using LoginAutenticacion.Web.Models;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.IdentityModel.Tokens.Jwt;

namespace LoginAutenticacion.Web.Controllers;

public class LoginController : Controller
{
    private IConfiguration _configuration;
    private readonly IUsuarioServicio usuarioServicio;

    public LoginController(IConfiguration configuration, IUsuarioServicio usuarioServicio)
    {
        _configuration = configuration;
        this.usuarioServicio = usuarioServicio;
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
        var usuarios = this.usuarioServicio.ObtenerTodos();
        return Json(usuarios);
    }

    [HttpPost]
    public IActionResult Autenticar(UsuarioModel usuario)
    {
        if (ModelState.IsValid)
        {
            if (usuario.Username == "admin" && usuario.Password == "admin")
            {
                var claims = new[]
                {
                    new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Sub, usuario.Username),
                    new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim("role", usuario.Rol)
                };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var token = new JwtSecurityToken(_configuration["Jwt:Issuer"],
                    _configuration["Jwt:Issuer"],
                    claims,
                    expires: DateTime.Now.AddMinutes(30),
                    signingCredentials: creds);

                var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

                //return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
                Response.Cookies.Append("JwtToken", tokenString, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict
                });

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

    [Authorize]
    public IActionResult Bienvenida()
    {
        return View();
    }

    [Authorize(Roles = "Admin")]
    public IActionResult Admin()
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

