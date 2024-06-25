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
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using LoginAuthentication.DATA.EntidadesEF;
using LoginAutenticacion.Web.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace LoginAutenticacion.Web.Controllers;

public class LoginController : Controller
{
    private IConfiguration _configuration;
    private readonly IUsuarioServicio _usuarioServicio;
    private readonly IGoogleAuthService _googleAuthService;

    public LoginController(IConfiguration configuration, IUsuarioServicio usuarioServicio, IGoogleAuthService googleAuthService)
    {
        _configuration = configuration;
        _usuarioServicio = usuarioServicio;
        _googleAuthService = googleAuthService;
    }
    public IActionResult Inicio()
    {
         var response = _googleAuthService.GetGoogleAuthUrl();
        ViewBag.response = response;
        return View();
    }

    public string Autenticar(string usuario, string rol)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, usuario),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("roles", rol)
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(_configuration["Jwt:Issuer"],
            _configuration["Jwt:Issuer"],
            claims,
            expires: DateTime.Now.AddMinutes(30),
            signingCredentials: creds);

        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

        Response.Cookies.Append("JwtToken", tokenString, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict
        });

        return tokenString;
    }

    public async Task<ActionResult> RedirectGoogle(string code)
    {
        var googleData = await _googleAuthService.GetGoogleUserDataAsync(code);
        if(!_usuarioServicio.ExisteUsuarioPorEmail(googleData.email))
        {
            var usuario = new Usuario
            {
                Nombre = googleData.given_name,
                Mail = googleData.email,
                Username = googleData.name,
                Password = "",
                Rol = "Usuario",
            };
            _usuarioServicio.RegistrarUsuario(usuario);
            ViewBag.username = googleData.name;
            return View("Bienvenida");
        }
        ViewBag.username = googleData.name;
        return View("Bienvenida");
    }

    [HttpPost]
    public IActionResult RegistrarUsuario(Usuario usuario)
    {
        if (!ModelState.IsValid)
            return RedirectToAction("Error");

        if (_usuarioServicio.ExisteUsuarioPorEmail(usuario.Mail))
        {
            ViewBag.ErrorMessage = $"Ya existe un usuario registrado con el email proporcionado.";
            
            var clientId = _configuration["OAuth:ClientID"];
            var url = _configuration["OAuth:Url"];
            ViewBag.response = GoogleAuth.GetAuthUrl(clientId, url);
            
            return View("Inicio");
        }

        _usuarioServicio.RegistrarUsuario(usuario);

        return RedirectToAction("Bienvenida");
    }

    [HttpPost]
    public IActionResult LoginUsuario(string username, string password)
    {
        Usuario usuarioEncontrado = _usuarioServicio.ObtenerUsuarioPorUsername(username);

        if (usuarioEncontrado == null)
        {
            ModelState.AddModelError("UserNotFound", "Usuario inexistente.");
        }
        else if (usuarioEncontrado.Password != password)
        {
            ModelState.AddModelError("InvalidPassword", "Credenciales incorrectas.");
        }
        else
        {
            string token = Autenticar(usuarioEncontrado.Username, usuarioEncontrado.Rol);

            if (!string.IsNullOrEmpty(token))
            {
                ViewBag.username = usuarioEncontrado.Username;
                ViewBag.esAdmin = usuarioEncontrado.Rol == "Admin";
                return View("Bienvenida");
            }
        }
        
        var clientId = _configuration["OAuth:ClientID"];
        var url = _configuration["OAuth:Url"];
        ViewBag.response = GoogleAuth.GetAuthUrl(clientId, url);

        return View("Inicio");
    }

    [Authorize]
    public IActionResult Bienvenida()
    {
        return View();
    }

    [Authorize(Roles = "Admin")]
    public IActionResult Admin()
    {
        var usuarios = _usuarioServicio.ObtenerTodos();
        return View(usuarios);
    }

    public async Task<IActionResult> Logout()
    {
        Response.Cookies.Delete("JwtToken");
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        return RedirectToAction("Inicio");
    }

    public IActionResult Error()
    {
        return View();
    }

}

