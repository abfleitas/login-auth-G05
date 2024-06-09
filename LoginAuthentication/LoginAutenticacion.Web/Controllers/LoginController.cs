﻿using LoginAuthentication.LOGICA;
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
using LoginAutenticacion.Web.Models;

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
    public string Autenticar(string usuario, string rol)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, usuario),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("role", rol)
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

    [HttpPost]
    public IActionResult LoginUsuario(string username, string password)
    {
        Usuario usuarioEncontrado;
        string token = "";

        if (ModelState.IsValid)
        {
            usuarioEncontrado = _usuarioServicio.ObtenerUsuarioPorUsernameYPassword(username, password);

            if (usuarioEncontrado != null)
            {
                token = Autenticar(usuarioEncontrado.Username, usuarioEncontrado.Rol);
                
                if (token != "")
                {
                    return RedirectToAction("Bienvenida");
                }
            }
        }

        return RedirectToAction("Error");
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

