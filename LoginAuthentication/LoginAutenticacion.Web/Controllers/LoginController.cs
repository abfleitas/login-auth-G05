using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace LoginAutenticacion.Web.Controllers;

public class LoginController : Controller
{
    private IConfiguration _configuration;

    public LoginController(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    public IActionResult Inicio()
    {
        return View();
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

