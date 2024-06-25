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
    private readonly IUsuarioServicio _usuarioServicio;
    private readonly IJwtServicio _jwtServicio;
    private readonly IEmailServicio _emailServicio;
    private readonly IGoogleAuthService _googleAuthService;
    private readonly IConfiguration _configuration;


    public LoginController(IEmailServicio emailServicio, IGoogleAuthService googleAuthService,
        IUsuarioServicio usuarioServicio, IJwtServicio jwtServicio, IConfiguration configuration)
    {
        _usuarioServicio = usuarioServicio;
        _jwtServicio = jwtServicio;
        _googleAuthService = googleAuthService;
        _emailServicio = emailServicio;
        _configuration = configuration;

    }

    public IActionResult Inicio()
    {
        var response = _googleAuthService.GetGoogleAuthUrl();
        ViewBag.response = response;
        return View();
    }

    public async Task<ActionResult> RedirectGoogle(string code)
    {
        var googleData = await _googleAuthService.GetGoogleUserDataAsync(code);
        if (!_usuarioServicio.ExisteUsuarioPorEmail(googleData.email))
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
    public async Task<IActionResult> RegistrarUsuario(Usuario usuario)
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

        string token = _jwtServicio.GenerarTokenDeVerificacionDeCorreo(usuario.Mail, usuario.Id.ToString());

        string verificationLink = $"https://localhost:8080/verificar_email?token={token}";
        await _emailServicio.EnviarEmailAsync(usuario.Mail, "Verifica tu correo electrónico",
            $"Haz clic en este enlace para verificar tu correo electrónico: {verificationLink}");

        TempData["SuccessMessage"] =
            "Tu cuenta ha sido creada con éxito. Por favor, verifica tu correo electrónico para activar tu cuenta.";

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
            // Verificar si el correo electrónico del usuario ha sido verificado
            if (!(usuarioEncontrado.EmailVerificado ?? false))
            {
                // Establecer el mensaje de 
                ViewBag.EmailNotVerifiedMessage = "Email sin verificar.";
                ViewBag.EmailVerificationLink = "/Login/ReenviarEmailDeVerificacion?userId=" + usuarioEncontrado.Id;
                return View("Inicio");
            }

            string token = _jwtServicio.GenerarToken(usuarioEncontrado.Username, usuarioEncontrado.Rol);

            if (!string.IsNullOrEmpty(token))
            {
                Response.Cookies.Append("JwtToken", token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict
                });

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

[HttpGet]
        [Route("verificar_email")]
        public IActionResult VerificarEmail(string token)
        {
            // Verificar el token
            var claimPrincipal = _jwtServicio.VerificarToken(token);

            // Si el token no es válido, redirigir a una página de error
            if (claimPrincipal == null)
            {
                return RedirectToAction("Error");
            }

            // Obtener el ID del usuario del token
            var userIdClaim = claimPrincipal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier);
            if (userIdClaim == null)
            {
                return RedirectToAction("Error");
            }

            int userId = int.Parse(userIdClaim.Value);

            // Obtener el usuario
            var usuario = _usuarioServicio.ObtenerUsuarioPorId(userId);
            if (usuario == null)
            {
                return RedirectToAction("Error");
            }

            // Activar la cuenta del usuario
            usuario.EmailVerificado = true;
            _usuarioServicio.ActualizarUsuario(usuario);

            // Redirigir a la página de inicio
            return RedirectToAction("Inicio");
        }

        [HttpGet]
        public async Task<IActionResult> ReenviarEmailDeVerificacion(int userId)
        {
            // Obtener el usuario
            var usuario = _usuarioServicio.ObtenerUsuarioPorId(userId);
            if (usuario == null)
            {
                return RedirectToAction("Error");
            }

            // Generar un nuevo token de verificación de correo
            string token = _jwtServicio.GenerarTokenDeVerificacionDeCorreo(usuario.Mail, usuario.Id.ToString());

            // Crear el enlace de verificación
            string verificationLink = $"https://localhost:8080/verificar_email?token={token}";

            // Enviar el correo electrónico
            await _emailServicio.EnviarEmailAsync(usuario.Mail, "Reenviar email para verificación",
                $"Haz clic en este enlace para verificar tu correo electrónico: {verificationLink}");

            // Establecer el mensaje de éxito en TempData
            TempData["SuccessMessage"] = "Correo electrónico reenviado con éxito.";

            // Redirigir a la página de inicio
            return RedirectToAction("Inicio");
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

