using System.ComponentModel.DataAnnotations;

namespace LoginAutenticacion.Web.Models;

public class UsuarioModel
{
    [Required(ErrorMessage = "El campo de usuario es requerido")]
    public string Username { get; set; }

    [Required(ErrorMessage = "El campo de contraseña es requerido")]
    public string Password { get; set; }
    public string Rol { get; set; } = "Admin";

}

