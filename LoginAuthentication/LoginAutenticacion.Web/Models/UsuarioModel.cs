using System.ComponentModel.DataAnnotations;

namespace LoginAutenticacion.Web.Models;

public class UsuarioModel
{
    [Required]
    public string Nombre { get; set; }

    [Required]
    [EmailAddress]
    public string Mail { get; set; }

    [Required]
    public string Username { get; set; }

    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    public string Rol { get; set; } = "Admin";

}

