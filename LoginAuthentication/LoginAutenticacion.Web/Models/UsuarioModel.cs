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
    /*[Required(ErrorMessage = "El campo de usuario es requerido")]
    public string Username { get; set; }

    [Required(ErrorMessage = "El campo de contraseña es requerido")]
    public string Password { get; set; }*/
}

