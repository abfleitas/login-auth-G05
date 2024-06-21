using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.ModelBinding;

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
    
    [BindNever]
    public string UserNotFound { get; set; }
    [BindNever]
    public string InvalidPassword { get; set; }
    
    public string Password { get; set; }

    public string? Rol { get; set; }

}

