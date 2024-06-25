using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace LoginAutenticacion.Web.Models;

public class UsuarioModel
{
    [Required(ErrorMessage = "El campo Nombre es requerido.")]
    public string Nombre { get; set; }

    [Required(ErrorMessage = "El campo Mail es requerido.")]
    [EmailAddress(ErrorMessage = "El campo Mail debe ser una dirección de correo electrónico válida.")]
    public string Mail { get; set; }

    [Required(ErrorMessage = "El campo Username es requerido.")]
    public string Username { get; set; }

    [Required(ErrorMessage = "El campo Password es requerido.")]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    public string? Rol { get; set; }

    [BindNever]
    public string UserNotFound { get; set; }
    [BindNever]
    public string InvalidPassword { get; set; }
}