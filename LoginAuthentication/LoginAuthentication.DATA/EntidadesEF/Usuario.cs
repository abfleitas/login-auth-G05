using System;
using System.Collections.Generic;

namespace LoginAuthentication.DATA.EntidadesEF
{
    public partial class Usuario
    {
        public int Id { get; set; }
        public string Nombre { get; set; } = null!;
        public string Mail { get; set; } = null!;
        public string Username { get; set; } = null!;
        public string Password { get; set; } = null!;
        public string? Rol { get; set; }
    }
}
