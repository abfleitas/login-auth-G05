using LoginAuthentication.DATA.EntidadesEF;

namespace LoginAuthentication.LOGICA;

public interface IUsuarioServicio
{
    void AgregarUsuario(Usuario usuario);
    List<Usuario> ObtenerTodos();
    Usuario ObtenerUsuarioPorId(int id);
    Usuario ObtenerUsuarioPorUsernameYPassword(string username, string password);
    void ActualizarUsuario(Usuario usuario);
    void EliminarUsuario(int id);
    void RegistrarUsuario(Usuario usuario);

}

public class UsuarioServicio : IUsuarioServicio
{
    private LoginAutenticationContext _context;

    public UsuarioServicio(LoginAutenticationContext context)
    {
        this._context = context;
    }

    public void RegistrarUsuario(Usuario usuario)
    {
        this._context.Usuarios.Add(usuario);
        this._context.SaveChanges();
    }

    public void AgregarUsuario(Usuario usuario)
    {
        this._context.Usuarios.Add(usuario);
        this._context.SaveChanges();
    }

    public List<Usuario> ObtenerTodos()
    {
        return this._context.Usuarios.ToList();
    }

    public Usuario ObtenerUsuarioPorId(int id)
    {
        return this._context.Usuarios.Find(id);
    }

    public void ActualizarUsuario(Usuario usuario)
    {
        this._context.Usuarios.Update(usuario);
        this._context.SaveChanges();
    }

    public void EliminarUsuario(int id)
    {
        var usuario = this.ObtenerUsuarioPorId(id);
        if (usuario == null)
            return;

        this._context.Usuarios.Remove(usuario);
        this._context.SaveChanges();
    }

    public Usuario ObtenerUsuarioPorUsernameYPassword(string username, string password)
    {
        // no se recomienda esta forma para buscar por password pero lo mantengo simple (al menos por ahora)
        Usuario usuario = _context.Usuarios.Where(u => u.Username == username && u.Password == password)
                        .FirstOrDefault();

        return usuario;
    }

}
