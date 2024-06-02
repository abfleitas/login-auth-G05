using LoginAuthentication.DATA.EntidadesEF;

namespace LoginAuthentication.LOGICA;

public interface IUsuarioServicio
{
    void AgregarUsuario(Usuario usuario);
    List<Usuario> ObtenerTodos();
    Usuario ObtenerUsuarioPorId(int id);
    void ActualizarUsuario(Usuario usuario);
    void EliminarUsuario(int id);

}

public class UsuarioServicio : IUsuarioServicio
    {
    private LoginAutenticationContext _context;

    public UsuarioServicio(LoginAutenticationContext context) {
        this._context = context;
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











}
