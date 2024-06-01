# login-auth-G05
Integración de Login-Authentication en .NET

Paquetes para descargar:
estos tiene que estar en las de pendencias de .DATA y el proyecto .web tambien tiene que referenciarlo
   <PackageReference Include="Microsoft.EntityFrameworkCore.SqlServer" Version="6.0.0" />
    <PackageReference Include="Microsoft.EntityFrameworkCore.Tools" Version="6.0.0">
    <PackageReference Include="Microsoft.EntityFrameworkCore" Version="6.0.0" />
    <PackageReference Include="Microsoft.EntityFrameworkCore.Design" Version="6.0.0">

     <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="6.0.0" />
    <PackageReference Include="Microsoft.AspNetCore.Mvc.Razor.RuntimeCompilation" Version="6.0.0" />


CREATE DATABASE LoginAutentication;
GO

Use LoginAutentication;
GO

-- Crear la tabla de usuario
CREATE TABLE usuario (
    id INT IDENTITY(1,1) PRIMARY KEY,
    nombre VARCHAR(50) NOT NULL,
    mail VARCHAR(100) NOT NULL,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL
);

-asegurense de tener en la consola como proyecto predeterminado LoginAutentication.DATA
Scaffold-DbContext "Server=(como les aparece en sql);Database=LoginAutentication;Trusted_Connection=True;Encrypt=False" Microsoft.EntityFrameworkCore.SqlServer -OutputDir EntidadesEF