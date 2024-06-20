CREATE DATABASE LoginAutentication;
GO
USE LoginAutentication; 
GO

CREATE TABLE usuario (
	id INT IDENTITY(1,1) PRIMARY KEY, 
	nombre VARCHAR(50) NOT NULL,
	mail VARCHAR(100) NOT NULL,
	username VARCHAR(50) NOT NULL,
	password VARCHAR(255) NOT NULL,
	rol VARCHAR(100) DEFAULT 'Usuario'
);

INSERT INTO dbo.usuario(nombre, mail, username, password) 
	VALUES('test','test@gmail.com','test123','test123');