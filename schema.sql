-- Esquema de Base de Datos para MySQL/MariaDB (OWASP Verificator)

CREATE DATABASE IF NOT EXISTS owasp_verificador CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE owasp_verificador;

-- Tabla de Escaneos de Seguridad
CREATE TABLE IF NOT EXISTS scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target_type VARCHAR(50) NOT NULL,
    target_value LONGTEXT NOT NULL,
    status VARCHAR(50) NOT NULL,
    score INT NOT NULL,
    created_at DATETIME NOT NULL,
    findings_json LONGTEXT NOT NULL,
    username VARCHAR(255) NULL
) ENGINE=InnoDB;

-- Tabla de Tokens de API
CREATE TABLE IF NOT EXISTS api_tokens (
    token VARCHAR(255) PRIMARY KEY,
    user VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL,
    last_used DATETIME NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1
) ENGINE=InnoDB;

-- Tabla de Registro de Accesos (Auditoría)
CREATE TABLE IF NOT EXISTS access_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    path VARCHAR(255) NOT NULL,
    ip VARCHAR(50) NOT NULL,
    user_agent TEXT NOT NULL,
    username VARCHAR(255) NULL,
    created_at DATETIME NOT NULL
) ENGINE=InnoDB;

-- Tabla de Sesiones de Usuario
CREATE TABLE IF NOT EXISTS admin_sessions (
    session_id VARCHAR(255) PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL,
    expires_at DOUBLE NOT NULL
) ENGINE=InnoDB;

-- Tabla de Usuarios y Roles
CREATE TABLE IF NOT EXISTS users (
    username VARCHAR(255) PRIMARY KEY,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    created_at DATETIME NOT NULL,
    email VARCHAR(255) NULL,
    github_token VARCHAR(255) NULL
) ENGINE=InnoDB;

-- Insertar usuario Administrador por defecto
-- Contraseña por defecto: 123456
INSERT IGNORE INTO users (username, password_hash, role, created_at) 
VALUES ('admin', '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92', 'admin', NOW());

-- Insertar tokens de integración iniciales por defecto
INSERT IGNORE INTO api_tokens (token, user, created_at, last_used, is_active) 
VALUES ('demo-token-12345', 'demo', NOW(), NOW(), 1);

INSERT IGNORE INTO api_tokens (token, user, created_at, last_used, is_active) 
VALUES ('admin-token-67890', 'admin', NOW(), NOW(), 1);
