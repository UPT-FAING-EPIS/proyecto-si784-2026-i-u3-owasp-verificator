// Archivo de prueba JS con vulnerabilidades para el verificador OWASP

// OWASP-A02: Secretos expuestos
const apiKey = "AIzaSyD-unsecured-google-key-example";
const token = "secret_github_token_abc123";

// OWASP-A03: Inyección de código
function runDynamicCode(userInput) {
    eval(userInput);
}

// OWASP-A04: Diseño Inseguro
// TODO: Validar que el token pertenezca al usuario logueado
// FIXME: Remover hack de bypass temporal
// Insecure function definition

// OWASP-A07: Autenticación
function auth(user, pass) {
    if (pass == "password") {
        return true;
    }
    return false;
}

// OWASP-A09: Fallas de Logging
try {
    const data = JSON.parse(userInput);
} catch (e) {
    // Excepción vacía sin loguear la falla de seguridad
}
