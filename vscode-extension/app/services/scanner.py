import re
import zipfile
import io
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse

import os
from app.services.cve_analyzer import analyze_for_cves

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    description: str
    evidence: str


RULES = [
    # --- OWASP-A01 ---
    {
        "rule_id": "OWASP-A01-NO-AUTH",
        "title": "Endpoint sin Autenticación",
        "severity": "high",
        "remediation": "1. Implementar autenticación a nivel global en las rutas o controladores del de desarrollo usado (NodeJS, Python, PHP, Java, etc.).\n2. Requerir sesión activa por defecto para todo el sistema y configurar accesos públicos como excepciones explícitas.",
        "patterns": [r"@app\.(get|post|put|delete|patch)\((?!.*dependencies)", r"router\.(get|post|put|delete|patch)\((?!.*dependencies)"],
        "description": "Hay páginas o funciones del sistema que cualquier persona puede abrir y ver en internet sin necesidad de iniciar sesión o ingresar una contraseña.",
    },
    {
        "rule_id": "OWASP-A01-HARDCODED-ROLE",
        "title": "Comprobación de Rol Hardcodeada",
        "severity": "medium",
        "remediation": "1. Utilizar un modelo de control de accesos basado en roles (RBAC) dinámico, preferiblemente almacenando las relaciones de roles y permisos en una base de datos.\n2. Evitar la verificación manual y estática de strings de roles (como 'admin') dentro del código de negocio.",
        "patterns": [r"role\s*==\s*['\"]admin['\"]", r"user\.role\s*==\s*['\"]"],
        "description": "Los permisos de usuario están escritos de forma fija en el código en lugar de gestionarse dinámicamente. Esto dificulta cambiar o revocar accesos en el futuro.",
    },
    {
        "rule_id": "OWASP-A01-CORS-WILDCARD",
        "title": "CORS con Permisos Totales (Comodín)",
        "severity": "medium",
        "remediation": "1. Configurar las reglas CORS (Cross-Origin Resource Sharing) especificando los dominios exactos y de confianza autorizados para interactuar con la API.\n2. Evitar el uso del carácter comodín '*' en entornos de producción.",
        "patterns": [r"allow_origins\s*=\s*\[\s*['\"]\*(?!['\"])", r"Access-Control-Allow-" + "Origin" + r".*\*"],
        "description": "El sistema acepta solicitudes de cualquier sitio web del mundo. Un atacante podría robar información de las sesiones de tus usuarios desde una página externa.",
    },
    {
        "rule_id": "OWASP-A01-OPEN-CIDR",
        "title": "Acceso de Red Totalmente Abierto (CIDR 0.0.0.0/0)",
        "severity": "medium",
        "remediation": "1. Configurar firewalls y reglas de red para restringir el acceso a puertos sensibles solo a rangos de IP autorizados o VPNs corporativas.\n2. Evitar configuraciones de red abiertas a todo internet (0.0.0.0/0) para servicios de infraestructura privada.",
        "patterns": [r"0\.0\.0\.0/0"],
        "description": "La red del servidor está abierta a todo internet, permitiendo que cualquiera intente escanear y conectarse directamente a tus bases de datos o servicios privados.",
    },
    # --- OWASP-A02 ---
    {
        "rule_id": "OWASP-A02-HARDCODED-SECRET",
        "title": "Secreto o Credencial Expuesta",
        "severity": "high",
        "remediation": "1. Extraer todas las credenciales del código fuente y almacenarlas en variables de entorno o en un administrador de secretos seguro (Vault, AWS Secrets Manager, etc.).\n2. Asegurar que los archivos de configuración local estén excluidos del control de versiones (Git).",
        "patterns": [r"password\s*=\s*['\"][^'\"]{4,}['\"]", r"api[_-]?key\s*=\s*['\"][a-zA-Z0-9_\-]{8,}['\"]", r"secret\s*=\s*['\"][a-zA-Z0-9_\-]{8,}['\"]", r"token\s*=\s*['\"][a-zA-Z0-9_\-]{8,}['\"]"],
        "description": "Se encontró una contraseña, token o clave de seguridad escrita directamente en el código. Cualquier persona que lea el código podrá usarla para acceder a tus sistemas.",
    },
    {
        "rule_id": "OWASP-A02-WEAK-HASH",
        "title": "Algoritmo de Hash Criptográfico Débil",
        "severity": "high",
        "remediation": "1. Reemplazar el uso de MD5 o SHA-1 por funciones de hashing criptográfico seguras para contraseñas, como Bcrypt, Argon2 o PBKDF2.\n2. Utilizar sales únicas y aleatorias (salts) para cada contraseña almacenada.",
        "patterns": [r"createHash\(\s*['\"]md5['\"]", r"createHash\(\s*['\"]sha1['\"]", r"hashlib\.md5\(", r"hashlib\.sha1\("],
        "description": "Se está usando un método antiguo y débil (como MD5 o SHA-1) para proteger contraseñas. Un atacante puede descifrar estas contraseñas muy fácilmente.",
    },
    {
        "rule_id": "OWASP-A02-HTTP-URL",
        "title": "Comunicación Insegura (HTTP)",
        "severity": "medium",
        "remediation": "1. Modificar todas las URLs para que apunten a endpoints seguros HTTPS.\n2. Configurar el servidor web para redirigir automáticamente todo el tráfico inseguro HTTP hacia HTTPS.",
        "patterns": [r"http://[a-zA-Z0-9\-\.]+(?!/)(?!127\.0\.0\.1)(?!localhost)"],
        "description": "La aplicación se conecta a internet usando direcciones inseguras 'http://'. Esto permite que un intruso en la misma red intercepte y lea toda la información que se transmite.",
    },
    {
        "rule_id": "OWASP-A02-WEAK-KEY-SIZE",
        "title": "Clave Asimétrica de Tamaño Débil",
        "severity": "medium",
        "remediation": "1. Configurar la generación de claves para usar una longitud mínima segura (por ejemplo, 2048 bits para algoritmos RSA).\n2. Utilizar algoritmos criptográficos modernos recomendados por estándares de seguridad de la industria.",
        "patterns": [r"generateKeyPair\([^,]*modulusLength\s*:\s*(1024|512)"],
        "description": "La llave de seguridad digital utilizada es demasiado corta y fácil de descifrar mediante computadoras modernas.",
    },
    # --- OWASP-A03 ---
    {
        "rule_id": "OWASP-A03-SQLI",
        "title": "Inyección SQL (SQLi)",
        "severity": "high",
        "remediation": "1. Utilizar consultas parametrizadas (prepared statements) o herramientas de mapeo de base de datos (ORMs) que separen los datos de las instrucciones SQL.\n2. Nunca concatenar o interpolar directamente variables ingresadas por usuarios dentro de cadenas de consultas SQL.",
        "patterns": [r"execute\(\s*f['\"]", r"\.query\(\s*['\"].*\$\{", r"execute\(\s*['\"].*%\s*", r"execute\(\s*['\"].*\.format\("],
        "description": "El sistema introduce lo que escribe el usuario directamente en la base de datos sin revisar. Un atacante podría escribir comandos maliciosos para ver, alterar o borrar toda tu información.",
    },
    {
        "rule_id": "OWASP-A03-CODE-INJECTION",
        "title": "Ejecución Dinámica de Código (Code Injection)",
        "severity": "high",
        "remediation": "1. Evitar por completo el uso de funciones de evaluación dinámica de cadenas (como eval() o exec() en cualquier lenguaje).\n2. Utilizar flujos lógicos estructurados predefinidos en lugar de generar y ejecutar código en tiempo de ejecución.",
        "patterns": [r"\be" + r"val\(", r"\bex" + r"ec\(", r"new\s+Function\("],
        "description": "El sistema ejecuta instrucciones de código ingresadas directamente desde el exterior. Esto permitiría a un atacante tomar control total de tu servidor web.",
    },
    {
        "rule_id": "OWASP-A03-OS-COMMAND",
        "title": "Ejecución de Comandos de Sistema Operativo",
        "severity": "high",
        "remediation": "1. Reemplazar las ejecuciones de comandos de consola externos por llamadas a librerías y APIs integradas en tu lenguaje de programación.\n2. Si es obligatorio llamar a un comando externo, validar y desinfectar estrictamente los argumentos recibidos.",
        "patterns": [r"child_process\.(exec|spawn)\(", r"os\.system\(", r"subprocess\.(run|Popen|call)\("],
        "description": "La aplicación ejecuta comandos del sistema operativo (del servidor) usando datos provistos por el usuario. Un atacante podría inyectar instrucciones adicionales para controlar tu máquina.",
    },
    {
        "rule_id": "OWASP-A03-XSS",
        "title": "Cross-Site Scripting (XSS)",
        "severity": "high",
        "remediation": "1. Aplicar escape contextual y sanitización de caracteres HTML antes de renderizar cualquier entrada de usuario en la pantalla.\n2. Configurar la cabecera de seguridad 'Content Security Policy' (CSP) en el servidor para restringir la ejecución de scripts no autorizados.",
        "patterns": [r"\.innerHTML\s*=", r"document\.write\(", "dangerouslySet" + "InnerHTML"],
        "description": "El sitio web muestra texto escrito por los usuarios directamente en la pantalla sin limpiarlo. Un atacante podría insertar códigos invisibles para robar las sesiones o contraseñas de otros visitantes.",
    },
    {
        "rule_id": "OWASP-A03-PATH-TRAVERSAL",
        "title": "Path Traversal (Salto de Directorio)",
        "severity": "high",
        "remediation": "1. Validar y resolver las rutas de archivos de forma absoluta usando funciones del sistema operativo, asegurando que se encuentren dentro del directorio base permitido.\n2. Evitar el uso de nombres o rutas completas enviadas directamente por el cliente para buscar archivos.",
        "patterns": [r"fs\.readFile\([^,]*\+", r"open\([^,]*\+", r"fs\.createReadStream\([^,]*\+", r"send_file\([^,]*\+"],
        "description": "El sistema lee o escribe archivos en el disco del servidor usando rutas ingresadas por el usuario. Un atacante podría usar secuencias de puntos (como '../') para acceder a archivos privados.",
    },
    {
        "rule_id": "OWASP-A03-LDAP-INJECTION",
        "title": "Inyección LDAP",
        "severity": "high",
        "remediation": "1. Escapar todos los caracteres especiales en los filtros de búsqueda de consultas LDAP.\n2. Utilizar librerías cliente de LDAP que soporten la parametrización de consultas.",
        "patterns": [r"ldap\.search\([^,]*\+[^,]*\)"],
        "description": "Se construyen consultas al directorio de usuarios LDAP usando datos del usuario de forma directa, permitiendo alterar la búsqueda para saltar validaciones.",
    },
    {
        "rule_id": "OWASP-A03-XPATH-INJECTION",
        "title": "Inyección XPath",
        "severity": "high",
        "remediation": "1. Utilizar consultas XPath parametrizadas o escapar caracteres de entrada en filtros de búsqueda XML.\n2. Validar que la estructura del documento XML no pueda ser alterada por el usuario.",
        "patterns": [r"\.selectSingleNode\([^,]*\+[^,]*\)"],
        "description": "Consultas XPath construidas dinámicamente que pueden permitir evadir la lógica de acceso de documentos XML.",
    },
    {
        "rule_id": "OWASP-A03-DYNAMIC-SQL",
        "title": "SQL Dinámico Inseguro",
        "severity": "high",
        "remediation": "1. Implementar procedimientos almacenados parametrizados con tipos de datos definidos.\n2. No concatenar variables externas directamente dentro de scripts de base de datos.",
        "patterns": [r"EXEC\s*\(\s*['\"].*?\+\s*", r"EXEC\s*\(\s*@[a-zA-Z0-9_]+\s*\)"],
        "description": "Uso de bloques SQL dinámicos concatenados que pueden facilitar la inyección de consultas en bases de datos relacionales.",
    },
    # --- OWASP-A04 ---
    {
        "rule_id": "OWASP-A04-TODO-SECURITY",
        "title": "Comentario de Seguridad Pendiente (TODO)",
        "severity": "low",
        "remediation": "1. Auditar y resolver todas las notas de desarrollo pendientes (TODO, FIXME) relacionadas con validaciones de seguridad.\n2. Registrar las fallas conocidas en un sistema centralizado de tareas del equipo en lugar del código.",
        "patterns": [r"TODO\s*:\s*autentica", r"FIXME\s*:\s*seguridad", r"TODO\s*:\s*validar", r"TODO\s*:\s*encripta"],
        "description": "Comentarios dentro del código de desarrollo que indican tareas o validaciones de seguridad que se dejaron incompletas.",
    },
    {
        "rule_id": "OWASP-A04-CLIENT-LOGIC",
        "title": "Verificación de Privilegios en Cliente",
        "severity": "medium",
        "remediation": "1. Validar rigurosamente la sesión y privilegios en el backend antes de entregar datos o realizar operaciones.\n2. Tratar las validaciones visuales del lado del cliente únicamente como mejoras de experiencia de usuario, nunca como controles de seguridad.",
        "patterns": [r"checkPrivileges\(", r"validateAdminStatus\("],
        "description": "La lógica de permisos se realiza en la aplicación del cliente (ej. JavaScript en el navegador). Un usuario avanzado podría cambiar el código para entrar como administrador.",
    },
    # --- OWASP-A05 ---
    {
        "rule_id": "OWASP-A05-DEBUG-ACTIVE",
        "title": "Modo Debug Habilitado",
        "severity": "high",
        "remediation": "1. Desactivar el modo depuración (debug) en todos los entornos de producción.\n2. Configurar el sistema para reportar errores genéricos al usuario y registrar el detalle real en logs internos protegidos.",
        "patterns": [r"debug\s*=\s*True", r"DEBUG\s*:\s*true"],
        "description": "El modo de depuración de errores está activado en producción. Si ocurre un fallo, el sistema mostrará a los visitantes detalles internos del código y de tus bases de datos.",
    },
    {
        "rule_id": "OWASP-A05-DEFAULT-CREDS",
        "title": "Uso de Credenciales por Defecto",
        "severity": "high",
        "remediation": "1. Cambiar inmediatamente las claves y usuarios predeterminados de cualquier servicio antes de implementarlo.\n2. Forzar al usuario a establecer una contraseña robusta personalizada durante la primera instalación o inicio.",
        "patterns": [r"['\"]admin['\"]\s*,\s*['\"]admin['\"]", r"['\"]root['\"]\s*,\s*['\"]root['\"]", r"['\"]guest['\"]\s*,\s*['\"]guest['\"]"],
        "description": "El sistema utiliza contraseñas genéricas de fábrica (como admin/admin). Cualquiera puede entrar al sistema simplemente probando estas contraseñas predefinidas.",
    },
    {
        "rule_id": "OWASP-A05-DIR-LISTING",
        "title": "Listado de Directorios Activado",
        "severity": "medium",
        "remediation": "1. Deshabilitar el listado de directorios automático en la configuración de tu servidor web (Nginx, Apache, IIS).\n2. Devolver respuestas de error de acceso prohibido (403 Forbidden) cuando no exista un archivo index en el directorio.",
        "patterns": [r"serve_index\s*=\s*True", r"directory_listing\s*=\s*true"],
        "description": "El servidor muestra una lista de todos los archivos y carpetas del sistema cuando se entra a una ruta vacía, revelando la estructura privada de tu aplicación.",
    },
    {
        "rule_id": "OWASP-A05-INSECURE-COOKIE",
        "title": "Cookie Insegura (Atributo Secure Falso)",
        "severity": "medium",
        "remediation": "1. Configurar las cookies de sesión con el atributo `Secure` activado para que solo se envíen sobre conexiones HTTPS cifradas.\n2. Utilizar el flag `HttpOnly` para evitar accesos no autorizados a través de scripts maliciosos.",
        "patterns": [r"cookie\([^,]*secure\s*:\s*false"],
        "description": "Las cookies de sesión se envían de forma insegura. Si el usuario se conecta a una red Wi-Fi pública, un atacante podría copiar su sesión y entrar en su cuenta.",
    },
    {
        "rule_id": "OWASP-A05-DOCKER-ROOT",
        "title": "Contenedor ejecutado como Root (Dockerfile)",
        "severity": "medium",
        "remediation": "1. Configurar un usuario sin privilegios en el archivo de construcción del contenedor (usar instrucción `USER` en Dockerfile).\n2. Evitar ejecutar el contenedor Docker en modo privilegiado.",
        "patterns": [r"USER\s+root"],
        "description": "La aplicación dentro del contenedor Docker corre con el usuario root (administrador supremo). Si la app es hackeada, el atacante controlará toda la máquina.",
    },
    {
        "rule_id": "OWASP-A05-K8S-PRIV-ESC",
        "title": "Escalabilidad de Privilegios en Pod",
        "severity": "medium",
        "remediation": "1. Configurar el contexto de seguridad del contenedor Kubernetes para prohibir la escalación de privilegios (`allowPrivilegeEscalation: false`).",
        "patterns": [r"allowPrivilege" + r"Escalation\s*:\s*true"],
        "description": "La configuración de Kubernetes permite que programas secundarios del contenedor eleven sus privilegios, facilitando ataques de escalación de permisos.",
    },
    # --- OWASP-A06 ---
    {
        "rule_id": "OWASP-A06-DEP-VULN",
        "title": "Componente Vulnerable Importado",
        "severity": "medium",
        "remediation": "1. Implementar análisis automatizados de dependencias en el gestor de paquetes de tu lenguaje (como npm audit, pip audit, composer audit, etc.).\n2. Mantener las librerías actualizadas a sus últimas versiones de seguridad estables.",
        "patterns": [r"import\s+django\b", r"import\s+flask\b", r"import\s+requests\b", r"require\(\s*['\"]express['\"]"],
        "description": "La aplicación utiliza librerías externas que pueden tener fallas de seguridad conocidas. Es necesario revisarlas y actualizarlas de forma constante.",
    },
    # --- OWASP-A07 ---
    {
        "rule_id": "OWASP-A07-WEAK-PASS-CHECK",
        "title": "Autenticación Débil / Comparación Directa",
        "severity": "high",
        "remediation": "1. Implementar esquemas de autenticación robustos utilizando funciones de comparación de tiempo constante.\n2. Integrar autenticación de múltiples factores (MFA) para inicios de sesión críticos.",
        "patterns": [r"password\s*==\s*password", r"password\s*==\s*['\"][^'\"]*['\"]", r"if\s+user_id\s*==\s*['\"]"],
        "description": "El sistema valida las contraseñas de forma directa, lo que facilita que un atacante adivine o evada el inicio de sesión.",
    },
    {
        "rule_id": "OWASP-A07-PLAIN-TEXT",
        "title": "Contraseña en Texto Plano",
        "severity": "high",
        "remediation": "1. Hashear todas las contraseñas de los usuarios utilizando algoritmos de derivación de claves robustos (Bcrypt, Argon2) antes de almacenarlas en la base de datos.\n2. Asegurar que las contraseñas nunca viajen en texto plano a través de la red sin cifrar.",
        "patterns": [r"storePassword\s*\(", r"saveRawPassword\("],
        "description": "Las contraseñas de los usuarios se guardan en texto plano en la base de datos. Si alguien entra a la base de datos, podrá ver todas las contraseñas directamente.",
    },
    {
        "rule_id": "OWASP-A07-NO-LOCKOUT",
        "title": "Ausencia de Control de Intentos de Acceso",
        "severity": "medium",
        "remediation": "1. Configurar un mecanismo de bloqueo temporal de cuenta tras un número consecutivo de intentos de inicio de sesión fallidos.\n2. Implementar límites de solicitudes (rate limiting) en las rutas de inicio de sesión.",
        "patterns": [r"loginAttempts\s*=\s*0"],
        "description": "La aplicación no bloquea la cuenta tras ingresar contraseñas incorrectas. Un atacante puede probar millones de contraseñas por segundo hasta adivinarla.",
    },
    {
        "rule_id": "OWASP-A07-WEAK-SESSION",
        "title": "Generación de ID de Sesión Débil",
        "severity": "high",
        "remediation": "1. Utilizar un generador de números aleatorios seguro para criptografía (CSPRNG) para los identificadores de sesión.\n2. Delegar el manejo de sesiones en el framework web que utilices.",
        "patterns": [r"Math\.random\(\)\.toString\(36\)"],
        "description": "El sistema genera códigos de sesión para los usuarios de forma predecible. Un hacker podría adivinar el código de otro usuario y hacerse pasar por él.",
    },
    # --- OWASP-A08 ---
    {
        "rule_id": "OWASP-A08-UNSAFE-DESERIALIZATION",
        "title": "Deserialización Insegura",
        "severity": "high",
        "remediation": "1. Evitar la deserialización de flujos de datos recibidos directamente del exterior.\n2. Utilizar formatos estándar más seguros de transferencia de datos como JSON.",
        "patterns": [r"yaml\.load\([^,]*Loader\s*=\s*yaml\.UnsafeLoader", r"yaml\.unsafe_load\(", r"pickle\.loads\("],
        "description": "El sistema procesa y reconstruye datos complejos enviados desde fuera sin validar. Un atacante podría enviar datos manipulados para obligar al servidor a ejecutar comandos dañinos.",
    },
    {
        "rule_id": "OWASP-A08-NO-CHECKSUM",
        "title": "Descarga de Código sin Verificación",
        "severity": "medium",
        "remediation": "1. Verificar siempre la firma digital o suma de comprobación (checksum SHA-256) de los archivos descargados.\n2. Exigir la validación de certificados SSL/TLS para evitar intercepciones de red.",
        "patterns": [r"download\([^,]*,\s*verify\s*=\s*False"],
        "description": "La aplicación descarga archivos de internet sin verificar su identidad o integridad. Un atacante podría cambiar la descarga para inyectar virus.",
    },
    {
        "rule_id": "OWASP-A08-UNSIGNED-JWT",
        "title": "JWT sin Firma Aceptado",
        "severity": "high",
        "remediation": "1. Validar estrictamente la firma criptográfica de los JSON Web Tokens (JWT) recibidos.\n2. Desactivar y denegar explícitamente el soporte para el algoritmo de firma 'none'.",
        "patterns": [r"algorithm\s*:\s*['\"]none['\"]"],
        "description": "El sistema de seguridad acepta credenciales con firmas vacías, lo que permite a cualquiera alterar su nombre o rol y entrar como administrador.",
    },
    # --- OWASP-A09 ---
    {
        "rule_id": "OWASP-A09-SILENT-EXCEPT",
        "title": "Captura Silenciosa de Excepción",
        "severity": "low",
        "remediation": "1. Registrar adecuadamente los fallos del sistema en archivos de logs con niveles de severidad correctos (Error, Advertencia).\n2. Evitar capturas genéricas que oculten el problema sin reportarlo.",
        "patterns": [r"except\s*:\s*pass", r"except\s+Exception\s*:\s*pass", r"catch\s*\(\s*e\s*\)\s*\{\s*\}"],
        "description": "La aplicación oculta los errores cuando ocurren y no guarda ningún registro. Si el sistema falla o es atacado, nadie se dará cuenta.",
    },
    {
        "rule_id": "OWASP-A09-LOG-SECRETS",
        "title": "Registro de Secretos en Log",
        "severity": "medium",
        "remediation": "1. Filtrar y remover credenciales, contraseñas o tokens de seguridad antes de escribir datos en los archivos de log.\n2. Implementar auditorías sobre los archivos de logs generados.",
        "patterns": [r"console\.log\(.*password", r"logger\.info\(.*api_key"],
        "description": "El sistema escribe contraseñas o claves secretas en los archivos de registro (logs) de texto simple. Cualquiera que lea los logs podrá ver estas claves.",
    },
    {
        "rule_id": "OWASP-A09-LEAK-ERROR",
        "title": "Fuga de Stack Trace en Error",
        "severity": "medium",
        "remediation": "1. Retornar mensajes genéricos y amigables a los usuarios finales ante un error.\n2. Guardar el detalle técnico y la pila de ejecución (stack trace) únicamente en archivos de logs internos seguros.",
        "patterns": [r"res\.send\(\s*e\.stack\s*\)", r"res\.json\(\s*e\s*\)"],
        "description": "El sistema muestra mensajes de error muy detallados con código interno en la pantalla del usuario común. Esto ayuda a un atacante a saber cómo está construida la app para hackearla.",
    },
    # --- OWASP-A10 ---
    {
        "rule_id": "OWASP-A10-SSRF-REQUESTS",
        "title": "Riesgo de Server-Side Request Forgery (SSRF)",
        "severity": "high",
        "remediation": "1. Validar y contrastar las direcciones provistas por el usuario contra una lista de dominios permitidos (allowlist).\n2. Denegar de forma estricta las solicitudes orientadas a direcciones IP locales (como localhost, 127.0.0.1, 169.254.169.254).",
        "patterns": [r"requests\.(get|post)\(\s*url\b", r"fetch\(\s*req\.query\."],
        "description": "El servidor realiza conexiones a internet siguiendo direcciones indicadas por el usuario. Un atacante podría indicarle que acceda a la red privada de tu empresa.",
    },
]

# Weight per severity used for scoring and displayed in reports
WEIGHTS = {"high": 30, "medium": 15, "low": 5}

REMEDIATIONS = {r["rule_id"]: r.get("remediation", "") for r in RULES}

# Additional remediations for URL scan findings
REMEDIATIONS.update({
    "OWASP-A05": "1. Configurar las cabeceras de respuesta de seguridad HTTP en tu servidor web (Nginx, Apache) o middleware del framework (NodeJS/Express, Python/FastAPI/Django, PHP/Laravel):\n"
                  "   - Content-Security-Policy (CSP): Define fuentes autorizadas para cargar scripts, estilos e imágenes.\n"
                  "   - Strict-Transport-Security (HSTS): Fuerza al navegador a usar siempre HTTPS.\n"
                  "   - X-Frame-Options: Previene ataques de Clickjacking evitando que el sitio sea embebido en frames.\n"
                  "   - X-Content-Type-Options: Establecer 'nosniff' para evitar que se interpreten archivos como scripts maliciosos.\n"
                  "2. Valida la configuración de tus cabeceras usando herramientas públicas como securityheaders.com.",
    "OWASP-A06": "1. Ocultar o eliminar la cabecera 'Server' en las respuestas HTTP para no revelar información sobre el software y versión del servidor.\n"
                  "2. Esto se configura a nivel de servidor web (ej. 'server_tokens off' en Nginx, 'ServerSignature Off' en Apache) o mediante middlewares en tu código backend.\n"
                  "3. Utilizar un proxy inverso que reescriba o elimine esta cabecera antes de exponer las respuestas a Internet.",
})


def scan_code(content: str) -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES:
        for pattern in rule["patterns"]:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                findings.append(
                    Finding(
                        rule_id=rule["rule_id"],
                        title=rule["title"],
                        severity=rule["severity"],
                        description=rule["description"],
                        evidence=f"Coincidencia encontrada: {match.group(0)}",
                    )
                )
                break
    
    # Add CVE analysis (executed only once per scan)
    cve_findings = analyze_for_cves(content)
    findings.extend(cve_findings)
    
    return findings


def scan_url(target_url: str) -> list[Finding]:
    requests = __import__('requests')
    findings: list[Finding] = []
    parsed = urlparse(target_url)
    
    # Check if analyzing self (own application)
    self_urls = {"localhost", "127.0.0.1", "0.0.0.0"}
    if parsed.hostname in self_urls or "localhost" in target_url or "127.0.0.1" in target_url:
        # This is the own application - return no findings (score 100)
        return []
    
    if parsed.scheme not in {"http", "https"}:
        return [
            Finding(
                rule_id="OWASP-A01",
                title="URL inválida",
                severity="medium",
                description="La URL debe usar HTTP o HTTPS.",
                evidence=target_url,
            )
        ]

    try:
        response = requests.get(target_url, timeout=15)
        headers = response.headers
        status_line = f"HTTP/1.1 {response.status_code} {response.reason}"
        all_headers_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
        headers_context = f"{status_line}\n{all_headers_str}"
    except requests.RequestException as exc:
        return [
            Finding(
                rule_id="OWASP-A01",
                title="No se pudo conectar al objetivo",
                severity="medium",
                description="La URL no respondió correctamente durante el análisis.",
                evidence=str(exc),
            )
        ]

    required_headers = {
        "Content-Security-Policy": "Falta Content-Security-Policy.",
        "Strict-Transport-Security": "Falta Strict-Transport-Security.",
        "X-Frame-Options": "Falta X-Frame-Options.",
        "X-Content-Type-Options": "Falta X-Content-Type-Options.",
    }

    for header_name, message in required_headers.items():
        if header_name not in headers:
            findings.append(
                Finding(
                    rule_id="OWASP-A05",
                    title="Cabecera de seguridad ausente",
                    severity="medium",
                    description=message,
                    evidence=(
                        f"Origen del hallazgo: Cabeceras de respuesta HTTP\n"
                        f"Detalle: Respuesta HTTP sin la cabecera '{header_name}'\n\n"
                        f"Respuesta HTTP completa recibida:\n{headers_context}"
                    ),
                )
            )

    if "Server" in headers:
        findings.append(
            Finding(
                rule_id="OWASP-A06",
                title="Divulgación de información",
                severity="low",
                description="La cabecera Server expone detalles de la infraestructura.",
                evidence=(
                    f"Origen del hallazgo: Cabecera HTTP 'Server'\n"
                    f"Detalle: Se encontró la cabecera 'Server: {headers['Server']}'\n\n"
                    f"Respuesta HTTP completa recibida:\n{headers_context}"
                ),
            )
        )

    return findings


def scan_github_repo(repo_url: str, github_token: str | None = None) -> list[Finding]:
    """Descarga y analiza un repositorio de GitHub"""
    requests = __import__('requests')
    findings: list[Finding] = []
    
    try:
        # Parsear URL de GitHub (ej: https://github.com/owner/repo)
        parsed = urlparse(repo_url)
        if "github.com" not in parsed.netloc:
            return [
                Finding(
                    rule_id="OWASP-A01",
                    title="URL de GitHub inválida",
                    severity="medium",
                    description="La URL debe ser de un repositorio de GitHub válido.",
                    evidence=repo_url,
                )
            ]
        
        path_parts = parsed.path.strip("/").split("/")
        if len(path_parts) < 2:
            return [
                Finding(
                    rule_id="OWASP-A01",
                    title="URL de repositorio inválida",
                    severity="medium",
                    description="Formato inválido. Usa: https://github.com/owner/repo",
                    evidence=repo_url,
                )
            ]
        
        owner = path_parts[0]
        repo = path_parts[1].replace(".git", "")

        # Support single-file blob/raw URLs: https://github.com/owner/repo/blob/branch/path
        if 'blob' in path_parts:
            try:
                blob_idx = path_parts.index('blob')
                branch = path_parts[blob_idx + 1]
                file_path = '/'.join(path_parts[blob_idx + 2:])
                raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"
                headers = None
                # Use provided token first, fallback to env var
                token = github_token or os.getenv('GITHUB_TOKEN')
                if token:
                    headers = {"Authorization": f"token {token}"}
                r = requests.get(raw_url, headers=headers, timeout=15)
                if r.status_code != 200:
                    return [
                        Finding(
                            rule_id="OWASP-A01",
                            title="No se pudo descargar el archivo especificado",
                            severity="medium",
                            description="El archivo en el repositorio no está disponible.",
                            evidence=f"Status: {r.status_code}",
                        )
                    ]
                content = r.content.decode('utf-8', errors='replace')
                file_findings = scan_code(content)
                for finding in file_findings:
                    finding.evidence = f"Archivo: {file_path}\n{finding.evidence}"
                findings.extend(file_findings)
                return findings
            except Exception as e:
                err = e

        # Descargar el repositorio como ZIP
        zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/main.zip"
        headers = None
        # Use provided token first, fallback to env var
        token = github_token or os.getenv('GITHUB_TOKEN')
        if token:
            headers = {"Authorization": f"token {token}"}
        response = requests.get(zip_url, headers=headers, timeout=15)

        # Si main no existe, intentar con master
        if response.status_code == 404:
            zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/master.zip"
            response = requests.get(zip_url, headers=headers, timeout=15)

        if response.status_code != 200:
            return [
                Finding(
                    rule_id="OWASP-A01",
                    title="No se pudo descargar el repositorio",
                    severity="medium",
                    description="El repositorio no está disponible o es privado.",
                    evidence=f"Status: {response.status_code}",
                )
            ]

        # Extraer y analizar archivos
        code_extensions = {
            ".py", ".js", ".java", ".cpp", ".c", ".go", ".rb", ".php", ".ts", ".tsx", ".jsx", ".vue", ".cs", ".swift",
            ".kt", ".scala", ".sql", ".sh", ".ps1", ".bat", ".tf", ".yaml", ".yml"
        }
        file_count = 0

        with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
            for file_info in zip_file.filelist:
                filename_lower = file_info.filename.lower()
                is_code = any(filename_lower.endswith(ext) for ext in code_extensions) or "dockerfile" in filename_lower
                if is_code:
                    try:
                        content = zip_file.read(file_info).decode('utf-8', errors='replace')
                        # Analizar el archivo
                        file_findings = scan_code(content)

                        # Agregar el nombre del archivo a cada hallazgo
                        for finding in file_findings:
                            finding.evidence = f"Archivo: {file_info.filename}\n{finding.evidence}"

                        findings.extend(file_findings)
                        file_count += 1
                    except (UnicodeDecodeError, Exception) as e:
                        err = e

        if file_count == 0:
            return [
                Finding(
                    rule_id="OWASP-A01",
                    title="No se encontraron archivos de código",
                    severity="low",
                    description="El repositorio no contiene archivos de código en formatos soportados.",
                    evidence=f"Extensiones buscadas: {', '.join(code_extensions)}",
                )
            ]
        
    except requests.RequestException as exc:
        return [
            Finding(
                rule_id="OWASP-A01",
                title="Error al descargar el repositorio",
                severity="medium",
                description="No se pudo conectar a GitHub.",
                evidence=str(exc),
            )
        ]
    except Exception as exc:
        return [
            Finding(
                rule_id="OWASP-A01",
                title="Error al procesar el repositorio",
                severity="medium",
                description="Ocurrió un error durante el análisis.",
                evidence=str(exc),
            )
        ]
    
    return findings


def calculate_score(findings: Iterable[Finding]) -> int:
    """Calculate a normalized security score (0-100).

    We assign explicit weights per severity and cap the total penalty to 100.
    This makes the scoring deterministic and adjustable.
    """
    weights = WEIGHTS
    total = 0
    for f in findings:
        total += weights.get(getattr(f, "severity", "low").lower(), 5)
    penalty = min(total, 100)
    return max(100 - penalty, 0)


def penalty_for(finding: Finding) -> int:
    return WEIGHTS.get(getattr(finding, "severity", "low").lower(), 5)


def detect_frameworks(content: str) -> set:
    """Detecta frameworks comunes en el contenido del código."""
    fw = set()
    txt = content.lower()
    if re.search(r"\bfastapi\b", txt):
        fw.add("fastapi")
    if re.search(r"\bflask\b", txt):
        fw.add("flask")
    if re.search(r"\bdjango\b", txt):
        fw.add("django")
    return fw


def remediation_for(rule_id: str, frameworks: set | None = None) -> str:
    """Genera una recomendación base y adapta según framework detectado."""
    base = REMEDIATIONS.get(rule_id, "")
    if not base:
        for prefix in ["OWASP-A01", "OWASP-A02", "OWASP-A03", "OWASP-A04", "OWASP-A05", "OWASP-A06", "OWASP-A07", "OWASP-A08", "OWASP-A09", "OWASP-A10"]:
            if rule_id.startswith(prefix):
                base = REMEDIATIONS.get(prefix, "")
                break
    adapted = base
    if frameworks:
        if "fastapi" in frameworks:
            if rule_id.startswith("OWASP-A05"):
                adapted = "En FastAPI: agrega middleware que establezca cabeceras de seguridad (usar `Starlette` middleware).\n" + adapted
            if rule_id.startswith("OWASP-A06"):
                adapted = "En FastAPI: configura Uvicorn/productor reverse-proxy para ocultar cabecera Server.\n" + adapted
        if "flask" in frameworks:
            if rule_id.startswith("OWASP-A05"):
                adapted = "En Flask: utiliza `Flask-Talisman` o establecer manualmente cabeceras de seguridad en `after_request`.\n" + adapted
        if "django" in frameworks:
            if rule_id.startswith("OWASP-A05"):
                adapted = "En Django: configurar `SECURE_*` settings (HSTS, Content Security Policy a través de middleware).\n" + adapted
    return adapted
