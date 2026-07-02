# OWASP Verificator

**OWASP Verificator** es un ecosistema de herramientas diseñadas para evaluar y mejorar el cumplimiento de las directrices de seguridad de **OWASP Top 10** en tu código de forma ágil, simple y ampliable.

El proyecto consta de dos componentes principales:
1. **Extensión de VS Code (v0.1.8):** Un asistente de desarrollo en tiempo real con dashboard premium e integración directa con IA.
2. **Sistema Web API (FastAPI):** Un backend de análisis estático de código, escaneo de URLs de producción e historial en memoria.

---

## 1. Extensión de Visual Studio Code (v0.1.8)

La extensión permite realizar análisis estáticos de seguridad en tiempo real y visualizar un reporte interactivo sobre cumplimiento de OWASP directamente desde tu entorno de desarrollo.

### Características Clave

* **Soporte Multi-Lenguaje Universal:** Escanea archivos de **C#** (`.cs`), **ASP.NET** (`.cshtml`, `.aspx`, etc.), **Python**, **JavaScript/TypeScript**, **Java**, **PHP**, **Go**, **C/C++**, **Rust**, **Ruby**, **Swift**, **Kotlin**, **Lua** y más.
* **Dashboard Interactivo Premium:** Una interfaz gráfica integrada con estética *glassmorphic*, sombras HSL, y barra de progreso. Permite buscar, filtrar y colapsar archivos con animaciones fluidas, y saltar directamente a la línea vulnerable.
* **Integración Directa con IA (Copilot / Gemini):** Envía automáticamente las consultas de remediación a los paneles de chat de **GitHub Copilot** o **Google Gemini** con un solo clic. El prompt requiere que la IA te explique brevemente el problema y la solución antes de escribir el bloque de código final.
* **Acciones de Código (Quick Fixes):** Ofrece arreglos automáticos y seguros específicos para Python (como reemplazar secretos expuestos con `os.getenv()` o registrar excepciones ocultas con `logging.exception()`).
* **Modo "Puro Dashboard":** Opción configurable (`owaspVerificator.showDiagnostics`) para desactivar el subrayado de errores en el editor si prefieres gestionar la seguridad únicamente desde el Dashboard.
* **Indicador en la Barra de Estado:** Iconos dinámicos en la barra inferior que resumen el estado de seguridad global.

### Cómo instalar y probar la Extensión (.vsix)

Para utilizar la última versión empaquetada:
1. Abre VS Code y ve a la barra lateral de **Extensiones** (`Ctrl+Shift+X`).
2. Haz clic en el icono de los tres puntos (`...`) en la parte superior derecha.
3. Selecciona **Instalar desde VSIX (Install from VSIX...)**.
4. Elige el archivo [vscode-extension/owasp-verificator-0.1.8.vsix](vscode-extension/owasp-verificator-0.1.8.vsix) del repositorio y reinicia VS Code.

### Cómo probar la Extensión en Desarrollo

1. Abre la carpeta `vscode-extension` en una ventana limpia de VS Code.
2. Presiona la tecla **F5** (o ve a *Run and Debug* y selecciona *Launch Extension*).
3. En la nueva ventana **[Host de desarrollo de extensiones]**, abre cualquier proyecto o archivo de prueba.
4. Escribe código con vulnerabilidades (ej. `password = "secreto"` o `eval(input)`) y guárdalo para ver el análisis en tiempo real.

---

## 2. Sistema Web y API (FastAPI)

El sistema web central provee una interfaz ligera y una API RESTful para realizar auditorías rápidas de código y verificar la presencia de cabeceras HTTP de seguridad en endpoints públicos.

### Características Clave

* **Auditoría de URLs de Producción:** Examina respuestas HTTP/HTTPS de cualquier dirección URL provista y evalúa la ausencia o mala configuración de cabeceras críticas (CSP, HSTS, X-Frame-Options, etc.).
* **Auditoría de Bloques de Código:** Formulario para pegar fragmentos de código y evaluarlos inmediatamente.
* **Historial en Memoria:** Registro temporal de análisis y hallazgos recientes para revisar desde el panel web.
* **API REST Completa:** Integrable con herramientas de integración continua (CI/CD) u otros editores de código.

### Stack Tecnológico
- Python 3.11+
- FastAPI (Framework API)
- Jinja2 (Renderizado de plantillas HTML)
- CSS Puro (Diseño responsivo sin librerías externas)
- Pytest (Automatización de pruebas unitarias)

### Ejecución Local del Servidor

1. Instala las dependencias requeridas:
   ```bash
   pip install -r requirements.txt
   ```
2. Configura las variables de entorno copiando el archivo de ejemplo:
   ```bash
   cp .env.example .env
   ```
3. Ejecuta el servidor Uvicorn en modo desarrollo:
   ```bash
   uvicorn app.main:app --reload
   ```
4. Abre tu navegador en `http://127.0.0.1:8000` para acceder a la interfaz de usuario.

### Pruebas Unitarias
El backend incluye pruebas automáticas. Puedes ejecutarlas utilizando pytest:
```bash
python -m pytest -q
```

### Despliegue Automatizado en Azure
El repositorio cuenta con una acción de GitHub en `.github/workflows/azure-webapp.yml` que aprovisiona automáticamente un Resource Group, un App Service Plan y una Web App Python en Azure al hacer push a la rama `main` (requiere configurar la credencial `AZURE_CREDENTIALS` en los Secrets del repositorio).

---

## Documentación del Proyecto
Para conocer más detalles sobre la arquitectura y la planeación del proyecto:
- **Requisitos Funcionales y No Funcionales:** [docs/requirements.md](docs/requirements.md)
- **Roadmap del Proyecto:** [docs/roadmap.md](docs/roadmap.md)

---

## Apoyo y Donaciones

Si este ecosistema o la extensión te resultan de utilidad, puedes apoyar su mantenimiento y desarrollo mediante donaciones:

[![Donar con PayPal](https://img.shields.io/badge/Donate-PayPal-blue.svg?style=for-the-badge&logo=paypal)](https://www.paypal.com/donate/?hosted_button_id=MASK8JSBNSZPQ)
