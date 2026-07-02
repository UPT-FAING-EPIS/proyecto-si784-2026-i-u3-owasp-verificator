# FD08 - Estándares de Programación

**UNIVERSIDAD PRIVADA DE TACNA**

**FACULTAD DE INGENIERÍA**

**Escuela Profesional de Ingeniería de Sistemas**

**Proyecto:** Sistema Verificador de Cumplimiento OWASP

Curso: Calidad y Pruebas de Software

Docente: Patrick Jose Cuadros Quiroga

Integrantes:
- Andia Navarro, Diego Fabrizio - 2022073906
- Concha Llaca Gerardo Alejandro - 2017057849

Tacna – Perú

2026

---

## CONTROL DE VERSIONES

| Versión | Hecha por | Revisada por | Aprobada por | Fecha | Motivo |
|---|---|---|---|---|---|
| 1.0 | Equipo | Profesor | - | 24/06/2026 | Versión inicial de los estándares de programación |

---

## 1. Introducción
Este documento establece las directrices de codificación, estilos y buenas prácticas de desarrollo para el **Sistema Verificador de Cumplimiento OWASP**. El cumplimiento de estas normas garantiza la legibilidad del código, facilita el mantenimiento colaborativo y previene la introducción de vulnerabilidades en el propio sistema.

El proyecto está compuesto por dos tecnologías principales:
1. **Backend (Python + FastAPI)**
2. **Extensión de VS Code (JavaScript + HTML/CSS)**

---

## 2. Estándares para el Backend (Python)

### 2.1 Formato y Estilo de Código (PEP 8)
Se sigue el estándar oficial **PEP 8** con las siguientes precisiones:
- **Indentación:** Se deben utilizar estrictamente **4 espacios** por nivel de anidamiento. No se permiten tabulaciones (`\t`).
- **Límite de caracteres por línea:** Un máximo de 100 caracteres por línea para favorecer la lectura vertical en pantallas estándar.
- **Nombres de archivos y directorios:** Deben escribirse en minúsculas y separados por guiones bajos si es necesario (ej: `analysis_service.py`).
- **Nombres de variables y funciones:** En formato `snake_case` (ej: `calculate_score()`, `scan_store`).
- **Nombres de clases:** En formato `PascalCase` (ej: `InMemoryScanStore`, `APIToken`).
- **Nombres de constantes:** En mayúsculas y en formato `SNAKE_CASE` (ej: `KNOWN_CVES`, `WEIGHTS`).

### 2.2 Tipado Estático y Modelado de Datos
- **Anotaciones de Tipo (Type Hints):** Se deben definir los tipos de datos en la firma de cada función o método público para facilitar la depuración estática.
  ```python
  def calculate_score(findings: Iterable[Finding]) -> int:
  ```
- **Modelos de Datos:** 
  - Usar `dataclasses` (en [models.py](file:///c:/Users/Equipo/Downloads/proyecto-si784-2026-i-u1-verificador-de-cumplimiento-de-owasp-main/app/models.py)) para representar las entidades del dominio de forma ligera.
  - Usar `Pydantic` (en [schemas.py](file:///c:/Users/Equipo/Downloads/proyecto-si784-2026-i-u1-verificador-de-cumplimiento-de-owasp-main/app/schemas.py)) para la validación y serialización de los payloads que ingresan y salen de la API REST.

### 2.3 Arquitectura y Organización del Código
- **Desacoplamiento de Capas:** Las rutas (`app/routers/`) solo deben encargarse de la validación inicial del protocolo HTTP/API y la delegación. La lógica de auditoría pesada debe delegarse a los servicios independientes en `app/services/`.
- **Manejo del Estado y Concurrencia:** La persistencia y el estado de la aplicación se gestionan de forma centralizada a través de `app/store.py`. Al ser un servidor web asíncrono multiproceso, todas las operaciones de escritura y lectura en variables del servidor deben protegerse con un bloqueo de exclusión mutua (`threading.Lock`) para evitar condiciones de carrera (Race Conditions).

### 2.4 Control de Seguridad en el Backend
- **Evitar la Inyección SQL y de Código:** Queda terminantemente prohibido concatenar variables en sentencias SQL en crudo. Se debe usar la parametrización de consultas nativa de `sqlite3`.
- **Secretos del Sistema:** Ninguna clave de API, token de administrador o credencial de desarrollo debe grabarse directamente en el código fuente. Se debe utilizar siempre `os.getenv()` con valores de respaldo definidos en el archivo `.env`.

---

## 3. Estándares para la Extensión de VS Code (JavaScript)

### 3.1 Estilo de JavaScript
Dado que la extensión se desarrolla en **JavaScript Vanilla** para mantenerla ligera y autocontenida:
- **Variables y Constantes:** Se debe priorizar el uso de `const` para referencias que no cambian de valor y `let` para las variables mutables. El uso de `var` está desaconsejado.
- **Nombres de funciones y variables:** En formato `camelCase` (ej: `updateStatusBar()`, `currentDiagnostics`).
- **Nombres de constantes:** En formato `SNAKE_CASE` (ej: `PYTHON_PATH_SETTING`).
- **Manejo de Promesas:** Se debe utilizar la sintaxis `async/await` en lugar de encadenar múltiples `.then()` para asegurar la legibilidad en procesos asíncronos (como el llamado al ejecutable de Python).

### 3.2 Arquitectura de la Extensión
- **Ciclo de Vida y Eventos:** El archivo `extension.js` debe inicializar recursos únicamente en el método `activate(context)`. Se deben registrar las suscripciones de los comandos y diagnostic collections para que se liberen limpiamente en `deactivate()`.
- **Comunicación Webview-Host:** La comunicación entre el panel del Dashboard (HTML renderizado en Webview) y el Host de VS Code debe canalizarse exclusivamente a través del paso de mensajes seguro (`vscode.postMessage` y `window.addEventListener('message')`).

---

## 4. Estándares para el Frontend (HTML y CSS)

### 4.1 HTML
- **HTML5 Semántico:** Usar etiquetas descriptivas como `<header>`, `<nav>`, `<main>`, `<section>`, `<article>` y `<footer>` en lugar de agrupar todo en contenedores genéricos `<div>`.
- **Accesibilidad:** Todos los elementos interactivos (botones, inputs, enlaces) deben contar con atributos claros y etiquetas descriptivas. Los campos del formulario deben estar conectados a sus `<label>` correspondientes.

### 4.2 CSS
- **Sin Librerías / Frameworks:** Todo el diseño estético de la aplicación web y de la extensión debe realizarse con CSS Vanilla, evitando TailwindCSS o Bootstrap, lo que reduce la latencia y elimina dependencias.
- **Variables de CSS:** Definir un sistema de tokens de diseño globales (colores de fondo, bordes, espaciados y tipografía) en el bloque `:root`.
- **Diseño Glassmorphism y Rich Aesthetics:**
  - Emplear sombras suaves basadas en HSL (`box-shadow: 0 8px 32px 0 hsla(...)`).
  - Utilizar el filtro de desenfoque de fondo (`backdrop-filter: blur(12px)`) para lograr el efecto esmerilado de vidrio.
  - Asegurar la responsividad total utilizando Flexbox y CSS Grid.

---

## 5. Pruebas y Aseguramiento de Calidad

### 5.1 Pruebas Unitarias
- Cada nueva funcionalidad, regla del escáner o ruta del API debe contar con pruebas unitarias implementadas en el directorio `/tests`.
- Se utiliza el framework `pytest`. Para ejecutar la suite de pruebas localmente se debe invocar:
  ```bash
  python -m pytest -q
  ```

### 5.2 Estándar de Mensajes de Commit (Git)
Se recomienda seguir la especificación de commits convencionales para facilitar el seguimiento del historial de cambios:
- `feat`: incorporación de una nueva funcionalidad (ej. `feat: agregar analisis de repositorio github`).
- `fix`: corrección de un error o vulnerabilidad (ej. `fix: corregir inyeccion de comandos en ejecutor python`).
- `docs`: modificaciones o adición de documentación (ej. `docs: crear diccionario de datos`).
- `refactor`: cambios en el código que no alteran el comportamiento del sistema.
