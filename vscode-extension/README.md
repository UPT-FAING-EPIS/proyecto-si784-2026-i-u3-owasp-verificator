# OWASP Verificator - Extensión de VS Code

Esta extensión permite realizar análisis estáticos de seguridad en tiempo real sobre cumplimiento de **OWASP Top 10** en cualquier archivo de tu proyecto.

## Características

* **Análisis Automático:** Examina el archivo abierto al guardarlo, abrirlo o cambiar entre editores.
* **Diagnósticos Visuales:** Subraya directamente en tu editor los problemas detectados (en rojo para severidad alta, amarillo para media).
* **Remediación en Tiempo Real:** Coloca el cursor sobre el error resaltado para ver el detalle de la vulnerabilidad y la recomendación específica de cómo solucionarla (adaptada al framework que estés usando si es Django, Flask o FastAPI).
* **Indicador en la Barra de Estado:** Muestra un resumen del estado de seguridad en la barra inferior izquierda (por ejemplo, `$(check) OWASP: Seguro` o `$(bug) OWASP: 2 errores`).

---

## Requisitos Previos

1. **Python 3** debe estar instalado y disponible en tu variable de entorno PATH (puedes verificarlo ejecutando `python --version` en una terminal).
   *Nota: La extensión es completamente autocontenida y no requiere de ningún paquete o instalación adicional para escanear tus archivos.*

---

## Cómo Probar y Ejecutar la Extensión en Desarrollo

Dado que la extensión está construida en **JavaScript Vanilla** (sin TypeScript ni dependencias externas), puedes probarla inmediatamente en VS Code:

1. Abre la carpeta `vscode-extension` en una nueva ventana de VS Code.
2. Presiona la tecla **F5** (o ve a la pestaña *Ejecutar y depurar* en el menú lateral y haz clic en *Iniciar depuración / Launch Extension*).
3. Se abrirá una nueva ventana de VS Code llamada **[Host de desarrollo de extensiones]**.
4. En esa nueva ventana, abre el proyecto de **OWASP Verificator** (o cualquier carpeta que contenga archivos de código).
5. Abre cualquier archivo de código (por ejemplo, `app/main.py` o crea un archivo de prueba `test.py` con una línea como `password = "secreto"`) y guárdalo.
6. ¡Verás los subrayados de seguridad en el código y el estado en la barra de tareas!

---

## Configuración Personalizada

Si tu ejecutable de Python tiene un nombre diferente (por ejemplo, `python3` o `py`), puedes configurarlo desde los Ajustes de VS Code:
1. Ve a `File > Preferences > Settings`.
2. Busca `OWASP Verificator`.
3. Edita la opción **Python Path** ingresando tu comando personalizado.

---

## Donaciones

Si esta extensión te ha sido de utilidad y deseas apoyar su desarrollo, puedes realizar una donación aquí:

[![Donar con PayPal](https://img.shields.io/badge/Donate-PayPal-blue.svg?style=for-the-badge&logo=paypal)](https://www.paypal.com/donate/?hosted_button_id=MASK8JSBNSZPQ)

