---
name: owasp-verifier-dashboard
description: >-
  Mantiene y actualiza el panel unificado de control de pruebas de calidad y
  seguridad OWASP en GitHub Pages, incluyendo reportes interactivos de SonarCloud
  y remediaciones automatizadas con Inteligencia Artificial.
---

# OWASP Verifier Dashboard Manager

## Overview
Esta skill permite a los agentes gestionar, actualizar y solucionar problemas relacionados con el panel de control unificado y los reportes de pruebas publicados en GitHub Pages para el proyecto `proyecto-si784-2026-i-u3-owasp-verificator`.

## API Scan Backend
El backend de análisis de cumplimiento OWASP de la aplicación está desplegado y disponible en:
- **Base URL**: `http://38.250.116.71:8000`
- **Servicio principal**:
  - `POST http://38.250.116.71:8000/analyze/api`
  - Cabeceras requeridas: `x-api-key: ${{ secrets.OWASP_VERIFICATOR_TOKEN }}` y `Content-Type: application/json`.
  - Token de API activo para pruebas/desarrollo: `eca71480-42f0-4948-b6e3-4455c26b3204`.
  - Parámetros: `{ "target_type": "github_repo", "target_value": "URL_DEL_REPO", "create_issues": false }`.

## Quick Start

Para regenerar el Dashboard principal en `public-root/index.html` después de cualquier prueba:
```bash
python3 scripts/generate_index.py
```

Para procesar un escaneo de seguridad OWASP (`response.json`) y generar el reporte interactivo con remediaciones por IA:
```bash
python3 scripts/generate_report.py
```

## Estructura de Reportes y Rutas
Los reportes se organizan en las siguientes carpetas dentro de la rama `gh-pages`:
- **Dashboard Principal**: Raíz `/index.html` (generado por `scripts/generate_index.py`).
- **Pruebas Unitarias**: `/unit/index.html` (generado por Pytest).
- **Pruebas de Integración**: `/integration/index.html` (generado por Pytest).
- **Pruebas UI**: `/ui/index.html` (generado por Playwright).
- **Pruebas BDD**: `/bdd/index.html` (generado por Behave).
- **Pruebas de Mutación**: `/mutation/index.html` (generado por Mutmut).
- **Análisis Estático (Semgrep)**: `/semgrep/index.html` (generado por Semgrep HTML).
- **Dependencias (Snyk)**: `/snyk/index.html` (generado por Snyk HTML).
- **Calidad (SonarCloud)**: `/sonar/index.html` (generado por `scripts/generate_sonar_report.py`).
- **Auditoría de IA (Skill IA)**: `/skill-ia/index.html` (generado por `scripts/generate_report.py`).

## Scripts de Utilidad

### 1. `generate_index.py`
- **Ubicación**: `scripts/generate_index.py`
- **Función**: Genera la página de inicio principal (`index.html`) con un diseño premium y responsive, enlazando los 9 módulos de prueba. No incluye accesos redundantes a cobertura.

### 2. `generate_report.py`
- **Ubicación**: `scripts/generate_report.py`
- **Función**: Lee `response.json` (reporte de análisis OWASP), consulta las remediaciones mediante `gpt-4o-mini` usando la API de GitHub Inference, y genera un reporte HTML interactivo con pestañas:
  - **Pestaña 1 (Detalle de Hallazgos)**: Detalle del escaneo.
  - **Pestaña 2 (Remediaciones con IA)**: Soluciones sugeridas.
- **Requisito**: Requiere la variable de entorno `GH_PAT` con un token de acceso que tenga permisos de uso para GitHub Models.

### 3. `generate_sonar_report.py`
- **Ubicación**: `scripts/generate_sonar_report.py`
- **Función**: Procesa el archivo `metrics.json` de métricas de calidad de SonarCloud y genera un reporte HTML interactivo `/sonar/index.html`.

## Reglas de Concurrencia de Despliegue
Para evitar fallos de empuje de Git en paralelo (`cannot lock ref 'refs/heads/gh-pages'`), todos los flujos de trabajo en `.github/workflows/` deben compartir el grupo de concurrencia:
```yaml
concurrency:
  group: gh-pages-deploy
  cancel-in-progress: false
```

## Errores Comunes
1. **Error HTTP 401 en la Skill de IA**: Ocurre si `GH_PAT` no está configurado en los secretos de GitHub Actions o no es válido. El script continuará sin bloquear el flujo pero advertirá en el reporte que falta configurar la clave.
2. **Pérdida de archivos en GH Pages**: Al desplegar reportes individuales, asegúrate de que el paso de despliegue tenga `keep_files: true` para evitar borrar los reportes de otros workflows.
