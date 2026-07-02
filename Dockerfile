# ─────────────────────────────────────────────────────────────────────────────
# Dockerfile — OWASP Verificador + API Microservice
# Ejecuta ambos sistemas: web app (puerto 8000) y API (puerto 8001)
# Para producción, usa Gunicorn en lugar de Uvicorn directamente.
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.12-slim AS base

# Metadata
LABEL org.opencontainers.image.title="OWASP Verificador"
LABEL org.opencontainers.image.description="OWASP Compliance Checker + API Microservice"

# Variables de entorno
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production \
    APP_DATA_PATH=/app/data \
    PORT=8000 \
    API_PORT=8001

# Directorio de trabajo
WORKDIR /app

# Instalar dependencias del sistema (mínimas)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copiar e instalar dependencias Python primero (mejor cache)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copiar código fuente
COPY . .

# Crear directorio de datos persistente
RUN mkdir -p /app/data

# Exponer puertos
EXPOSE 8000
EXPOSE 8001

# Health check para el sistema web
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Script de inicio: arranca ambos servicios
COPY docker-start.sh /docker-start.sh
RUN chmod +x /docker-start.sh

CMD ["/docker-start.sh"]
