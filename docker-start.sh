#!/bin/bash
# docker-start.sh — Inicia ambos servicios en el mismo contenedor
# En producción real, considera usar dos contenedores separados.

set -e

echo "🚀 Iniciando OWASP Verificador Web App (puerto 8000)..."
uvicorn app.main:app \
    --host 0.0.0.0 \
    --port ${PORT:-8000} \
    --workers 2 \
    --log-level info &

echo "🔌 Iniciando OWASP API Microservice (puerto 8001)..."
uvicorn api.main:app \
    --host 0.0.0.0 \
    --port ${API_PORT:-8001} \
    --workers 2 \
    --log-level info &

# Esperar a que alguno termine (o falle)
wait -n
