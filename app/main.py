from fastapi import FastAPI, Request, HTTPException, Header, Form
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone
import os

from app.config import get_settings
from app.routers.analysis import router as analysis_router
from app.routers.dashboard import router as dashboard_router
from app.routers.reports import router as reports_router
from app.store import scan_store

settings = get_settings()
app = FastAPI(
    title=settings.app_title,
    description="Verificador de Cumplimiento OWASP - Herramienta de análisis de seguridad",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Asset version used to bust browser cache after each deploy.
# You can set ASSET_VERSION in your deployment pipeline (recommended).
app.state.asset_version = os.getenv("ASSET_VERSION") or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

# Ruta absoluta para archivos estáticos
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

@app.middleware("http")
async def access_logger(request: Request, call_next):
    # Prefer X-Forwarded-For or X-Real-IP when behind proxies; fallback to request.client
    xff = request.headers.get("x-forwarded-for") or request.headers.get("X-Real-IP")
    if xff:
        client_ip = xff.split(",")[0].strip()
    else:
        client_ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "")
    try:
        scan_store.log_access(path=str(request.url.path), ip=client_ip, user_agent=ua)
    except Exception as e:
        # Ignore access logging failure
        err = e
    response = await call_next(request)

    # Avoid stale HTML after deployment; assets are cache-busted via version query.
    content_type = (response.headers.get("content-type") or "").lower()
    if "text/html" in content_type:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    return response

@app.get("/health", dependencies=[])
def health_check():
    """Health check endpoint - verifica que el servicio está operativo."""
    return {"status": "ok", "env": settings.app_env}


@app.post("/api/token", dependencies=[])
def generate_api_token(username: str = Form(...)):
    """Genera un nuevo token API para el usuario especificado."""
    if not username or len(username.strip()) < 2:
        raise HTTPException(status_code=400, detail="Nombre de usuario inválido")
    token = scan_store.generate_token(username.strip())
    return {"token": token, "user": username.strip(), "message": "Token generado exitosamente"}


@app.get("/api/validate-token", dependencies=[])
def validate_api_token(x_api_key: Optional[str] = Header(None)):
    """Valida un token API y retorna información del usuario."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Token no proporcionado")
    
    result = scan_store.validate_token(x_api_key)
    if not result:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")
    
    return result


app.include_router(dashboard_router)
app.include_router(analysis_router)
app.include_router(reports_router)
