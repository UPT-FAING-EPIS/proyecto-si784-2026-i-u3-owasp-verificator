from pathlib import Path
import os
import hashlib
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.store import scan_store
from app.services.analysis_service import calculate_dashboard_statistics

router = APIRouter()
templates_dir = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))


# Add global context processor to make current_user available in all templates
def get_current_user_context(request: Request):
    session_id = request.cookies.get("admin_session")
    user = scan_store.get_admin_session_user(session_id)
    return {
        "current_user": user,
        "show_donate_btn": scan_store.get_setting("donate_btn_enabled", "true") == "true"
    }

templates.context_processors.append(get_current_user_context)


@router.get("/register", response_class=HTMLResponse, dependencies=[])
def admin_register_form(request: Request):
    session_id = request.cookies.get("admin_session")
    if scan_store.validate_admin_session(session_id):
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="admin_register.html",
        context={"request": request, "error": None, "success": None},
    )


@router.post("/register", response_class=HTMLResponse, dependencies=[])
def admin_register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    email: str = Form(...)
):
    username_clean = username.strip()
    email_clean = email.strip() if email else None
    if not username_clean:
        return templates.TemplateResponse(
            request=request,
            name="admin_register.html",
            context={"request": request, "error": "El nombre de usuario no puede estar vacío."},
            status_code=400,
        )
    
    success = scan_store.create_user(username_clean, password, "user", email_clean)
    if not success:
        return templates.TemplateResponse(
            request=request,
            name="admin_register.html",
            context={"request": request, "error": f"El usuario '{username_clean}' ya está registrado."},
            status_code=400,
        )
        
    return templates.TemplateResponse(
        request=request,
        name="admin_login.html",
        context={"request": request, "success": f"Registro exitoso para '{username_clean}'. Por favor inicia sesión.", "error": None},
    )


@router.get("/login", response_class=HTMLResponse, dependencies=[])
def admin_login_form(request: Request):
    session_id = request.cookies.get("admin_session")
    if scan_store.validate_admin_session(session_id):
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="admin_login.html",
        context={"request": request, "error": None, "success": None},
    )


@router.post("/login", response_class=HTMLResponse, dependencies=[])
def admin_login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = scan_store.get_user(username)
    if not user:
        return templates.TemplateResponse(
            request=request,
            name="admin_login.html",
            context={"request": request, "error": "Usuario o contraseña incorrectos."},
            status_code=401,
        )
        
    password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    if user["password_hash"] != password_hash:
        return templates.TemplateResponse(
            request=request,
            name="admin_login.html",
            context={"request": request, "error": "Usuario o contraseña incorrectos."},
            status_code=401,
        )

    session_id = scan_store.create_admin_session(user["username"])
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        key="admin_session",
        value=session_id,
        httponly=True,
        samesite="lax",
        max_age=6 * 60 * 60,
        path="/",
    )
    return response


@router.get("/logout", dependencies=[])
def admin_logout(request: Request):
    session_id = request.cookies.get("admin_session")
    scan_store.revoke_admin_session(session_id)
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("admin_session", path="/")
    return response


# Redirect /admin to /dashboard for backward compatibility
@router.get("/admin", dependencies=[])
def admin_redirect():
    return RedirectResponse(url="/dashboard", status_code=303)


@router.get("/dashboard", response_class=HTMLResponse, dependencies=[])
def user_dashboard(request: Request):
    """Dashboard del usuario con sus estadísticas y control."""
    session_id = request.cookies.get("admin_session")
    if not scan_store.validate_admin_session(session_id):
        return RedirectResponse(url="/login", status_code=303)

    current_user = scan_store.get_admin_session_user(session_id)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    if current_user["role"] == "admin":
        scans = scan_store.list_scans()
    else:
        scans = scan_store.list_scans(username=current_user["username"])
    
    # Delegar el cálculo de estadísticas a la capa de servicios
    dash_data = calculate_dashboard_statistics(scans)
    
    # Get tokens (scoped: all if admin, only own if user)
    if current_user["role"] == "admin":
        tokens = scan_store.get_all_tokens()
    else:
        tokens = scan_store.get_tokens_by_user(current_user["username"])
        
    accesses = scan_store.list_accesses(limit=100)
    users = scan_store.list_users()
    
    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={
            "request": request,
            "stats": dash_data["stats"],
            "risk_matrix": dash_data["risk_matrix"],
            "tokens": tokens,
            "accesses": accesses,
            "scans_data": dash_data["scans_data"],
            "scans": scans,
            "current_user": current_user,
            "users": users,
        },
    )


@router.post("/dashboard/tokens", response_class=HTMLResponse)
def create_token_route(request: Request):
    session_id = request.cookies.get("admin_session")
    if not scan_store.validate_admin_session(session_id):
        return RedirectResponse(url="/login", status_code=303)
        
    current_user = scan_store.get_admin_session_user(session_id)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
        
    scan_store.generate_token(current_user["username"])
    return RedirectResponse(url="/dashboard", status_code=303)


@router.get("/dashboard/users", response_class=HTMLResponse)
def admin_users_management(request: Request):
    session_id = request.cookies.get("admin_session")
    if not scan_store.validate_admin_session(session_id):
        return RedirectResponse(url="/login", status_code=303)
        
    current_user = scan_store.get_admin_session_user(session_id)
    if not current_user or current_user.get("role") != "admin":
        return RedirectResponse(url="/dashboard", status_code=303)
        
    users = scan_store.list_users()
    return templates.TemplateResponse(
        request=request,
        name="admin_users.html",
        context={
            "request": request,
            "current_user": current_user,
            "users": users,
        }
    )


@router.post("/dashboard/users/delete", response_class=HTMLResponse)
def delete_user_route(request: Request, username: str = Form(...)):
    session_id = request.cookies.get("admin_session")
    if not scan_store.validate_admin_session(session_id):
        return RedirectResponse(url="/login", status_code=303)
        
    current_user = scan_store.get_admin_session_user(session_id)
    if not current_user or current_user.get("role") != "admin":
        return RedirectResponse(url="/dashboard", status_code=303)
        
    if username != "admin" and username != current_user.get("username"):
        scan_store.delete_user(username)
        
    return RedirectResponse(url="/dashboard/users", status_code=303)


@router.post("/dashboard/users/create-admin", response_class=HTMLResponse)
def create_admin_route(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    email: str = Form(...)
):
    session_id = request.cookies.get("admin_session")
    if not scan_store.validate_admin_session(session_id):
        return RedirectResponse(url="/login", status_code=303)
        
    current_user = scan_store.get_admin_session_user(session_id)
    if not current_user or current_user.get("role") != "admin":
        return RedirectResponse(url="/dashboard", status_code=303)
        
    username_clean = username.strip()
    email_clean = email.strip() if email else None
    if username_clean:
        scan_store.create_user(username_clean, password, "admin", email_clean)
        
    return RedirectResponse(url="/dashboard/users", status_code=303)


@router.post("/dashboard/github-token", response_class=HTMLResponse)
def update_github_token_route(
    request: Request,
    github_token: str = Form(""),
    action: str = Form("save")
):
    session_id = request.cookies.get("admin_session")
    if not scan_store.validate_admin_session(session_id):
        return RedirectResponse(url="/login", status_code=303)
        
    current_user = scan_store.get_admin_session_user(session_id)
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
        
    username = current_user["username"]
    token_to_save = github_token.strip() if action == "save" else None
    scan_store.update_user_github_token(username, token_to_save)
    return RedirectResponse(url="/dashboard", status_code=303)


@router.get("/api-tutorial", response_class=HTMLResponse, dependencies=[])
def api_tutorial(request: Request):
    """Página con tutorial de integración de la API."""
    return templates.TemplateResponse(
        request=request,
        name="api_tutorial.html",
        context={"request": request, "title": "Integraciones"},
    )


@router.get("/", response_class=HTMLResponse, dependencies=[])
def home(request: Request):
    scans = scan_store.list_scans()
    
    # Calculate statistics
    total_scans = len(scans)
    total_findings = sum(len(scan.findings) for scan in scans)
    avg_score = round(sum(scan.score for scan in scans) / total_scans, 1) if total_scans > 0 else 0
    high_severity_count = sum(
        1 for scan in scans 
        for finding in scan.findings 
        if finding.severity == 'high'
    )
    
    stats = {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "avg_score": avg_score,
        "high_severity": high_severity_count,
    }
    
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"request": request, "scans": scans, "stats": stats},
    )


@router.get("/about", response_class=HTMLResponse, dependencies=[])
def about(request: Request):
    return templates.TemplateResponse(request=request, name="about.html", context={"request": request})


@router.get("/owasp", response_class=HTMLResponse, dependencies=[])
def owasp_wiki(request: Request):
    return templates.TemplateResponse(request=request, name="owasp_wiki.html", context={"request": request})


@router.get("/monitoring", response_class=HTMLResponse, dependencies=[])
def monitoring_accesses(request: Request):
    # Fetch recent accesses and deduplicate by IP (keep most recent per IP)
    accesses = scan_store.list_accesses(limit=1000)
    seen = set()
    unique_accesses = []
    for a in accesses:
        ip = a.get("ip")
        if not ip:
            continue
        if ip in seen:
            continue
        seen.add(ip)
        unique_accesses.append(a)

    return templates.TemplateResponse(request=request, name="monitoring.html", context={"request": request, "accesses": unique_accesses})


@router.get("/integraciones", dependencies=[])
def integraciones():
    """Redirige la ruta antigua de integraciones a api-tutorial."""
    return RedirectResponse(url="/api-tutorial", status_code=308)


@router.post("/dashboard/settings", response_class=HTMLResponse)
def update_settings(request: Request, donate_btn_enabled: str = Form(None)):
    session_id = request.cookies.get("admin_session")
    if not scan_store.validate_admin_session(session_id):
        return RedirectResponse(url="/login", status_code=303)
        
    current_user = scan_store.get_admin_session_user(session_id)
    if not current_user or current_user.get("role") != "admin":
        return RedirectResponse(url="/dashboard", status_code=303)
        
    val = "true" if donate_btn_enabled == "on" else "false"
    scan_store.set_setting("donate_btn_enabled", val)
    
    return RedirectResponse(url="/dashboard", status_code=303)
