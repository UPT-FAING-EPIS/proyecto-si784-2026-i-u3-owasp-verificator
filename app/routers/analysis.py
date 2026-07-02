from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Form, HTTPException, Request, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.schemas import AnalyzeRequest, ScanOut
from app.services.analysis_service import execute_scan

router = APIRouter(prefix="/analyze")
templates_dir = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))


def get_current_user_context(request: Request):
    session_id = request.cookies.get("admin_session")
    from app.store import scan_store
    user = scan_store.get_admin_session_user(session_id)
    return {
        "current_user": user,
        "show_donate_btn": scan_store.get_setting("donate_btn_enabled", "true") == "true"
    }

templates.context_processors.append(get_current_user_context)


@router.get("", response_class=HTMLResponse, dependencies=[])
def analyze_form(request: Request):
    session_id = request.cookies.get("admin_session")
    from app.store import scan_store
    current_user = scan_store.get_admin_session_user(session_id)
    if current_user and current_user.get("role") == "admin":
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse(request=request, name="analyze.html", context={"request": request})


@router.post("", response_class=HTMLResponse, dependencies=[])
async def analyze(
    request: Request,
    target_type: str = Form(...),
    target_value: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    create_issues: Optional[str] = Form(None),
    github_token: Optional[str] = Form(None),
):
    session_id = request.cookies.get("admin_session")
    from app.store import scan_store
    current_user = scan_store.get_admin_session_user(session_id)
    if current_user and current_user.get("role") == "admin":
        return RedirectResponse(url="/dashboard", status_code=303)
    try:
        # Si es archivo, leer el contenido del archivo
        if target_type == "archivo":
            if not file or file.filename == "":
                raise ValueError("Por favor selecciona un archivo")
            content = await file.read()
            target_value = content.decode('utf-8')
        else:
            if not target_value or not target_value.strip():
                raise ValueError("target_value es requerido para este tipo de análisis")
        
        # Determine boolean value for create_issues (checkbox may send string)
        create_issues_flag = False
        if create_issues is not None:
            try:
                if isinstance(create_issues, str):
                    create_issues_flag = create_issues.lower() not in ('0', 'false', 'off')
                else:
                    create_issues_flag = bool(create_issues)
            except Exception:
                create_issues_flag = False

        # Clean up token (strip whitespace)
        token = github_token.strip() if github_token else None

        # Fetch active session owner if logged in
        session_id = request.cookies.get("admin_session")
        from app.store import scan_store
        user_info = scan_store.get_admin_session_user(session_id)
        username = user_info["username"] if user_info else None

        # Save/load token logic for logged in users
        if username:
            if token:
                scan_store.update_user_github_token(username, token)
            else:
                if user_info and user_info.get("github_token"):
                    token = user_info["github_token"]

        scan = execute_scan(target_type=target_type, target_value=target_value, create_issues=create_issues_flag, github_token=token, username=username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return RedirectResponse(url=f"/reports/{scan.id}", status_code=303)


@router.post("/api", response_model=ScanOut, dependencies=[])
def analyze_api(payload: AnalyzeRequest):
    try:
        return execute_scan(target_type=payload.target_type, target_value=payload.target_value, create_issues=payload.create_issues)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
