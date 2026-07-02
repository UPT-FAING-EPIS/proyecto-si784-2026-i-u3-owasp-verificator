from pathlib import Path
from fastapi import APIRouter, HTTPException, Request, UploadFile, File
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from app.schemas import ScanOut
from app.store import scan_store
from app.services.pdf_export import export_scan_to_pdf
from app.services.analysis_service import execute_scan

router = APIRouter(prefix="/reports")
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


@router.get("/api/{scan_id}", response_model=ScanOut, dependencies=[])
def report_detail_api(scan_id: int):
    scan = scan_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan no encontrado")
    return scan


@router.get("/api", response_model=list[ScanOut], dependencies=[])
def report_list_api(limit: int = 20):
    safe_limit = min(max(limit, 1), 100)
    return scan_store.list_scans(limit=safe_limit)


@router.get("/{scan_id}/export-pdf", dependencies=[])
def export_report_pdf(scan_id: int):
    """Exporta un reporte de escaneo como PDF."""
    scan = scan_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan no encontrado")
    
    pdf_buffer = export_scan_to_pdf(scan)
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=reporte-seguridad-{scan.id}.pdf"
        },
    )


@router.get("/{scan_id}/export-json", dependencies=[])
def export_report_json(scan_id: int):
    """Exporta un reporte de escaneo como JSON."""
    scan = scan_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan no encontrado")
    
    content = {
        "scan_id": scan.id,
        "target_type": scan.target_type,
        "target_value": scan.target_value,
        "score": scan.score,
        "created_at": scan.created_at.isoformat(),
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "evidence": f.evidence,
                "penalty": f.penalty,
                "remediation": f.remediation,
            }
            for f in scan.findings
        ]
    }
    return JSONResponse(
        content=content,
        headers={
            "Content-Disposition": f"attachment; filename=reporte-seguridad-{scan.id}.json"
        }
    )


@router.get("/{scan_id}", response_class=HTMLResponse, dependencies=[])
def report_detail(request: Request, scan_id: int):
    scan = scan_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan no encontrado")
    return templates.TemplateResponse(request=request, name="report.html", context={"request": request, "scan": scan})
