from app.models import Finding, Scan
from app.services.scanner import (
    calculate_score,
    scan_code,
    scan_url,
    scan_github_repo,
    detect_frameworks,
    penalty_for,
    remediation_for,
)
from app.services.github_integration import create_issues_for_findings
import threading
import logging
from urllib.parse import urlparse

logger = logging.getLogger("analysis_service")
from app.store import scan_store
import json
from datetime import datetime


def execute_scan(target_type: str, target_value: str, create_issues: bool = False, github_token: str | None = None, username: str | None = None) -> Scan:
    effective_github_token = github_token

    if target_type == "code":
        findings = scan_code(target_value)
    elif target_type == "url":
        findings = scan_url(target_value)
    elif target_type == "archivo":
        # Procesar archivo como código
        findings = scan_code(target_value)
    elif target_type == "github_repo":
        # Descargar y procesar repositorio de GitHub
        findings = scan_github_repo(target_value, github_token=effective_github_token)
    else:
        raise ValueError("target_type debe ser 'code', 'url', 'archivo' o 'github_repo'")

    score = calculate_score(findings)
    stored_findings = [
        Finding(
            rule_id=finding.rule_id,
            title=finding.title,
            severity=finding.severity,
            description=finding.description,
            evidence=finding.evidence,
        )
        for finding in findings
    ]

    # detect frameworks from content when possible
    frameworks = set()
    try:
        if target_type in ("code", "archivo") and target_value:
            frameworks = detect_frameworks(target_value)
        elif target_type == "github_repo" and target_value:
            try:
                # Attempt to fetch single-file raw content or a small sample from the repo to detect frameworks
                from urllib.parse import urlparse
                parsed = urlparse(target_value)
                parts = parsed.path.strip('/').split('/')
                combined = ""
                if 'blob' in parts:
                    # raw file URL
                    try:
                        blob_idx = parts.index('blob')
                        branch = parts[blob_idx + 1]
                        file_path = '/'.join(parts[blob_idx + 2:])
                        raw_url = f"https://raw.githubusercontent.com/{parts[0]}/{parts[1]}/{branch}/{file_path}"
                        _req = __import__('requests')
                        headers = None
                        if effective_github_token:
                            headers = {"Authorization": f"token {effective_github_token}"}
                        r = _req.get(raw_url, headers=headers, timeout=8)
                        if r.status_code == 200:
                            combined = r.text
                    except Exception:
                        combined = ""
                else:
                    # try downloading repo zip (main/master) and combine a subset of files for detection
                    _req = __import__('requests')
                    import zipfile, io
                    owner = parts[0]
                    repo = parts[1].replace('.git', '')
                    zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/main.zip"
                    headers = None
                    if effective_github_token:
                        headers = {"Authorization": f"token {effective_github_token}"}
                    r = _req.get(zip_url, headers=headers, timeout=8)
                    if r.status_code == 404:
                        zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/master.zip"
                        r = _req.get(zip_url, headers=headers, timeout=8)
                    if r.status_code == 200:
                        try:
                            code_ext = {'.py', '.js', '.ts', '.jsx', '.tsx'}
                            with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
                                count = 0
                                for fi in zf.filelist:
                                    if any(fi.filename.endswith(ext) for ext in code_ext):
                                        try:
                                            txt = zf.read(fi).decode('utf-8', errors='replace')
                                            combined += '\n' + txt
                                            count += 1
                                            if count >= 10:
                                                break
                                        except Exception:
                                            continue
                        except Exception:
                            combined = ""
                if combined:
                    frameworks = detect_frameworks(combined)
            except Exception:
                frameworks = set()
    except Exception:
        frameworks = set()

    # attach penalty and remediation to stored findings (include framework-specific guidance)
    for sf in stored_findings:
        try:
            sf.penalty = penalty_for(sf)
            sf.remediation = remediation_for(sf.rule_id, frameworks)
        except Exception:
            sf.penalty = 0
            sf.remediation = ""

    scan = Scan(
        id=0,
        target_type=target_type,
        target_value=target_value,
        status="completed",
        score=score,
        findings=stored_findings,
        username=username,
    )
    created_scan = scan_store.create_scan(scan)

    # If requested and target was a GitHub repo, attempt to create issues
    if create_issues and target_type == "github_repo":
        try:
            # parse owner/repo
            parsed = urlparse(target_value)
            parts = parsed.path.strip('/').split('/')
            if len(parts) >= 2:
                owner = parts[0]
                repo = parts[1].replace('.git', '')

                # run issue creation in background to avoid blocking the request
                def _bg_create():
                    try:
                        created = create_issues_for_findings(owner, repo, stored_findings, github_token=effective_github_token)
                        # Persist a result log for visibility
                        try:
                            results_path = scan_store._data_path / 'issue_results.json'
                            entry = {
                                'scan_id': created_scan.id if 'created_scan' in locals() else None,
                                'owner': owner,
                                'repo': repo,
                                'created': len(created),
                                'issues': [i.get('html_url') for i in created if isinstance(i, dict) and i.get('html_url')],
                                'timestamp': datetime.now(timezone.utc).isoformat(),
                            }
                            # append to file
                            existing = []
                            if results_path.exists():
                                try:
                                    with results_path.open('r', encoding='utf-8') as fh:
                                        existing = json.load(fh)
                                except Exception:
                                    existing = []
                            existing.append(entry)
                            with results_path.open('w', encoding='utf-8') as fh:
                                json.dump(existing, fh, ensure_ascii=False, indent=2)
                        except Exception:
                            logger.exception("Failed to write issue_results.json")
                    except Exception:
                        logger.exception("Background issue creation failed for %s/%s", owner, repo)

                t = threading.Thread(target=_bg_create, daemon=True)
                t.start()
        except Exception:
            logger.exception("Failed to enqueue background issue creation")

    return created_scan


def calculate_dashboard_statistics(scans: list[Scan]) -> dict:
    """Calcula las estadísticas y matriz de riesgos de negocio para el panel de administración."""
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
    
    # Construir matriz de riesgo
    risk_matrix = {"high": [0, 0, 0, 0], "medium": [0, 0, 0, 0], "low": [0, 0, 0, 0]}
    for scan in scans:
        for finding in scan.findings:
            severity = finding.severity
            count = sum(1 for f in scan.findings if f.rule_id == finding.rule_id and f.severity == severity)
            if count > 10:
                idx = 0
            elif count > 5:
                idx = 1
            elif count > 2:
                idx = 2
            else:
                idx = 3
            if risk_matrix[severity][idx] < count:
                risk_matrix[severity][idx] = count
                
    return {
        "stats": stats,
        "risk_matrix": risk_matrix,
        "scans_data": [{"id": s.id, "score": s.score} for s in scans[-10:]]
    }




