import os
import time
import logging
requests = __import__('requests')

logger = logging.getLogger("github_integration")


def create_github_issue(owner: str, repo: str, title: str, body: str, github_token: str | None = None) -> dict | None:
    # Use provided token first, fallback to env var
    token = github_token or os.getenv("GITHUB_TOKEN")
    if not token:
        logger.debug("No GitHub token available for creating issue %s/%s", owner, repo)
        return None

    issue_url = f"https://api.github.com/repos/{owner}/{repo}/issues"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    payload = {"title": title, "body": body}

    # Retry loop with exponential backoff
    retries = 3
    backoff = 1.0
    for attempt in range(1, retries + 1):
        try:
            r = requests.post(issue_url, json=payload, headers=headers, timeout=10)
            if r.status_code in (200, 201):
                return r.json()
            # For rate-limit or server errors, log and retry
            if r.status_code >= 500 or r.status_code == 429:
                logger.warning("GitHub issue creation returned %s; retrying (attempt %s)", r.status_code, attempt)
                time.sleep(backoff)
                backoff *= 2
                continue
            # client error: invalid token/permissions or bad request
            logger.error("GitHub issue creation failed: %s %s", r.status_code, r.text)
            return None
        except requests.exceptions.RequestException as exc:
            logger.exception("Network error creating GitHub issue (attempt %s): %s", attempt, exc)
            time.sleep(backoff)
            backoff *= 2
            continue

    logger.error("Failed to create GitHub issue after %s attempts: %s/%s", retries, owner, repo)
    return None


def create_issues_for_findings(owner: str, repo: str, findings: list, github_token: str | None = None):
    """Crea un issue por cada finding. Devuelve la lista de issues creados."""
    # Use provided token first, fallback to env var
    token = github_token or os.getenv("GITHUB_TOKEN")
    if not token:
        logger.debug("No token available; skipping issue creation for %s/%s", owner, repo)
        return []

    created = []
    for f in findings:
        try:
            title = f"{f.rule_id}: {f.title}"
            body = f"**Descripción**: {f.description}\n\n**Evidencia**:\n{f.evidence}\n\n**Severidad**: {f.severity}\n"
            issue = create_github_issue(owner, repo, title, body, github_token=token)
            if issue:
                created.append(issue)
        except Exception:
            logger.exception("Unexpected error while creating issue for %s/%s", owner, repo)
            continue
    return created
