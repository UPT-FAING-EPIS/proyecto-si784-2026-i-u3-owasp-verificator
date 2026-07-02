from datetime import datetime, timezone
from dataclasses import dataclass, field


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    description: str
    evidence: str
    penalty: int = 0
    remediation: str = ""


@dataclass
class Scan:
    id: int
    target_type: str
    target_value: str
    status: str
    score: int
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    findings: list[Finding] = field(default_factory=list)
    username: str | None = None
