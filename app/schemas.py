from datetime import datetime

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    target_type: str = Field(pattern="^(code|url|archivo|github_repo)$")
    target_value: str
    create_issues: bool = False


class FindingOut(BaseModel):
    rule_id: str
    title: str
    severity: str
    description: str
    evidence: str

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: int
    target_type: str
    target_value: str
    status: str
    score: int
    created_at: datetime | None = None
    findings: list[FindingOut]

    model_config = {"from_attributes": True}
