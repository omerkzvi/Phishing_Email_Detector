from pydantic import BaseModel, Field, ConfigDict, field_validator
from typing import Optional, List, Dict, Any
from enums import Classification, Severity, MLStatus


class EmailRequest(BaseModel):
    sender: str = Field(..., description="The email sender address")
    subject: str = Field(default="", description="The email subject")
    body: str = Field(default="", description="Plain text body (preferred)")
    body_html: Optional[str] = Field(default=None, description="Optional HTML body")
    headers: Optional[Dict[str, Any]] = Field(default=None, description="Optional headers dict from Gmail API")

    @field_validator("sender")
    @classmethod
    def sender_must_not_be_blank(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("sender must not be empty")
        return v

    @field_validator("subject", "body")
    @classmethod
    def normalize_text(cls, v: str) -> str:
        return (v or "").strip()

    @field_validator("subject")
    @classmethod
    def subject_len_limit(cls, v: str) -> str:
        if len(v) > 500:
            return v[:500]
        return v

    @field_validator("body")
    @classmethod
    def body_len_limit(cls, v: str) -> str:
        # keep it sane for API usage; still enough for detection
        if len(v) > 20000:
            return v[:20000]
        return v

    model_config = ConfigDict(extra="ignore")


class MlResult(BaseModel):
    ml_score: Optional[int] = None
    confidence: float = 0.0
    status: MLStatus

    model_config = ConfigDict(use_enum_values=True)


class ScanMetadata(BaseModel):
    sender_domain: str
    links_found: int
    heuristic_score: int
    ml_status: MLStatus
    ml_score: Optional[int]
    ml_confidence: float
    overall_confidence: float
    decision_confidence: float
    evidence_confidence: float

    model_config = ConfigDict(use_enum_values=True)


class ScanResult(BaseModel):
    score: int
    classification: Classification
    severity: Severity
    reasons: List[str]
    metadata: ScanMetadata

    model_config = ConfigDict(use_enum_values=True)
