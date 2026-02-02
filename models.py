from pydantic import BaseModel, Field, ConfigDict, field_validator
from typing import Optional, List, Dict, Any
from enums import Classification, Severity, MLStatus


class EmailRequest(BaseModel):
    # request payload for scanning an email

    sender: str = Field(..., description="The email sender address")
    subject: str = Field(default="", description="The email subject")
    body: str = Field(default="", description="Plain text body (preferred)")
    body_html: Optional[str] = Field(default=None, description="Optional HTML body")
    headers: Optional[Dict[str, Any]] = Field(default=None, description="Optional headers dict from Gmail API")

    @field_validator("sender")
    @classmethod
    def sender_must_not_be_blank(cls, value: str) -> str:
        value = (value or "").strip()
        if not value:
            raise ValueError("sender must not be empty")
        return value

    @field_validator("subject", "body")
    @classmethod
    def normalize_text(cls, v: str) -> str:
        return (v or "").strip()

    @field_validator("subject")
    @classmethod
    def subject_len_limit(cls, value: str) -> str:
        if len(value) > 500:
            return value[:500]
        return value

    @field_validator("body")
    @classmethod
    def body_len_limit(cls, value: str) -> str:
        # keep payloads reasonable, still enough for detection
        if len(value) > 20000:
            return value[:20000]
        return value

    model_config = ConfigDict(extra="ignore")


class MlResult(BaseModel):
    ml_score: Optional[int] = None
    confidence: float = 0.0
    status: MLStatus

    model_config = ConfigDict(use_enum_values=True)


class ScanMetadata(BaseModel):
    # debug metadat returned with the scan result

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
    # final API response for the gmail add on
    score: int
    classification: Classification
    severity: Severity
    reasons: List[str]
    metadata: ScanMetadata

    model_config = ConfigDict(use_enum_values=True)
