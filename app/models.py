from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    ACCEPTED = "ACCEPTED"
    REMEDIATED = "REMEDIATED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Finding(BaseModel):
    fingerprint: str
    title: str
    description: str = ""
    severity: Severity
    source: str
    cve: Optional[str] = None
    cwe: Optional[str] = None
    cvss: Optional[float] = Field(default=None, ge=0, le=10)
    application: str = "demo-application"
    location: str = ""
    owner: str = "unassigned"
    status: Status = Status.OPEN
    internet_exposed: bool = False
    known_exploitable: bool = False
    remediation: str = ""
    risk_score: float = Field(ge=0, le=100)
