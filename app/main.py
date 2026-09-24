from collections import Counter
from typing import Any

from fastapi import FastAPI, HTTPException, Query

from app.models import Finding, Status
from app.normalizers import from_semgrep, from_trivy, from_zap
from app.store import initialize, list_findings, update_status, upsert_many


app = FastAPI(
    title="AppSec Vulnerability Manager",
    version="1.0.0",
    description="Normalize and prioritize defensive application security scanner findings.",
)


@app.on_event("startup")
def startup() -> None:
    initialize()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/ingest/{scanner}")
def ingest(scanner: str, payload: dict[str, Any]) -> dict[str, int]:
    parsers = {
        "semgrep": from_semgrep,
        "trivy": from_trivy,
        "zap": from_zap,
    }
    parser = parsers.get(scanner.lower())
    if not parser:
        raise HTTPException(status_code=400, detail="supported scanners: semgrep, trivy, zap")

    findings = parser(payload)
    created, updated = upsert_many(findings)
    return {"received": len(findings), "created": created, "updated": updated}


@app.get("/findings", response_model=list[Finding])
def findings(
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    source: str | None = Query(default=None),
) -> list[Finding]:
    return list_findings(severity=severity, status=status, source=source)


@app.patch("/findings/{fingerprint_value}/status")
def set_status(fingerprint_value: str, status: Status) -> dict[str, str]:
    if not update_status(fingerprint_value, status):
        raise HTTPException(status_code=404, detail="finding not found")
    return {"fingerprint": fingerprint_value, "status": status.value}


@app.get("/summary")
def summary() -> dict[str, object]:
    items = list_findings()
    severity_counts = Counter(item.severity.value for item in items)
    status_counts = Counter(item.status.value for item in items)
    source_counts = Counter(item.source for item in items)
    open_risk = sum(item.risk_score for item in items if item.status in {Status.OPEN, Status.IN_PROGRESS})

    return {
        "total": len(items),
        "severity": dict(severity_counts),
        "status": dict(status_counts),
        "source": dict(source_counts),
        "open_risk_points": round(open_risk, 1),
        "top_findings": [
            {
                "fingerprint": item.fingerprint,
                "title": item.title,
                "severity": item.severity.value,
                "risk_score": item.risk_score,
            }
            for item in sorted(items, key=lambda finding: finding.risk_score, reverse=True)[:5]
        ],
    }
