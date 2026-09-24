import hashlib
from typing import Any

from app.models import Finding, Severity


SEVERITY_ORDER = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "MODERATE": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
    "INFORMATIONAL": Severity.INFO,
}


def normalize_severity(value: str | None) -> Severity:
    return SEVERITY_ORDER.get((value or "INFO").upper(), Severity.INFO)


def fingerprint(source: str, title: str, location: str, identity: str = "") -> str:
    raw = "|".join([source.lower(), title.strip().lower(), location.strip().lower(), identity.lower()])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def risk_score(severity: Severity, cvss: float | None, internet_exposed: bool = False, known_exploitable: bool = False) -> float:
    base = {
        Severity.CRITICAL: 85,
        Severity.HIGH: 70,
        Severity.MEDIUM: 50,
        Severity.LOW: 25,
        Severity.INFO: 5,
    }[severity]

    if cvss is not None:
        base = max(base, cvss * 10)
    if internet_exposed:
        base += 8
    if known_exploitable:
        base += 12
    return round(min(base, 100), 1)


def from_semgrep(payload: dict[str, Any]) -> list[Finding]:
    findings = []
    for item in payload.get("results", []):
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})
        severity = normalize_severity(extra.get("severity"))
        location = f"{item.get('path', '')}:{item.get('start', {}).get('line', '')}"
        cwe_value = metadata.get("cwe")
        if isinstance(cwe_value, list):
            cwe_value = ", ".join(str(v) for v in cwe_value)

        title = item.get("check_id", "Semgrep finding")
        findings.append(
            Finding(
                fingerprint=fingerprint("semgrep", title, location),
                title=title,
                description=extra.get("message", ""),
                severity=severity,
                source="Semgrep",
                cwe=cwe_value,
                location=location,
                remediation=metadata.get("fix", ""),
                risk_score=risk_score(severity, None),
            )
        )
    return findings


def from_trivy(payload: dict[str, Any]) -> list[Finding]:
    findings = []
    for result in payload.get("Results", []):
        target = result.get("Target", "")
        for item in result.get("Vulnerabilities") or []:
            severity = normalize_severity(item.get("Severity"))
            cvss_map = item.get("CVSS") or {}
            cvss = None
            for score_data in cvss_map.values():
                if isinstance(score_data, dict) and score_data.get("V3Score") is not None:
                    cvss = float(score_data["V3Score"])
                    break
            vuln_id = item.get("VulnerabilityID")
            package = item.get("PkgName", "unknown-package")
            title = f"{vuln_id or 'Vulnerability'} in {package}"
            location = f"{target}:{package}"
            findings.append(
                Finding(
                    fingerprint=fingerprint("trivy", title, location, vuln_id or ""),
                    title=title,
                    description=item.get("Title") or item.get("Description") or "",
                    severity=severity,
                    source="Trivy",
                    cve=vuln_id if str(vuln_id).startswith("CVE-") else None,
                    cvss=cvss,
                    location=location,
                    remediation=f"Upgrade to {item.get('FixedVersion')}" if item.get("FixedVersion") else "Review vendor advisory",
                    risk_score=risk_score(severity, cvss),
                )
            )
    return findings


def from_zap(payload: dict[str, Any]) -> list[Finding]:
    findings = []
    for site in payload.get("site", []):
        site_name = site.get("@name", "")
        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc", "Informational").split(" ")[0]
            severity = normalize_severity(risk)
            cwe = str(alert.get("cweid")) if alert.get("cweid") not in (None, "-1", -1) else None
            for instance in alert.get("instances") or [{}]:
                location = instance.get("uri") or site_name
                title = alert.get("name", "ZAP finding")
                findings.append(
                    Finding(
                        fingerprint=fingerprint("zap", title, location),
                        title=title,
                        description=alert.get("desc", ""),
                        severity=severity,
                        source="OWASP ZAP",
                        cwe=f"CWE-{cwe}" if cwe else None,
                        location=location,
                        internet_exposed=True,
                        remediation=alert.get("solution", ""),
                        risk_score=risk_score(severity, None, internet_exposed=True),
                    )
                )
    return findings
