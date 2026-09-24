from app.models import Severity
from app.normalizers import from_semgrep, from_trivy, from_zap, normalize_severity, risk_score


def test_severity_normalization():
    assert normalize_severity("critical") == Severity.CRITICAL
    assert normalize_severity("moderate") == Severity.MEDIUM
    assert normalize_severity("unknown") == Severity.INFO


def test_risk_score_increases_for_exposure():
    internal = risk_score(Severity.HIGH, 7.5)
    exposed = risk_score(Severity.HIGH, 7.5, internet_exposed=True)
    assert exposed > internal


def test_semgrep_normalization():
    payload = {
        "results": [
            {
                "check_id": "python.lang.security.audit.eval-detected",
                "path": "app/demo.py",
                "start": {"line": 10},
                "extra": {
                    "severity": "ERROR",
                    "message": "Dynamic execution should be reviewed",
                    "metadata": {"cwe": ["CWE-95"]},
                },
            }
        ]
    }
    finding = from_semgrep(payload)[0]
    assert finding.source == "Semgrep"
    assert finding.location == "app/demo.py:10"


def test_trivy_normalization():
    payload = {
        "Results": [
            {
                "Target": "package-lock.json",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2099-0001",
                        "PkgName": "demo-package",
                        "Severity": "HIGH",
                        "FixedVersion": "2.0.0",
                    }
                ],
            }
        ]
    }
    finding = from_trivy(payload)[0]
    assert finding.cve == "CVE-2099-0001"
    assert finding.severity == Severity.HIGH


def test_zap_normalization_marks_web_exposure():
    payload = {
        "site": [
            {
                "@name": "http://localhost",
                "alerts": [
                    {
                        "name": "Missing Header",
                        "riskdesc": "Low (Medium)",
                        "cweid": "693",
                        "instances": [{"uri": "http://localhost/"}],
                    }
                ],
            }
        ]
    }
    finding = from_zap(payload)[0]
    assert finding.internet_exposed is True
    assert finding.cwe == "CWE-693"
