import json
import sqlite3
from pathlib import Path

from app.models import Finding, Status


DB_PATH = Path("vulnerabilities.db")


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize() -> None:
    with connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                fingerprint TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                status TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


def upsert_many(findings: list[Finding]) -> tuple[int, int]:
    created = 0
    updated = 0
    with connect() as conn:
        for finding in findings:
            existing = conn.execute(
                "SELECT fingerprint FROM findings WHERE fingerprint = ?",
                (finding.fingerprint,),
            ).fetchone()
            conn.execute(
                """
                INSERT INTO findings (fingerprint, payload, status)
                VALUES (?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    payload = excluded.payload,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (finding.fingerprint, finding.model_dump_json(), finding.status.value),
            )
            if existing:
                updated += 1
            else:
                created += 1
    return created, updated


def list_findings(severity: str | None = None, status: str | None = None, source: str | None = None) -> list[Finding]:
    with connect() as conn:
        rows = conn.execute("SELECT payload, status FROM findings ORDER BY updated_at DESC").fetchall()

    output = []
    for row in rows:
        data = json.loads(row["payload"])
        data["status"] = row["status"]
        finding = Finding.model_validate(data)
        if severity and finding.severity.value != severity.upper():
            continue
        if status and finding.status.value != status.upper():
            continue
        if source and finding.source.lower() != source.lower():
            continue
        output.append(finding)
    return output


def update_status(fingerprint_value: str, status: Status) -> bool:
    with connect() as conn:
        cursor = conn.execute(
            "UPDATE findings SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE fingerprint = ?",
            (status.value, fingerprint_value),
        )
        return cursor.rowcount > 0
