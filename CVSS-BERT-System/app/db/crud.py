from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.models import VulnerabilityLog


def create_log(
    db: Session,
    *,
    original_desc: str,
    translated_desc: str,
    cvss_vector: str,
    base_score: float,
    severity: str,
    source_ip: str,
) -> VulnerabilityLog:
    row = VulnerabilityLog(
        original_description=original_desc,
        translated_description=translated_desc,
        cvss_vector=cvss_vector,
        base_score=base_score,
        severity=severity,
        source_ip=source_ip,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_history(db: Session, *, limit: int = 10) -> list[dict]:
    stmt = select(VulnerabilityLog).order_by(desc(VulnerabilityLog.timestamp)).limit(limit)
    rows = db.execute(stmt).scalars().all()
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat(sep=" ", timespec="seconds"),
            "original_description": r.original_description,
            "translated_description": r.translated_description,
            "cvss_vector": r.cvss_vector,
            "base_score": r.base_score,
            "severity": r.severity,
            "source_ip": r.source_ip,
        }
        for r in rows
    ]

