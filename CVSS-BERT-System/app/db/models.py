from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class VulnerabilityLog(Base):
    __tablename__ = "vulnerability_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        nullable=False,
    )
    original_description: Mapped[str | None] = mapped_column(Text)
    translated_description: Mapped[str | None] = mapped_column(Text)
    cvss_vector: Mapped[str | None] = mapped_column(String(255))
    base_score: Mapped[float | None] = mapped_column(Float)
    severity: Mapped[str | None] = mapped_column(String(50))
    source_ip: Mapped[str | None] = mapped_column(String(50))

