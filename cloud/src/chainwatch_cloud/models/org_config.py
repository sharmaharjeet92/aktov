"""Organization config model — per-org settings."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from chainwatch_cloud.models.base import Base


class OrgConfig(Base):
    __tablename__ = "org_configs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id"), unique=True, nullable=False
    )
    default_mode: Mapped[str] = mapped_column(String, nullable=False, default="safe")
    trace_retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_by: Mapped[str | None] = mapped_column(Text, nullable=True)
