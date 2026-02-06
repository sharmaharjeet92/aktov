"""Usage meter model — monthly trace and alert counts per org."""

from __future__ import annotations

import uuid
from datetime import date

from sqlalchemy import Date, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column

from chainwatch_cloud.models.base import Base


class UsageMeter(Base):
    __tablename__ = "usage_meters"

    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id"), primary_key=True
    )
    period_start: Mapped[date] = mapped_column(Date, primary_key=True)
    trace_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
