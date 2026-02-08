"""Organization model — multi-tenant root entity."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aktov_cloud.models.base import Base

if TYPE_CHECKING:
    from aktov_cloud.models.agent import Agent
    from aktov_cloud.models.api_key import ApiKey


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String, nullable=False)
    slug: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    plan: Mapped[str] = mapped_column(String, nullable=False, default="free")
    trace_limit_monthly: Mapped[int] = mapped_column(Integer, nullable=False, default=10_000)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    agents: Mapped[list[Agent]] = relationship("Agent", back_populates="organization", lazy="selectin")
    api_keys: Mapped[list[ApiKey]] = relationship("ApiKey", back_populates="organization", lazy="selectin")
