"""API key model — hashed keys for org authentication."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from chainwatch_cloud.models.base import Base

if TYPE_CHECKING:
    from chainwatch_cloud.models.organization import Organization


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    key_hash: Mapped[str] = mapped_column(String, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String, nullable=False, default="default")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
    )

    # Relationships
    organization: Mapped[Organization] = relationship("Organization", back_populates="api_keys")

    @staticmethod
    def generate_key() -> str:
        """Generate a new API key in the format ``cw_<hex>``."""
        return f"cw_{secrets.token_hex(24)}"

    @staticmethod
    def hash_key(raw_key: str, salt: str) -> str:
        """Produce a SHA-256 hash of the raw key with the given salt."""
        return hashlib.sha256(f"{salt}:{raw_key}".encode()).hexdigest()
