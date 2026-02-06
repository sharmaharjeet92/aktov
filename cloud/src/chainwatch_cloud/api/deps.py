"""Shared FastAPI dependencies — authentication, DB session."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from chainwatch_cloud.config import settings
from chainwatch_cloud.database import get_db
from chainwatch_cloud.models.api_key import ApiKey
from chainwatch_cloud.models.organization import Organization


async def get_current_org(
    authorization: str = Header(..., alias="Authorization"),
    db: AsyncSession = Depends(get_db),
) -> Organization:
    """Validate the ``Authorization: Bearer cw_...`` header and return the org.

    Raises 401 if the key is missing, malformed, or inactive.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header must start with 'Bearer '.",
        )

    raw_key = authorization.removeprefix("Bearer ").strip()
    if not raw_key.startswith("cw_"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key format. Keys must start with 'cw_'.",
        )

    key_hash = ApiKey.hash_key(raw_key, settings.api_key_salt)

    result = await db.execute(
        select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.is_active.is_(True))
    )
    api_key = result.scalar_one_or_none()

    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive API key.",
        )

    # Update last_used_at (fire-and-forget style, within same session)
    await db.execute(
        update(ApiKey)
        .where(ApiKey.id == api_key.id)
        .values(last_used_at=datetime.now(timezone.utc))
    )

    # Fetch the organization
    result = await db.execute(
        select(Organization).where(Organization.id == api_key.org_id)
    )
    org = result.scalar_one_or_none()

    if org is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Organization not found for this API key.",
        )

    return org
