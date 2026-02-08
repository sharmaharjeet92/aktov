"""Alert deduplication — suppress repeated alerts within a time window.

Phase 0: simple DB query, no Redis required.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aktov_cloud.models.alert import Alert

DEDUP_WINDOW = timedelta(hours=1)


async def is_duplicate(
    db: AsyncSession,
    org_id: uuid.UUID,
    agent_id: uuid.UUID,
    rule_id: uuid.UUID,
) -> bool:
    """Return True if an alert for (org, agent, rule) was created within the last hour."""
    cutoff = datetime.now(timezone.utc) - DEDUP_WINDOW

    result = await db.execute(
        select(Alert.id)
        .where(
            Alert.org_id == org_id,
            Alert.agent_id == agent_id,
            Alert.rule_id == rule_id,
            Alert.created_at >= cutoff,
        )
        .limit(1)
    )
    return result.scalar_one_or_none() is not None
