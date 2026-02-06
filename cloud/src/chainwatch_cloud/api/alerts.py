"""Alert endpoints — list, get, update status."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from chainwatch_cloud.api.deps import get_current_org
from chainwatch_cloud.database import get_db
from chainwatch_cloud.models.alert import Alert
from chainwatch_cloud.models.organization import Organization

router = APIRouter(prefix="/v1/alerts", tags=["alerts"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class AlertDetail(BaseModel):
    id: str
    org_id: str
    trace_id: str
    agent_id: str
    rule_id: str
    severity: str
    category: str
    title: str
    description: str | None = None
    context: dict[str, Any] | None = None
    status: str
    resolved_at: datetime | None = None
    created_at: datetime

    @classmethod
    def from_model(cls, alert: Alert) -> AlertDetail:
        return cls(
            id=str(alert.id),
            org_id=str(alert.org_id),
            trace_id=str(alert.trace_id),
            agent_id=str(alert.agent_id),
            rule_id=str(alert.rule_id),
            severity=alert.severity,
            category=alert.category,
            title=alert.title,
            description=alert.description,
            context=alert.context,
            status=alert.status,
            resolved_at=alert.resolved_at,
            created_at=alert.created_at,
        )


class AlertStatusUpdate(BaseModel):
    status: str  # "acknowledged", "resolved", "false_positive"


class AlertListResponse(BaseModel):
    alerts: list[AlertDetail]
    total: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

VALID_STATUSES = {"open", "acknowledged", "resolved", "false_positive"}


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    org: Organization = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
    alert_status: str | None = Query(None, alias="status"),
    severity: str | None = Query(None),
    agent_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> AlertListResponse:
    query = select(Alert).where(Alert.org_id == org.id)

    if alert_status:
        statuses = [s.strip() for s in alert_status.split(",")]
        query = query.where(Alert.status.in_(statuses))
    if severity:
        severities = [s.strip() for s in severity.split(",")]
        query = query.where(Alert.severity.in_(severities))
    if agent_id:
        query = query.where(Alert.agent_id == uuid.UUID(agent_id))

    # Count total before limit/offset
    from sqlalchemy import func

    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    query = query.order_by(Alert.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    alerts = result.scalars().all()

    return AlertListResponse(
        alerts=[AlertDetail.from_model(a) for a in alerts],
        total=total,
    )


@router.get("/{alert_id}", response_model=AlertDetail)
async def get_alert(
    alert_id: uuid.UUID,
    org: Organization = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> AlertDetail:
    result = await db.execute(
        select(Alert).where(Alert.id == alert_id, Alert.org_id == org.id)
    )
    alert = result.scalar_one_or_none()

    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found.")

    return AlertDetail.from_model(alert)


@router.patch("/{alert_id}", response_model=AlertDetail)
async def update_alert_status(
    alert_id: uuid.UUID,
    body: AlertStatusUpdate,
    org: Organization = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> AlertDetail:
    if body.status not in VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid status. Must be one of: {', '.join(sorted(VALID_STATUSES))}",
        )

    result = await db.execute(
        select(Alert).where(Alert.id == alert_id, Alert.org_id == org.id)
    )
    alert = result.scalar_one_or_none()

    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found.")

    alert.status = body.status
    if body.status == "resolved":
        alert.resolved_at = datetime.now(timezone.utc)

    return AlertDetail.from_model(alert)
