"""Rules endpoints — list detection rules."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aktov_cloud.api.deps import get_current_org
from aktov_cloud.database import get_db
from aktov_cloud.models.detection_rule import DetectionRule
from aktov_cloud.models.organization import Organization

router = APIRouter(prefix="/v1/rules", tags=["rules"])


class RuleDetail(BaseModel):
    id: str
    rule_id_human: str
    name: str
    description: str | None = None
    severity: str
    category: str
    rule_type: str
    enabled: bool
    is_system_rule: bool
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_model(cls, rule: DetectionRule) -> RuleDetail:
        return cls(
            id=str(rule.id),
            rule_id_human=rule.rule_id_human,
            name=rule.name,
            description=rule.description,
            severity=rule.severity,
            category=rule.category,
            rule_type=rule.rule_type,
            enabled=rule.enabled,
            is_system_rule=rule.is_system_rule,
            created_at=rule.created_at,
            updated_at=rule.updated_at,
        )


class RuleListResponse(BaseModel):
    rules: list[RuleDetail]


@router.get("", response_model=RuleListResponse)
async def list_rules(
    org: Organization = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> RuleListResponse:
    """Return all enabled rules visible to this org (system rules + org-specific)."""
    result = await db.execute(
        select(DetectionRule)
        .where(
            DetectionRule.enabled.is_(True),
            (DetectionRule.org_id == org.id) | (DetectionRule.is_system_rule.is_(True)),
        )
        .order_by(DetectionRule.rule_id_human)
    )
    rules = result.scalars().all()
    return RuleListResponse(rules=[RuleDetail.from_model(r) for r in rules])
