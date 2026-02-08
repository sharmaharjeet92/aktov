"""Trace ingestion endpoint — POST /v1/traces."""

from __future__ import annotations

import asyncio
import uuid
from datetime import date, datetime, timezone
from typing import Any

import json as _json

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aktov_cloud.api.deps import get_current_org
from aktov_cloud.config import settings
from aktov_cloud.database import get_db
from aktov_cloud.detection.engine import evaluate_trace
from aktov_cloud.models.agent import Agent
from aktov_cloud.models.alert import Alert as AlertModel
from aktov_cloud.models.detection_rule import DetectionRule
from aktov_cloud.models.organization import Organization
from aktov_cloud.models.trace import Trace
from aktov_cloud.models.usage import UsageMeter
from aktov_cloud.webhooks.sender import deliver_alerts

router = APIRouter(prefix="/v1/traces", tags=["traces"])


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class SemanticFlagsIn(BaseModel):
    """Allowlisted semantic flag fields. Unknown fields are ignored."""

    model_config = ConfigDict(extra="ignore")

    sql_statement_type: str | None = None
    http_method: str | None = None
    is_external: bool | None = None
    sensitive_dir_match: bool | None = None
    has_network_calls: bool | None = None
    argument_size_bucket: str | None = None
    path_traversal_detected: bool | None = None


class ActionOutcomeIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: str
    error_class: str | None = None
    response_size_bucket: str | None = None


class ActionIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    sequence_index: int = 0
    tool_name: str = Field(max_length=256)
    tool_category: str = Field(max_length=64)
    semantic_flags: SemanticFlagsIn = Field(default_factory=SemanticFlagsIn)
    arguments: dict[str, Any] | None = None
    outcome: ActionOutcomeIn | None = None
    timestamp: datetime | None = None
    latency_ms: float | None = None


class TraceIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    agent_id: str = Field(max_length=256)
    agent_type: str = Field(max_length=128)
    task_id: str | None = Field(default=None, max_length=256)
    session_id: str | None = Field(default=None, max_length=256)
    declared_intent: str | None = Field(default=None, max_length=1024)
    mode: str = "safe"
    actions: list[ActionIn] = Field(default_factory=list)
    metadata: dict[str, Any] | None = None
    agent_fingerprint: str | None = Field(default=None, max_length=64)

    @field_validator("metadata")
    @classmethod
    def validate_metadata_size(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is not None:
            size = len(_json.dumps(v))
            if size > settings.max_metadata_bytes:
                raise ValueError(
                    f"metadata exceeds {settings.max_metadata_bytes}B limit ({size} bytes)"
                )
        return v


class AlertOut(BaseModel):
    alert_id: str
    rule_id: str
    severity: str
    category: str
    title: str


class TraceOut(BaseModel):
    trace_id: str
    rules_evaluated: int = 0
    alerts: list[AlertOut] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post("", response_model=TraceOut, status_code=status.HTTP_201_CREATED)
async def ingest_trace(
    payload: TraceIn,
    org: Organization = Depends(get_current_org),
    db: AsyncSession = Depends(get_db),
) -> TraceOut:
    # --- Validate action count limit ---
    if len(payload.actions) > settings.max_trace_actions:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Trace exceeds max action limit ({settings.max_trace_actions}).",
        )

    # --- SAFE mode validation: reject if any action has non-null arguments ---
    if payload.mode == "safe":
        for action in payload.actions:
            if action.arguments is not None:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=(
                        f"SAFE mode violation: action at index {action.sequence_index} "
                        f"({action.tool_name}) contains raw arguments. "
                        f"Strip arguments or switch to DEBUG mode."
                    ),
                )

    # --- Auto-register agent (upsert on org_id + agent_id_external) ---
    result = await db.execute(
        select(Agent).where(
            Agent.org_id == org.id,
            Agent.agent_id_external == payload.agent_id,
        )
    )
    agent = result.scalar_one_or_none()

    now = datetime.now(timezone.utc)
    framework = (payload.metadata or {}).get("framework")

    if agent is None:
        agent = Agent(
            org_id=org.id,
            agent_id_external=payload.agent_id,
            agent_type=payload.agent_type,
            declared_intent=payload.declared_intent,
            framework=framework,
            fingerprint=payload.agent_fingerprint,
            first_seen=now,
            last_seen=now,
        )
        db.add(agent)
        await db.flush()
    else:
        agent.last_seen = now
        if payload.agent_type:
            agent.agent_type = payload.agent_type
        if framework:
            agent.framework = framework
        if payload.agent_fingerprint:
            agent.fingerprint = payload.agent_fingerprint

    # --- Store trace ---
    actions_dicts = [a.model_dump(mode="json") for a in payload.actions]
    # Build denormalized semantic_flags summary
    semantic_flags_summary = [
        a.semantic_flags.model_dump(exclude_none=True) for a in payload.actions
    ]

    trace = Trace(
        org_id=org.id,
        agent_id=agent.id,
        task_id=payload.task_id,
        session_id=payload.session_id,
        declared_intent=payload.declared_intent,
        action_count=len(payload.actions),
        mode=payload.mode,
        actions=actions_dicts,
        semantic_flags=semantic_flags_summary,
        metadata_=payload.metadata,
        environment=(payload.metadata or {}).get("environment", "production"),
        ingested_at=now,
    )
    db.add(trace)
    await db.flush()

    # --- Run sync rule evaluation ---
    rules_result = await db.execute(
        select(DetectionRule).where(
            DetectionRule.enabled.is_(True),
            (DetectionRule.org_id == org.id) | (DetectionRule.is_system_rule.is_(True)),
        )
    )
    rules = list(rules_result.scalars().all())

    generated_alerts = await evaluate_trace(
        db=db,
        trace=trace,
        agent=agent,
        org=org,
        rules=rules,
        actions=payload.actions,
    )

    # Persist alerts
    alert_models: list[AlertModel] = []
    for alert_data in generated_alerts:
        alert_model = AlertModel(
            org_id=org.id,
            trace_id=trace.id,
            agent_id=agent.id,
            rule_id=alert_data["rule_id"],
            severity=alert_data["severity"],
            category=alert_data["category"],
            title=alert_data["title"],
            description=alert_data.get("description"),
            context=alert_data.get("context"),
            status="open",
            created_at=now,
        )
        db.add(alert_model)
        alert_models.append(alert_model)

    await db.flush()

    # --- Increment usage meter ---
    today = date.today().replace(day=1)  # first of month
    usage_result = await db.execute(
        select(UsageMeter).where(
            UsageMeter.org_id == org.id,
            UsageMeter.period_start == today,
        )
    )
    usage = usage_result.scalar_one_or_none()
    if usage is None:
        usage = UsageMeter(org_id=org.id, period_start=today, trace_count=1, alert_count=len(alert_models))
        db.add(usage)
    else:
        usage.trace_count += 1
        usage.alert_count += len(alert_models)

    # --- Fire-and-forget webhook delivery ---
    if alert_models:
        asyncio.create_task(deliver_alerts(alert_models, org.id, db))

    # --- Build response ---
    alert_outputs = [
        AlertOut(
            alert_id=str(am.id),
            rule_id=str(am.rule_id),
            severity=am.severity,
            category=am.category,
            title=am.title,
        )
        for am in alert_models
    ]

    return TraceOut(
        trace_id=str(trace.id),
        rules_evaluated=len(rules),
        alerts=alert_outputs,
    )
