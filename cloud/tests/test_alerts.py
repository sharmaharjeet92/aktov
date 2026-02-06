"""Tests for alert endpoints — GET /v1/alerts, PATCH /v1/alerts/{id}."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from chainwatch_cloud.models.agent import Agent
from chainwatch_cloud.models.alert import Alert
from chainwatch_cloud.models.detection_rule import DetectionRule
from chainwatch_cloud.models.organization import Organization


@pytest.mark.asyncio
async def test_list_alerts_empty(
    client: AsyncClient,
    test_api_key: str,
):
    """Listing alerts when none exist should return an empty list."""
    resp = await client.get(
        "/v1/alerts",
        headers={"Authorization": f"Bearer {test_api_key}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["alerts"] == []
    assert body["total"] == 0


@pytest.mark.asyncio
async def test_list_alerts_with_filters(
    client: AsyncClient,
    test_api_key: str,
    db_session: AsyncSession,
    test_org: Organization,
    test_agent: Agent,
    test_rules: list[DetectionRule],
):
    """Alerts can be filtered by status and severity."""
    rule = test_rules[0]
    now = datetime.now(timezone.utc)

    # Create two alerts: one open/high, one resolved/medium
    alert_open = Alert(
        id=uuid.uuid4(),
        org_id=test_org.id,
        trace_id=uuid.uuid4(),
        agent_id=test_agent.id,
        rule_id=rule.id,
        severity="high",
        category="capability_escalation",
        title="Open alert",
        status="open",
        created_at=now,
    )
    alert_resolved = Alert(
        id=uuid.uuid4(),
        org_id=test_org.id,
        trace_id=uuid.uuid4(),
        agent_id=test_agent.id,
        rule_id=rule.id,
        severity="medium",
        category="chain_anomaly",
        title="Resolved alert",
        status="resolved",
        resolved_at=now,
        created_at=now,
    )
    db_session.add_all([alert_open, alert_resolved])
    await db_session.flush()

    # Filter: status=open
    resp = await client.get(
        "/v1/alerts?status=open",
        headers={"Authorization": f"Bearer {test_api_key}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["alerts"][0]["status"] == "open"

    # Filter: severity=medium
    resp2 = await client.get(
        "/v1/alerts?severity=medium",
        headers={"Authorization": f"Bearer {test_api_key}"},
    )
    assert resp2.status_code == 200
    body2 = resp2.json()
    assert body2["total"] == 1
    assert body2["alerts"][0]["severity"] == "medium"


@pytest.mark.asyncio
async def test_get_single_alert(
    client: AsyncClient,
    test_api_key: str,
    db_session: AsyncSession,
    test_org: Organization,
    test_agent: Agent,
    test_rules: list[DetectionRule],
):
    """GET /v1/alerts/{id} returns a single alert."""
    rule = test_rules[0]
    alert_id = uuid.uuid4()
    alert = Alert(
        id=alert_id,
        org_id=test_org.id,
        trace_id=uuid.uuid4(),
        agent_id=test_agent.id,
        rule_id=rule.id,
        severity="critical",
        category="argument_anomaly",
        title="Test single alert",
        status="open",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(alert)
    await db_session.flush()

    resp = await client.get(
        f"/v1/alerts/{alert_id}",
        headers={"Authorization": f"Bearer {test_api_key}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == str(alert_id)
    assert body["title"] == "Test single alert"


@pytest.mark.asyncio
async def test_alert_not_found(
    client: AsyncClient,
    test_api_key: str,
):
    """GET /v1/alerts/{id} with non-existent ID returns 404."""
    resp = await client.get(
        f"/v1/alerts/{uuid.uuid4()}",
        headers={"Authorization": f"Bearer {test_api_key}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_update_alert_status(
    client: AsyncClient,
    test_api_key: str,
    db_session: AsyncSession,
    test_org: Organization,
    test_agent: Agent,
    test_rules: list[DetectionRule],
):
    """PATCH /v1/alerts/{id} updates the alert status."""
    rule = test_rules[0]
    alert_id = uuid.uuid4()
    alert = Alert(
        id=alert_id,
        org_id=test_org.id,
        trace_id=uuid.uuid4(),
        agent_id=test_agent.id,
        rule_id=rule.id,
        severity="high",
        category="capability_escalation",
        title="Alert to resolve",
        status="open",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(alert)
    await db_session.flush()

    # Acknowledge
    resp = await client.patch(
        f"/v1/alerts/{alert_id}",
        json={"status": "acknowledged"},
        headers={"Authorization": f"Bearer {test_api_key}"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "acknowledged"

    # Resolve
    resp2 = await client.patch(
        f"/v1/alerts/{alert_id}",
        json={"status": "resolved"},
        headers={"Authorization": f"Bearer {test_api_key}"},
    )
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "resolved"
    assert resp2.json()["resolved_at"] is not None


@pytest.mark.asyncio
async def test_update_alert_invalid_status(
    client: AsyncClient,
    test_api_key: str,
    db_session: AsyncSession,
    test_org: Organization,
    test_agent: Agent,
    test_rules: list[DetectionRule],
):
    """PATCH /v1/alerts/{id} with invalid status returns 422."""
    rule = test_rules[0]
    alert_id = uuid.uuid4()
    alert = Alert(
        id=alert_id,
        org_id=test_org.id,
        trace_id=uuid.uuid4(),
        agent_id=test_agent.id,
        rule_id=rule.id,
        severity="high",
        category="capability_escalation",
        title="Alert for invalid status test",
        status="open",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(alert)
    await db_session.flush()

    resp = await client.patch(
        f"/v1/alerts/{alert_id}",
        json={"status": "banana"},
        headers={"Authorization": f"Bearer {test_api_key}"},
    )
    assert resp.status_code == 422
