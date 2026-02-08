"""Tests for the trace ingestion endpoint POST /v1/traces."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aktov_cloud.models.agent import Agent
from aktov_cloud.models.usage import UsageMeter


@pytest.mark.asyncio
async def test_ingest_trace_happy_path(
    client: AsyncClient,
    test_api_key: str,
    db_session: AsyncSession,
):
    """A valid SAFE-mode trace should be ingested and return 201."""
    payload = {
        "agent_id": "my-summarizer",
        "agent_type": "summarizer",
        "task_id": "task_001",
        "mode": "safe",
        "actions": [
            {
                "sequence_index": 0,
                "tool_name": "read_file",
                "tool_category": "read",
                "semantic_flags": {"sensitive_dir_match": False},
                "outcome": {"status": "success"},
            },
            {
                "sequence_index": 1,
                "tool_name": "generate_text",
                "tool_category": "execute",
                "semantic_flags": {},
                "outcome": {"status": "success"},
            },
        ],
        "metadata": {"framework": "langchain", "environment": "production"},
    }

    resp = await client.post(
        "/v1/traces",
        json=payload,
        headers={"Authorization": f"Bearer {test_api_key}"},
    )

    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert "trace_id" in body
    assert body["rules_evaluated"] > 0
    assert isinstance(body["alerts"], list)


@pytest.mark.asyncio
async def test_safe_mode_rejects_raw_arguments(
    client: AsyncClient,
    test_api_key: str,
):
    """SAFE mode traces with raw arguments should be rejected with 422."""
    payload = {
        "agent_id": "my-summarizer",
        "agent_type": "summarizer",
        "mode": "safe",
        "actions": [
            {
                "sequence_index": 0,
                "tool_name": "execute_sql",
                "tool_category": "read",
                "arguments": {"query": "SELECT * FROM users"},
                "outcome": {"status": "success"},
            },
        ],
    }

    resp = await client.post(
        "/v1/traces",
        json=payload,
        headers={"Authorization": f"Bearer {test_api_key}"},
    )

    assert resp.status_code == 422
    assert "SAFE mode violation" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_agent_auto_registration(
    client: AsyncClient,
    test_api_key: str,
    db_session: AsyncSession,
):
    """First trace from an unknown agent should auto-register it."""
    unique_agent = f"new-agent-{uuid.uuid4().hex[:8]}"
    payload = {
        "agent_id": unique_agent,
        "agent_type": "data_pipeline",
        "mode": "safe",
        "actions": [
            {
                "sequence_index": 0,
                "tool_name": "read_file",
                "tool_category": "read",
                "outcome": {"status": "success"},
            },
        ],
    }

    resp = await client.post(
        "/v1/traces",
        json=payload,
        headers={"Authorization": f"Bearer {test_api_key}"},
    )

    assert resp.status_code == 201

    # Verify agent was created in DB
    result = await db_session.execute(
        select(Agent).where(Agent.agent_id_external == unique_agent)
    )
    agent = result.scalar_one_or_none()
    assert agent is not None
    assert agent.agent_type == "data_pipeline"


@pytest.mark.asyncio
async def test_usage_metering_increment(
    client: AsyncClient,
    test_api_key: str,
    db_session: AsyncSession,
):
    """Ingesting a trace should increment the monthly usage meter."""
    payload = {
        "agent_id": "meter-test-agent",
        "agent_type": "summarizer",
        "mode": "safe",
        "actions": [
            {
                "sequence_index": 0,
                "tool_name": "read_file",
                "tool_category": "read",
                "outcome": {"status": "success"},
            },
        ],
    }

    # First trace
    resp = await client.post(
        "/v1/traces",
        json=payload,
        headers={"Authorization": f"Bearer {test_api_key}"},
    )
    assert resp.status_code == 201

    # Second trace
    resp2 = await client.post(
        "/v1/traces",
        json=payload,
        headers={"Authorization": f"Bearer {test_api_key}"},
    )
    assert resp2.status_code == 201

    # Check usage meter
    result = await db_session.execute(select(UsageMeter))
    usage = result.scalar_one_or_none()
    assert usage is not None
    assert usage.trace_count >= 2


@pytest.mark.asyncio
async def test_debug_mode_allows_arguments(
    client: AsyncClient,
    test_api_key: str,
):
    """DEBUG mode traces should allow raw arguments."""
    payload = {
        "agent_id": "debug-agent",
        "agent_type": "data_pipeline",
        "mode": "debug",
        "actions": [
            {
                "sequence_index": 0,
                "tool_name": "execute_sql",
                "tool_category": "read",
                "arguments": {"query": "SELECT * FROM users"},
                "outcome": {"status": "success"},
            },
        ],
    }

    resp = await client.post(
        "/v1/traces",
        json=payload,
        headers={"Authorization": f"Bearer {test_api_key}"},
    )

    assert resp.status_code == 201
