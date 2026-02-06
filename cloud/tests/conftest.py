"""Shared test fixtures for ChainWatch Cloud tests.

Uses SQLite + aiosqlite for a fast, self-contained test database.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Point the YAML engine to the actual rule files during tests
_RULES_DIR = str(Path(__file__).resolve().parents[2] / "rules" / "phase0")
os.environ["CW_RULES_DIR"] = _RULES_DIR

from chainwatch_cloud.config import settings
from chainwatch_cloud.models.agent import Agent
from chainwatch_cloud.models.api_key import ApiKey
from chainwatch_cloud.models.base import Base
from chainwatch_cloud.models.detection_rule import DetectionRule
from chainwatch_cloud.models.organization import Organization

# Import all models so Base.metadata has them
import chainwatch_cloud.models  # noqa: F401


# ---------------------------------------------------------------------------
# Test database engine (SQLite in-memory via aiosqlite)
# ---------------------------------------------------------------------------

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestSessionLocal = async_sessionmaker(
    test_engine, class_=AsyncSession, expire_on_commit=False
)


@pytest_asyncio.fixture
async def db_session():
    """Create tables and yield a fresh async session for each test."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestSessionLocal() as session:
        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


# ---------------------------------------------------------------------------
# Override FastAPI dependencies for tests
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def test_org(db_session: AsyncSession) -> Organization:
    """Create and return a test organization."""
    org = Organization(
        id=uuid.uuid4(),
        name="Test Org",
        slug="test-org",
        plan="free",
        trace_limit_monthly=10_000,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(org)
    await db_session.flush()
    return org


@pytest_asyncio.fixture
async def test_api_key(db_session: AsyncSession, test_org: Organization) -> str:
    """Create a test API key and return the raw key string."""
    raw_key = "cw_test_key_abc123"
    key_hash = ApiKey.hash_key(raw_key, settings.api_key_salt)
    api_key = ApiKey(
        id=uuid.uuid4(),
        org_id=test_org.id,
        key_hash=key_hash,
        name="test-key",
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(api_key)
    await db_session.flush()
    return raw_key


@pytest_asyncio.fixture
async def test_agent(db_session: AsyncSession, test_org: Organization) -> Agent:
    """Create and return a test agent."""
    agent = Agent(
        id=uuid.uuid4(),
        org_id=test_org.id,
        agent_id_external="test-summarizer",
        agent_type="summarizer",
        framework="langchain",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    db_session.add(agent)
    await db_session.flush()
    return agent


@pytest_asyncio.fixture
async def test_rules(db_session: AsyncSession) -> list[DetectionRule]:
    """Seed the Phase 0 system rules and return them."""
    # Severity/category must match YAML rules exactly (source of truth)
    rule_defs = [
        ("CW-001", "Read-only agent write operation", "high", "capability_escalation"),
        ("CW-007", "Credential tool from non-credential agent", "critical", "capability_escalation"),
        ("CW-010", "Sequential read -> network egress", "critical", "data_exfiltration"),
        ("CW-012", "Large payload to external network", "high", "data_exfiltration"),
        ("CW-020", "Extreme chain length", "medium", "chain_anomaly"),
        ("CW-022", "Burst of failed tool calls", "medium", "chain_anomaly"),
        ("CW-023", "Write/execute/network with no preceding read", "medium", "chain_anomaly"),
        ("CW-030", "SQL DDL from non-DB agent", "critical", "argument_anomaly"),
        ("CW-031", "Sensitive directory access", "high", "argument_anomaly"),
        ("CW-032", "Path traversal detected", "critical", "argument_anomaly"),
        ("CW-041", "Repeated network failures", "medium", "temporal_anomaly"),
        ("CW-050", "Multiple external domains", "high", "data_exfiltration"),
    ]
    rules = []
    for rule_id, name, severity, category in rule_defs:
        rule = DetectionRule(
            id=uuid.uuid4(),
            org_id=None,
            rule_id_human=rule_id,
            name=name,
            description=name,
            severity=severity,
            category=category,
            rule_type="yaml",
            rule_content="---",  # placeholder
            enabled=True,
            is_system_rule=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db_session.add(rule)
        rules.append(rule)
    await db_session.flush()
    return rules


@pytest_asyncio.fixture
async def client(
    db_session: AsyncSession,
    test_org: Organization,
    test_api_key: str,
    test_rules: list[DetectionRule],
) -> AsyncClient:
    """Create an httpx AsyncClient wired to the FastAPI app with test DB overrides."""
    from chainwatch_cloud.database import get_db
    from chainwatch_cloud.main import app

    async def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac

    app.dependency_overrides.clear()
