"""Seed development database with org, API key, and system rules.

Usage:
    make seed
    # or: uv run python cloud/src/aktov_cloud/scripts/seed_dev.py
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path

# Ensure cloud package is importable
_cloud_src = Path(__file__).resolve().parents[2]
if str(_cloud_src) not in sys.path:
    sys.path.insert(0, str(_cloud_src))

import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aktov_cloud.config import settings
from aktov_cloud.database import async_session_factory
from aktov_cloud.models.api_key import ApiKey
from aktov_cloud.models.detection_rule import DetectionRule
from aktov_cloud.models.organization import Organization

# Fixed dev API key — known to labs and tests
DEV_API_KEY = "ak_dev_test_key_abc123"
DEV_ORG_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")


async def seed() -> None:
    async with async_session_factory() as db:
        await _seed_org(db)
        await _seed_api_key(db)
        await _seed_rules(db)
        await db.commit()
    print("\nSeed complete.")


async def _seed_org(db: AsyncSession) -> None:
    result = await db.execute(
        select(Organization).where(Organization.id == DEV_ORG_ID)
    )
    if result.scalar_one_or_none():
        print(f"  org   {DEV_ORG_ID} already exists, skipping")
        return

    org = Organization(
        id=DEV_ORG_ID,
        name="Aktov Dev",
        slug="aktov-dev",
        plan="free",
    )
    db.add(org)
    await db.flush()
    print(f"  org   {DEV_ORG_ID} created (Aktov Dev)")


async def _seed_api_key(db: AsyncSession) -> None:
    key_hash = ApiKey.hash_key(DEV_API_KEY, settings.api_key_salt)

    result = await db.execute(
        select(ApiKey).where(ApiKey.key_hash == key_hash)
    )
    if result.scalar_one_or_none():
        print(f"  key   {DEV_API_KEY[:16]}... already exists, skipping")
        return

    api_key = ApiKey(
        org_id=DEV_ORG_ID,
        key_hash=key_hash,
        name="dev-seed",
        is_active=True,
    )
    db.add(api_key)
    await db.flush()
    print(f"  key   {DEV_API_KEY[:16]}... created")


async def _seed_rules(db: AsyncSession) -> None:
    rules_dir = Path(settings.rules_dir)
    if not rules_dir.is_dir():
        print(f"  rules  SKIP — {rules_dir} not found")
        return

    yaml_files = sorted(rules_dir.glob("*.yaml")) + sorted(rules_dir.glob("*.yml"))
    seeded = 0

    for filepath in yaml_files:
        with open(filepath) as f:
            doc = yaml.safe_load(f)

        rule_id_human = doc["rule_id"]

        # Check if rule already exists (system rules have org_id=None)
        result = await db.execute(
            select(DetectionRule).where(
                DetectionRule.rule_id_human == rule_id_human,
                DetectionRule.is_system_rule.is_(True),
            )
        )
        if result.scalar_one_or_none():
            print(f"  rule  {rule_id_human} already exists, skipping")
            continue

        rule = DetectionRule(
            org_id=None,
            rule_id_human=rule_id_human,
            name=doc["name"],
            description=doc.get("description", ""),
            severity=doc["severity"],
            category=doc["category"],
            rule_type="yaml",
            rule_content=filepath.read_text(),
            enabled=True,
            is_system_rule=True,
        )
        db.add(rule)
        seeded += 1
        print(f"  rule  {rule_id_human} — {doc['name']}")

    await db.flush()
    print(f"  {seeded} rules seeded from {rules_dir}")


if __name__ == "__main__":
    print("Seeding Aktov dev database...")
    print(f"  DB: {settings.database_url.split('@')[-1] if '@' in settings.database_url else 'configured'}")
    asyncio.run(seed())
