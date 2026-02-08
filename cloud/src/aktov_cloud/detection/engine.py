"""Rule evaluation engine — delegates to SDK YAML engine.

All detection logic lives in the YAML rules under rules/phase0/.
The SDK's RuleEngine is the single source of truth.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from aktov_cloud.detection.dedup import is_duplicate
from aktov_cloud.detection.yaml_bridge import evaluate_via_yaml
from aktov_cloud.models.agent import Agent
from aktov_cloud.models.detection_rule import DetectionRule
from aktov_cloud.models.organization import Organization
from aktov_cloud.models.trace import Trace

logger = logging.getLogger(__name__)


async def evaluate_trace(
    *,
    db: AsyncSession,
    trace: Trace,
    agent: Agent,
    org: Organization,
    rules: list[DetectionRule],
    actions: list[Any],
) -> list[dict]:
    """Evaluate all applicable rules against a trace.

    Delegates to the SDK YAML engine, then maps results back to
    the cloud alert format with dedup checks.
    """
    action_dicts = [
        a.model_dump(mode="json") if hasattr(a, "model_dump") else a
        for a in actions
    ]

    # Build a lookup: rule_id_human -> DetectionRule DB model
    rule_lookup: dict[str, DetectionRule] = {
        r.rule_id_human: r for r in rules
    }

    # Run SDK YAML engine
    yaml_alerts = evaluate_via_yaml(
        actions=action_dicts,
        agent_type=agent.agent_type or "",
        agent_id=agent.agent_id_external,
        mode=getattr(trace, "mode", "safe"),
        declared_intent=getattr(trace, "declared_intent", None),
        session_id=getattr(trace, "session_id", None),
        task_id=getattr(trace, "task_id", None),
    )

    generated: list[dict] = []

    for alert in yaml_alerts:
        db_rule = rule_lookup.get(alert.rule_id)
        if db_rule is None:
            logger.warning(
                "YAML rule %s fired but no DB rule found (org=%s)",
                alert.rule_id,
                org.id,
            )
            continue

        # Dedup check
        dup = await is_duplicate(db, org.id, agent.id, db_rule.id)
        if dup:
            logger.debug(
                "Duplicate alert suppressed for rule %s agent %s",
                alert.rule_id,
                agent.agent_id_external,
            )
            continue

        generated.append({
            "rule_id": db_rule.id,
            "severity": alert.severity,
            "category": alert.category,
            "title": f"Rule '{alert.rule_name}' matched",
            "description": alert.message,
            "context": {
                "matched_actions": alert.matched_actions,
                "yaml_rule_id": alert.rule_id,
            },
        })

    return generated
