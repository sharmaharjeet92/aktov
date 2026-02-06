"""Bridge between cloud trace data and SDK YAML rule engine.

The SDK's RuleEngine is the single source of truth for all detection
logic. This module adapts cloud-side action dicts into TracePayload
objects the SDK engine can evaluate.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

from chainwatch.rules.engine import Alert as YAMLAlert, RuleEngine
from chainwatch.schema import Action, TracePayload

from chainwatch_cloud.config import settings

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _get_engine() -> RuleEngine:
    """Load the YAML rule engine once and cache it."""
    engine = RuleEngine()
    count = engine.load_rules(settings.rules_dir)
    logger.info("Loaded %d YAML rules from %s", count, settings.rules_dir)
    return engine


def evaluate_via_yaml(
    actions: list[dict[str, Any]],
    agent_type: str,
    agent_id: str,
    mode: str = "safe",
    declared_intent: str | None = None,
    session_id: str | None = None,
    task_id: str | None = None,
) -> list[YAMLAlert]:
    """Evaluate actions using the SDK YAML engine.

    Constructs a TracePayload from raw action dicts and evaluates
    all loaded YAML rules against it. The real mode is passed through
    faithfully — SAFE traces already have arguments=null from API
    validation, so the schema validator won't fire.
    """
    engine = _get_engine()

    payload = TracePayload(
        agent_id=agent_id,
        agent_type=agent_type,
        mode=mode,
        declared_intent=declared_intent,
        session_id=session_id,
        task_id=task_id,
        actions=[
            Action(**{k: v for k, v in a.items() if v is not None})
            for a in actions
        ],
    )

    return engine.evaluate(payload)
