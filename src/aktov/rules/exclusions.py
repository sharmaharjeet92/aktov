"""Post-evaluation exclusion filter for rule alerts.

Loads YAML exclusion configs and filters alerts after rule evaluation.
Both active alerts and suppressed alerts are returned for transparency.
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from typing import Any

import yaml

from aktov.rules.engine import Alert

logger = logging.getLogger("aktov")

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class ExclusionEntry:
    """A single exclusion rule — expanded from rule_ids during load."""

    rule_id: str
    reason: str
    agent_id: str | None = None
    tool_names: list[str] | None = None


@dataclass
class ExclusionConfig:
    """Top-level exclusion configuration loaded from YAML."""

    severity_floor: str | None = None
    exclusions: list[ExclusionEntry] = field(default_factory=list)


@dataclass
class SuppressedAlert:
    """An alert that was suppressed by an exclusion rule."""

    rule_id: str
    rule_name: str
    severity: str
    reason: str


def load_exclusions(filepath: str) -> ExclusionConfig:
    """Load exclusion config from a YAML file.

    Returns an empty config if the file is missing or empty.
    """
    try:
        with open(filepath, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        logger.warning("Exclusion file not found: %s", filepath)
        return ExclusionConfig()
    except Exception as exc:
        logger.warning("Failed to load exclusion file %s: %s", filepath, exc)
        return ExclusionConfig()

    if not data or not isinstance(data, dict):
        return ExclusionConfig()

    severity_floor = data.get("severity_floor")
    if severity_floor and severity_floor not in SEVERITY_ORDER:
        logger.warning(
            "Invalid severity_floor '%s', ignoring. Must be one of: %s",
            severity_floor,
            ", ".join(SEVERITY_ORDER),
        )
        severity_floor = None

    entries: list[ExclusionEntry] = []
    for item in data.get("exclusions", []):
        if not isinstance(item, dict):
            continue

        # Collect rule IDs — support both rule_id (str) and rule_ids (list)
        rule_ids: list[str] = []
        if "rule_id" in item:
            rule_ids.append(item["rule_id"])
        if "rule_ids" in item:
            ids = item["rule_ids"]
            if isinstance(ids, list):
                rule_ids.extend(ids)

        if not rule_ids:
            logger.warning("Exclusion entry missing rule_id/rule_ids, skipping")
            continue

        reason = item.get("reason", "No reason provided")
        when = item.get("when", {}) or {}

        agent_id_pattern = when.get("agent_id")
        tool_name_patterns = when.get("tool_names")

        # Expand rule_ids into individual entries
        for rid in rule_ids:
            entries.append(
                ExclusionEntry(
                    rule_id=rid,
                    reason=reason,
                    agent_id=agent_id_pattern,
                    tool_names=tool_name_patterns,
                )
            )

    return ExclusionConfig(severity_floor=severity_floor, exclusions=entries)


def apply_exclusions(
    alerts: list[Alert],
    config: ExclusionConfig,
    agent_id: str,
    actions: list[Any],
) -> tuple[list[Alert], list[SuppressedAlert]]:
    """Filter alerts through the exclusion config.

    Returns (kept_alerts, suppressed_alerts).
    """
    if not config.exclusions and not config.severity_floor:
        return alerts, []

    kept: list[Alert] = []
    suppressed: list[SuppressedAlert] = []

    for alert in alerts:
        reason = _should_suppress(alert, config, agent_id, actions)
        if reason is not None:
            suppressed.append(
                SuppressedAlert(
                    rule_id=alert.rule_id,
                    rule_name=alert.rule_name,
                    severity=alert.severity,
                    reason=reason,
                )
            )
        else:
            kept.append(alert)

    return kept, suppressed


def _should_suppress(
    alert: Alert,
    config: ExclusionConfig,
    agent_id: str,
    actions: list[Any],
) -> str | None:
    """Check if an alert should be suppressed. Returns reason or None."""
    # 1. Severity floor check
    if config.severity_floor:
        floor_level = SEVERITY_ORDER.get(config.severity_floor, 0)
        alert_level = SEVERITY_ORDER.get(alert.severity, 0)
        if alert_level < floor_level:
            return f"Below severity floor ({config.severity_floor})"

    # 2. Exclusion entries — first match wins
    for entry in config.exclusions:
        if entry.rule_id != alert.rule_id:
            continue

        # Check agent_id condition (fnmatch glob)
        if entry.agent_id is not None:
            if not fnmatch.fnmatch(agent_id, entry.agent_id):
                continue

        # Check tool_names condition against matched actions only
        if entry.tool_names is not None:
            matched_tool_names = _get_matched_tool_names(alert, actions)
            if not _any_tool_matches(matched_tool_names, entry.tool_names):
                continue

        # All conditions passed — suppress
        return entry.reason

    return None


def _get_matched_tool_names(alert: Alert, actions: list[Any]) -> list[str]:
    """Get tool names from the alert's matched action indices."""
    names: list[str] = []
    for idx in alert.matched_actions:
        if 0 <= idx < len(actions):
            action = actions[idx]
            name = getattr(action, "tool_name", None)
            if name:
                names.append(name)
    return names


def _any_tool_matches(tool_names: list[str], patterns: list[str]) -> bool:
    """Check if any tool name matches any of the glob patterns."""
    return any(
        fnmatch.fnmatch(name, pattern)
        for name in tool_names
        for pattern in patterns
    )
