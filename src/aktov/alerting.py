"""Universal alert notification — default file log + helpers.

Alerts are appended to ``~/.aktov/alerts.jsonl`` automatically whenever
``trace.end()`` produces non-suppressed alerts.  The log can be read,
filtered, and cleared via the ``aktov alerts`` CLI command or
programmatically with the helpers in this module.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("aktov")

ALERT_LOG = Path.home() / ".aktov" / "alerts.jsonl"

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def log_alerts(
    alerts: list[dict[str, Any]],
    *,
    agent_id: str,
    agent_type: str,
    session_id: str,
) -> None:
    """Append alerts to the default alert log file.

    Best-effort — catches all exceptions so the trace pipeline is never
    interrupted.  Each alert is written as a single JSON line enriched
    with ``timestamp``, ``agent_id``, ``agent_type``, and ``session_id``.
    """
    if not alerts:
        return

    try:
        ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(UTC).isoformat()
        with open(ALERT_LOG, "a", encoding="utf-8") as f:
            for alert in alerts:
                entry = {
                    "timestamp": ts,
                    "agent_id": agent_id,
                    "agent_type": agent_type,
                    "session_id": session_id,
                    **alert,
                }
                f.write(json.dumps(entry, default=str) + "\n")
    except Exception:
        logger.debug("Failed to write to alert log", exc_info=True)


def read_alerts(
    *,
    since: datetime | None = None,
    min_severity: str | None = None,
) -> list[dict[str, Any]]:
    """Read alerts from the log file with optional filtering.

    Parameters
    ----------
    since:
        Only return alerts with a timestamp >= this value.
    min_severity:
        Only return alerts at or above this severity level.
    """
    if not ALERT_LOG.exists():
        return []

    min_level = SEVERITY_ORDER.get(min_severity, 0) if min_severity else 0

    results: list[dict[str, Any]] = []
    for line in ALERT_LOG.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Time filter
        if since is not None:
            ts_str = entry.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str)
                if ts < since:
                    continue
            except (ValueError, TypeError):
                continue

        # Severity filter
        if min_severity:
            severity = entry.get("severity", "low")
            if SEVERITY_ORDER.get(severity, 0) < min_level:
                continue

        results.append(entry)

    return results


def clear_alerts() -> None:
    """Truncate the alert log file."""
    if ALERT_LOG.exists():
        ALERT_LOG.write_text("")
