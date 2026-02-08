"""Claude Code PostToolUse hook for Aktov.

Receives tool call JSON on stdin from Claude Code's PostToolUse hook,
accumulates actions to a session trace file, and prints alerts to
stderr for real-time visibility.

Setup::

    aktov init claude-code

Or manually add to .claude/settings.json::

    {
      "hooks": {
        "PostToolUse": [{
          "command": "python -m aktov.hooks.claude_code",
          "async": true
        }]
      }
    }

Environment variables::

    AK_AGENT_NAME   — required, name for the agent being traced
    AK_RULES_DIR    — optional, path to custom YAML rules directory
    AK_API_KEY      — optional, Aktov API key for cloud features
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from aktov.client import Aktov
from aktov.schema import TracePayload


# Session trace directory
TRACES_DIR = Path.home() / ".aktov" / "traces"

SEVERITY_SYMBOLS = {
    "critical": "!!!",
    "high": "!! ",
    "medium": "!  ",
    "low": ".  ",
}


def _get_session_id() -> str:
    """Derive a session ID from the parent process or date."""
    ppid = os.getppid()
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"{today}-{ppid}"


def _append_action(session_id: str, action_data: dict) -> Path:
    """Append an action to the session trace file."""
    TRACES_DIR.mkdir(parents=True, exist_ok=True)
    trace_file = TRACES_DIR / f"{session_id}.jsonl"
    with open(trace_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(action_data, default=str) + "\n")
    return trace_file


def _load_session_actions(trace_file: Path) -> list[dict]:
    """Load all actions from a session trace file."""
    actions = []
    if trace_file.exists():
        for line in trace_file.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    actions.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return actions


def _evaluate_and_alert(
    agent_name: str,
    actions: list[dict],
    rules_dir: str | None = None,
    api_key: str | None = None,
) -> None:
    """Evaluate accumulated actions and print alerts to stderr."""
    ak = Aktov(
        api_key=api_key,
        agent_id=agent_name,
        agent_type="claude-code",
        rules_dir=rules_dir,
    )
    trace = ak.start_trace(agent_id=agent_name, agent_type="claude-code")

    for action in actions:
        trace.record_action(
            tool_name=action.get("tool_name", "unknown"),
            arguments=action.get("arguments"),
        )

    response = trace.end()

    for alert in response.alerts:
        severity = alert.get("severity", "medium")
        symbol = SEVERITY_SYMBOLS.get(severity, "?  ")
        rule_id = alert.get("rule_id", "???")
        rule_name = alert.get("rule_name", "unknown")
        print(
            f"[aktov] {symbol} [{rule_id}] {severity.upper()}: {rule_name}",
            file=sys.stderr,
        )


def main() -> None:
    """Entry point for the Claude Code PostToolUse hook."""
    agent_name = os.environ.get("AK_AGENT_NAME", "claude-code")
    rules_dir = os.environ.get("AK_RULES_DIR")
    api_key = os.environ.get("AK_API_KEY")

    # Read hook payload from stdin
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return
        payload = json.loads(raw)
    except (json.JSONDecodeError, IOError):
        return

    # Extract tool call data from Claude Code's hook format
    tool_name = payload.get("tool_name", "unknown")
    tool_input = payload.get("tool_input", {})

    # Build action record
    action_data = {
        "tool_name": tool_name,
        "arguments": tool_input if isinstance(tool_input, dict) else None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Append to session trace
    session_id = _get_session_id()
    trace_file = _append_action(session_id, action_data)

    # Load all session actions and evaluate
    all_actions = _load_session_actions(trace_file)
    _evaluate_and_alert(agent_name, all_actions, rules_dir, api_key)


if __name__ == "__main__":
    main()
