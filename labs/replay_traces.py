"""Replay saved traces through the ChainWatch YAML rule engine.

Takes JSON trace files (from the lab or Claude Code hooks) and evaluates
all Phase 0 rules against them, printing any alerts.

Usage:
    uv run python labs/replay_traces.py labs/output/exfiltration_*.json
    uv run python labs/replay_traces.py .claude/traces/20250207.jsonl
    uv run python labs/replay_traces.py tests/fixtures/traces/*.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sdk" / "src"))

from chainwatch.rules.engine import RuleEngine
from chainwatch.schema import TracePayload

RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "phase0"

SEVERITY_COLORS = {
    "critical": "\033[91m",  # red
    "high": "\033[93m",      # yellow
    "medium": "\033[94m",    # blue
    "low": "\033[90m",       # gray
}
RESET = "\033[0m"


def load_traces(filepath: Path) -> list[dict]:
    """Load traces from a JSON or JSONL file."""
    text = filepath.read_text()

    # Try single JSON object first
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return data
        return [data]
    except json.JSONDecodeError:
        pass

    # Try JSONL (one JSON object per line)
    traces = []
    for line in text.strip().splitlines():
        line = line.strip()
        if line:
            try:
                traces.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return traces


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay traces through ChainWatch rules")
    parser.add_argument("files", nargs="+", help="JSON/JSONL trace files to evaluate")
    parser.add_argument(
        "--rules-dir",
        default=str(RULES_DIR),
        help=f"Path to YAML rules directory (default: {RULES_DIR})",
    )
    args = parser.parse_args()

    # Load rules
    engine = RuleEngine()
    n_rules = engine.load_rules(args.rules_dir)
    print(f"Loaded {n_rules} rules from {args.rules_dir}\n")

    total_traces = 0
    total_alerts = 0

    for file_path in args.files:
        p = Path(file_path)
        if not p.exists():
            print(f"  SKIP: {file_path} (not found)")
            continue

        traces = load_traces(p)
        print(f"--- {p.name} ({len(traces)} trace(s)) ---")

        for i, raw_trace in enumerate(traces):
            total_traces += 1
            try:
                payload = TracePayload(**raw_trace)
            except Exception as e:
                print(f"  trace[{i}]: PARSE ERROR: {e}")
                continue

            alerts = engine.evaluate(payload)
            total_alerts += len(alerts)

            agent = f"{payload.agent_id} ({payload.agent_type})"
            n_actions = len(payload.actions)

            if alerts:
                for alert in alerts:
                    color = SEVERITY_COLORS.get(alert.severity, "")
                    print(
                        f"  {color}ALERT{RESET} [{alert.rule_id}] "
                        f"{alert.severity.upper()} — {alert.rule_name}"
                    )
                    print(f"        agent={agent}  actions={n_actions}  matched={alert.matched_actions}")
            else:
                print(f"  OK — no alerts for {agent} ({n_actions} actions)")

        print()

    print(f"=== Summary: {total_traces} traces, {total_alerts} alerts ===")


if __name__ == "__main__":
    main()
