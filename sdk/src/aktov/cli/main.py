"""Aktov CLI entry point.

Provides a ``preview`` command that shows what data would be transmitted
to the cloud API for a given trace file, with semantic flag extraction
applied.

Usage::

    aktov preview --trace trace.json --mode safe
    aktov preview --trace trace.json --mode debug
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from aktov.canonicalization import infer_tool_category
from aktov.rules.engine import RuleEngine
from aktov.schema import SemanticFlags, TracePayload
from aktov.semantic_flags import extract_semantic_flags


def _load_trace_file(path: str) -> dict[str, Any]:
    """Load and parse a JSON trace file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _format_flags(flags: SemanticFlags) -> str:
    """Format semantic flags as a compact summary string."""
    parts: list[str] = []
    if flags.sql_statement_type:
        parts.append(f"sql={flags.sql_statement_type}")
    if flags.http_method:
        parts.append(f"http={flags.http_method}")
    if flags.is_external is not None:
        parts.append(f"external={'Y' if flags.is_external else 'N'}")
    if flags.sensitive_dir_match:
        parts.append("SENSITIVE_DIR")
    if flags.path_traversal_detected:
        parts.append("PATH_TRAVERSAL")
    if flags.has_network_calls:
        parts.append("NETWORK")
    if flags.argument_size_bucket:
        parts.append(f"size={flags.argument_size_bucket}")
    return ", ".join(parts) if parts else "-"


def _print_table(headers: list[str], rows: list[list[str]]) -> None:
    """Print a simple formatted table to stdout."""
    # Compute column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    # Header
    header_line = " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    separator = "-+-".join("-" * w for w in widths)

    print(header_line)
    print(separator)
    for row in rows:
        line = " | ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))
        print(line)


def cmd_preview(args: argparse.Namespace) -> None:
    """Execute the ``preview`` command."""
    trace_data = _load_trace_file(args.trace)
    mode = args.mode

    print(f"\n{'=' * 60}")
    print(f"  Aktov Trace Preview  (mode: {mode.upper()})")
    print(f"{'=' * 60}")

    # Top-level metadata
    print(f"\n  Agent ID:    {trace_data.get('agent_id', 'N/A')}")
    print(f"  Agent Type:  {trace_data.get('agent_type', 'N/A')}")
    print(f"  Task ID:     {trace_data.get('task_id', 'N/A')}")
    print(f"  Intent:      {trace_data.get('declared_intent', 'N/A')}")
    print()

    # Process actions
    actions = trace_data.get("actions", [])
    if not actions:
        print("  (no actions recorded)")
        return

    headers = ["#", "Tool", "Category", "Semantic Flags", "Arguments"]
    rows: list[list[str]] = []

    for i, action in enumerate(actions):
        tool_name = action.get("tool_name", "unknown")
        tool_category = action.get("tool_category") or infer_tool_category(tool_name)
        arguments = action.get("arguments")

        # Extract semantic flags
        flags = extract_semantic_flags(tool_name, tool_category, arguments)

        # Format arguments column
        if mode == "safe":
            args_display = "[STRIPPED]"
        elif arguments:
            args_str = json.dumps(arguments, default=str)
            args_display = args_str[:80] + "..." if len(args_str) > 80 else args_str
        else:
            args_display = "-"

        rows.append([
            str(i),
            tool_name,
            tool_category,
            _format_flags(flags),
            args_display,
        ])

    _print_table(headers, rows)

    # Summary
    print(f"\n  Total actions: {len(actions)}")
    if mode == "safe":
        print("  Mode: SAFE — raw arguments are STRIPPED before transmission")
    else:
        print("  Mode: DEBUG — raw arguments are INCLUDED (use only in dev)")
    print()


SEVERITY_COLORS = {
    "critical": "\033[91m",
    "high": "\033[93m",
    "medium": "\033[94m",
    "low": "\033[90m",
}
RESET = "\033[0m"


def cmd_scan(args: argparse.Namespace) -> None:
    """Execute the ``scan`` command — evaluate traces against bundled rules."""
    engine = RuleEngine()

    if args.rules_dir:
        n = engine.load_rules(args.rules_dir)
        source = args.rules_dir
    else:
        n = engine.load_bundled_rules()
        source = "bundled samples"

    print(f"\nLoaded {n} rules from {source}\n")

    total_traces = 0
    total_alerts = 0

    for file_path in args.files:
        path = Path(file_path)
        if not path.exists():
            print(f"  SKIP: {file_path} (not found)")
            continue

        traces = _load_traces(path)
        print(f"--- {path.name} ({len(traces)} trace(s)) ---")

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

            if alerts:
                for alert in alerts:
                    color = SEVERITY_COLORS.get(alert.severity, "")
                    print(
                        f"  {color}ALERT{RESET} [{alert.rule_id}] "
                        f"{alert.severity.upper()} — {alert.rule_name}"
                    )
                    print(f"        agent={agent}  matched={alert.matched_actions}")
            else:
                print(f"  OK — no alerts for {agent}")

        print()

    print(f"=== Summary: {total_traces} traces, {total_alerts} alerts ===\n")


def _load_traces(filepath: Path) -> list[dict]:
    """Load traces from a JSON or JSONL file."""
    text = filepath.read_text()
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        pass
    traces = []
    for line in text.strip().splitlines():
        line = line.strip()
        if line:
            try:
                traces.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return traces


def main(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="aktov",
        description="Aktov CLI — detection engineering for AI agents",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # preview subcommand
    preview_parser = subparsers.add_parser(
        "preview",
        help="Preview what data would be sent to the cloud API",
    )
    preview_parser.add_argument(
        "--trace",
        required=True,
        help="Path to a JSON trace file",
    )
    preview_parser.add_argument(
        "--mode",
        choices=["safe", "debug"],
        default="safe",
        help="Transmission mode (default: safe)",
    )

    # scan subcommand
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan trace files against detection rules",
    )
    scan_parser.add_argument(
        "files",
        nargs="+",
        help="JSON/JSONL trace files to evaluate",
    )
    scan_parser.add_argument(
        "--rules-dir",
        default=None,
        help="Path to YAML rules directory (default: bundled samples)",
    )

    parsed = parser.parse_args(argv)

    if parsed.command is None:
        parser.print_help()
        sys.exit(1)

    if parsed.command == "preview":
        cmd_preview(parsed)
    elif parsed.command == "scan":
        cmd_scan(parsed)


if __name__ == "__main__":
    main()
