"""ChainWatch CLI entry point.

Provides a ``preview`` command that shows what data would be transmitted
to the cloud API for a given trace file, with semantic flag extraction
applied.

Usage::

    chainwatch preview --trace trace.json --mode safe
    chainwatch preview --trace trace.json --mode debug
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from chainwatch.canonicalization import infer_tool_category
from chainwatch.schema import SemanticFlags
from chainwatch.semantic_flags import extract_semantic_flags


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
    print(f"  ChainWatch Trace Preview  (mode: {mode.upper()})")
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


def main(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="chainwatch",
        description="ChainWatch CLI — detection engineering for AI agents",
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

    parsed = parser.parse_args(argv)

    if parsed.command is None:
        parser.print_help()
        sys.exit(1)

    if parsed.command == "preview":
        cmd_preview(parsed)


if __name__ == "__main__":
    main()
