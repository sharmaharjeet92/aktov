"""Aktov CLI entry point.

Commands::

    aktov init <framework>     — set up Aktov for your framework
    aktov scan trace.json      — evaluate traces against detection rules
    aktov report               — show alerts from latest Claude Code session
    aktov preview              — preview what data would be sent to cloud
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

# ---------------------------------------------------------------------------
# init command
# ---------------------------------------------------------------------------

INIT_SNIPPETS = {
    "claude-code": None,  # handled specially — writes config file
    "openai-agents": '''\
Add these lines to your agent code:

    from aktov.integrations.openai_agents import AktovHooks

    hooks = AktovHooks(aktov_agent_name="my-agent")
    result = await Runner.run(agent, input="...", hooks=hooks)
    response = hooks.end()
    # response.alerts → [{"rule_id": "AK-010", "severity": "critical", ...}]
''',
    "langchain": '''\
Add these lines to your agent code:

    from aktov.integrations.langchain import AktovCallback

    cb = AktovCallback(aktov_agent_name="my-agent")
    agent.invoke("do something", config={"callbacks": [cb]})
    response = cb.end()
    # response.alerts → [{"rule_id": "AK-010", "severity": "critical", ...}]
''',
    "mcp": '''\
Add these lines to your MCP client code:

    from aktov.integrations.mcp import wrap

    traced = wrap(mcp_client, aktov_agent_name="my-agent")
    result = await traced.call_tool("read_file", {"path": "/data/report.csv"})
    response = traced.end_trace()
    # response.alerts → [{"rule_id": "AK-010", "severity": "critical", ...}]
''',
    "custom": '''\
Use the core API directly in your agent code:

    from aktov import Aktov

    ak = Aktov(agent_id="my-agent", agent_type="custom")
    trace = ak.start_trace()

    # After each tool call in your agent loop:
    trace.record_action(tool_name="read_file", arguments={"path": "/data/report.csv"})

    response = trace.end()
    # response.alerts → [{"rule_id": "AK-010", "severity": "critical", ...}]
''',
}


def _init_claude_code() -> None:
    """Write Claude Code PostToolUse hook config to .claude/settings.json."""
    settings_dir = Path(".claude")
    settings_file = settings_dir / "settings.json"

    # Load existing settings or start fresh
    settings: dict[str, Any] = {}
    if settings_file.exists():
        try:
            settings = json.loads(settings_file.read_text())
        except json.JSONDecodeError:
            settings = {}

    # Add PostToolUse hook
    hooks = settings.setdefault("hooks", {})
    post_tool_use = hooks.setdefault("PostToolUse", [])

    hook_command = "python -m aktov.hooks.claude_code"

    # Check if already configured
    for hook_entry in post_tool_use:
        if not isinstance(hook_entry, dict):
            continue
        # Check both flat and nested formats
        if hook_entry.get("command") == hook_command:
            print("  Aktov hook already configured in .claude/settings.json")
            return
        for sub_hook in hook_entry.get("hooks", []):
            if isinstance(sub_hook, dict) and sub_hook.get("command") == hook_command:
                print("  Aktov hook already configured in .claude/settings.json")
                return

    post_tool_use.append({
        "matcher": ".*",
        "hooks": [
            {
                "type": "command",
                "command": hook_command,
                "timeout": 30,
                "async": True,
            }
        ],
    })

    settings_dir.mkdir(parents=True, exist_ok=True)
    settings_file.write_text(json.dumps(settings, indent=2) + "\n")

    print("  Added PostToolUse hook to .claude/settings.json")
    print()
    print("  Aktov will now monitor Claude Code tool calls.")
    print("  Alerts appear in real-time during sessions.")
    print()
    print("  To review after a session:")
    print("    $ aktov report")
    print()
    print("  To connect to cloud (full ruleset + dashboard):")
    print("    $ export AK_API_KEY=ak_...")


def cmd_init(args: argparse.Namespace) -> None:
    """Execute the ``init`` command."""
    framework = args.framework

    if framework not in INIT_SNIPPETS:
        valid = ", ".join(sorted(INIT_SNIPPETS.keys()))
        print(f"Unknown framework: {framework}")
        print(f"Valid options: {valid}")
        sys.exit(1)

    print(f"\n  Setting up Aktov for {framework}\n")

    if framework == "claude-code":
        _init_claude_code()
    else:
        print(INIT_SNIPPETS[framework])

    print("  Docs: https://aktov.io/docs")
    print()


# ---------------------------------------------------------------------------
# report command
# ---------------------------------------------------------------------------

def cmd_report(args: argparse.Namespace) -> None:
    """Show alerts from the latest Claude Code session trace."""
    traces_dir = Path.home() / ".aktov" / "traces"

    if not traces_dir.exists():
        print("\n  No session traces found.")
        print("  Run `aktov init claude-code` to start monitoring.\n")
        return

    # Find the most recent trace file
    trace_files = sorted(traces_dir.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not trace_files:
        print("\n  No session traces found.\n")
        return

    trace_file = trace_files[0]
    print(f"\n  Latest session: {trace_file.name}\n")

    # Load actions
    actions: list[dict] = []
    for line in trace_file.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                actions.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not actions:
        print("  (no actions recorded)\n")
        return

    # Evaluate
    from aktov.client import Aktov
    ak = Aktov(agent_id="claude-code", agent_type="claude-code")
    trace = ak.start_trace()
    for action in actions:
        trace.record_action(
            tool_name=action.get("tool_name", "unknown"),
            arguments=action.get("arguments"),
        )
    response = trace.end()

    print(f"  Tool calls: {len(actions)}")
    print(f"  Rules evaluated: {response.rules_evaluated}")
    print()

    if not response.alerts:
        print("  No alerts.\n")
        return

    # Print alert table
    headers = ["Rule", "Severity", "Description"]
    rows: list[list[str]] = []
    for alert in response.alerts:
        rows.append([
            alert.get("rule_id", "???"),
            alert.get("severity", "?").upper(),
            alert.get("rule_name", "unknown"),
        ])

    _print_table(headers, rows)
    print()


# ---------------------------------------------------------------------------
# preview command
# ---------------------------------------------------------------------------

def _load_trace_file(path: str) -> dict[str, Any]:
    """Load and parse a JSON trace file."""
    with open(path, encoding="utf-8") as f:
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
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    header_line = " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    separator = "-+-".join("-" * w for w in widths)

    print(f"  {header_line}")
    print(f"  {separator}")
    for row in rows:
        line = " | ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))
        print(f"  {line}")


def cmd_preview(args: argparse.Namespace) -> None:
    """Execute the ``preview`` command."""
    trace_data = _load_trace_file(args.trace)
    mode = args.mode

    print(f"\n{'=' * 60}")
    print(f"  Aktov Trace Preview  (mode: {mode.upper()})")
    print(f"{'=' * 60}")

    print(f"\n  Agent ID:    {trace_data.get('agent_id', 'N/A')}")
    print(f"  Agent Type:  {trace_data.get('agent_type', 'N/A')}")
    print(f"  Task ID:     {trace_data.get('task_id', 'N/A')}")
    print(f"  Intent:      {trace_data.get('declared_intent', 'N/A')}")
    print()

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

        flags = extract_semantic_flags(tool_name, tool_category, arguments)

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

    print(f"\n  Total actions: {len(actions)}")
    if mode == "safe":
        print("  Mode: SAFE — raw arguments are STRIPPED before transmission")
    else:
        print("  Mode: DEBUG — raw arguments are INCLUDED (use only in dev)")
    print()


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="aktov",
        description="Aktov CLI — detection engineering for AI agents",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # init subcommand
    init_parser = subparsers.add_parser(
        "init",
        help="Set up Aktov for your framework",
    )
    init_parser.add_argument(
        "framework",
        choices=sorted(INIT_SNIPPETS.keys()),
        help="Target framework",
    )

    # report subcommand
    subparsers.add_parser(
        "report",
        help="Show alerts from latest Claude Code session",
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

    # rules subcommand group
    rules_parser = subparsers.add_parser(
        "rules",
        help="Rule authoring tools: schema reference, validation, examples",
    )
    rules_sub = rules_parser.add_subparsers(
        dest="rules_command", help="Rules subcommands",
    )

    # rules schema
    schema_parser = rules_sub.add_parser(
        "schema", help="Print available fields, operators, and match types",
    )
    schema_parser.add_argument(
        "--fields", action="store_true", help="Show only fields",
    )
    schema_parser.add_argument(
        "--operators", action="store_true", help="Show only operators",
    )
    schema_parser.add_argument(
        "--match-types", action="store_true", help="Show only match types",
    )

    # rules validate
    validate_parser = rules_sub.add_parser(
        "validate", help="Validate a rule YAML file",
    )
    validate_parser.add_argument("file", help="Path to YAML rule file")

    # rules examples
    rules_sub.add_parser(
        "examples", help="Rule-writing guide with examples of each match type",
    )

    parsed = parser.parse_args(argv)

    if parsed.command is None:
        parser.print_help()
        sys.exit(1)

    if parsed.command == "init":
        cmd_init(parsed)
    elif parsed.command == "report":
        cmd_report(parsed)
    elif parsed.command == "scan":
        cmd_scan(parsed)
    elif parsed.command == "preview":
        cmd_preview(parsed)
    elif parsed.command == "rules":
        from aktov.cli.rules_cmd import (
            cmd_rules_examples,
            cmd_rules_schema,
            cmd_rules_validate,
        )

        if parsed.rules_command == "schema":
            cmd_rules_schema(parsed)
        elif parsed.rules_command == "validate":
            cmd_rules_validate(parsed)
        elif parsed.rules_command == "examples":
            cmd_rules_examples(parsed)
        else:
            rules_parser.print_help()
            sys.exit(1)


if __name__ == "__main__":
    main()
