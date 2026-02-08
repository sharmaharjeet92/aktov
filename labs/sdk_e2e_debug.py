"""SDK end-to-end test — DEBUG mode.

Like sdk_e2e_safe.py but with mode="debug", verifying that raw arguments
are preserved on the wire and the cloud still processes them correctly.

Usage:
    AK_BASE_URL=http://localhost:8000 uv run python labs/sdk_e2e_debug.py
"""

from __future__ import annotations

import os
import sys

from aktov.client import Aktov

BASE_URL = os.environ.get("AK_BASE_URL", "http://localhost:8000")
API_KEY = os.environ.get("AK_API_KEY", "ak_dev_test_key_abc123")


def main() -> None:
    print("=" * 60)
    print("SDK E2E Test — DEBUG Mode")
    print("=" * 60)
    print()

    cw = Aktov(
        api_key=API_KEY,
        base_url=BASE_URL,
        agent_id="e2e-debug-agent",
        agent_type="assistant",
        mode="debug",
        timeout_ms=5000,
        raise_on_error=True,
    )

    trace = cw.start_trace(declared_intent="Debug test")

    a1 = trace.record_action(
        tool_name="read_file",
        arguments={"path": "/tmp/report.csv"},
        outcome={"status": "success"},
        latency_ms=10,
    )
    print(f"  Action 0: {a1.tool_name} → category={a1.tool_category}")
    print(f"    args on wire: {a1.arguments}")  # Should be present in DEBUG

    a2 = trace.record_action(
        tool_name="write_file",
        arguments={"path": "/tmp/summary.txt", "content": "report summary"},
        outcome={"status": "success"},
        latency_ms=5,
    )
    print(f"  Action 1: {a2.tool_name} → category={a2.tool_category}")
    print(f"    args on wire: {a2.arguments}")

    # Verify DEBUG mode keeps arguments
    payload = trace._build_payload()
    for action in payload.actions:
        assert action.arguments is not None, (
            f"DEBUG MODE BUG: {action.tool_name} lost arguments!"
        )
    print("  ✓ DEBUG mode verified: raw arguments preserved")
    print()

    response = trace.end()
    print(f"  Response: status={response.status}, trace_id={response.trace_id}")
    print(f"  Rules evaluated: {response.rules_evaluated}")
    print(f"  Alerts: {len(response.alerts)}")

    if response.alerts:
        for alert in response.alerts:
            sev = alert.get("severity", "unknown")
            print(f"    ALERT [{sev.upper()}] {alert.get('title', '')}")
    else:
        print("  No alerts (expected — benign assistant trace)")

    print()
    print("=" * 60)
    if response.status == "sent":
        print("SDK → Cloud E2E (DEBUG mode): PASSED")
    else:
        print("SDK → Cloud E2E (DEBUG mode): FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
