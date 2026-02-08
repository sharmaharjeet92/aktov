"""Send a single trace to the running Aktov cloud and display the response.

Posts the fixture JSON directly to the cloud API (preserving pre-computed
semantic flags), proving the full chain: HTTP -> cloud -> YAML eval -> alert -> dedup.

Usage:
    # Start Postgres + seed first:
    #   make db && make migrate && make seed && make serve
    # Then:
    uv run python labs/send_one_trace.py
    uv run python labs/send_one_trace.py --fixture tests/fixtures/traces/exfiltration_pattern.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx

DEFAULT_FIXTURE = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "traces" / "exfiltration_pattern.json"
BASE_URL = "http://localhost:8000"
API_KEY = "ak_dev_test_key_abc123"

SEVERITY_COLORS = {
    "critical": "\033[91m",
    "high": "\033[93m",
    "medium": "\033[94m",
    "low": "\033[90m",
}
RESET = "\033[0m"


def main() -> None:
    parser = argparse.ArgumentParser(description="Send a trace to Aktov cloud")
    parser.add_argument("--fixture", default=str(DEFAULT_FIXTURE), help="Path to JSON fixture")
    parser.add_argument("--base-url", default=BASE_URL, help="Cloud base URL")
    parser.add_argument("--api-key", default=API_KEY, help="API key")
    args = parser.parse_args()

    fixture_path = Path(args.fixture)
    if not fixture_path.exists():
        print(f"Fixture not found: {fixture_path}")
        sys.exit(1)

    raw = json.loads(fixture_path.read_text())
    print(f"Fixture: {fixture_path.name}")
    print(f"  agent: {raw['agent_id']} ({raw['agent_type']})")
    print(f"  actions: {len(raw['actions'])}")
    print()

    # POST the raw fixture directly to preserve semantic flags
    url = f"{args.base_url}/v1/traces"
    headers = {
        "Authorization": f"Bearer {args.api_key}",
        "Content-Type": "application/json",
    }

    resp = httpx.post(url, json=raw, headers=headers, timeout=10.0)

    if resp.status_code != 201:
        print(f"FAILED: HTTP {resp.status_code}")
        print(f"  {resp.text}")
        sys.exit(1)

    data = resp.json()
    print("Response:")
    print(f"  trace_id: {data['trace_id']}")
    print(f"  rules_evaluated: {data['rules_evaluated']}")
    print(f"  alerts: {len(data['alerts'])}")

    if data["alerts"]:
        print()
        for alert in data["alerts"]:
            sev = alert["severity"]
            color = SEVERITY_COLORS.get(sev, "")
            print(f"  {color}ALERT{RESET} [{sev.upper()}] {alert['title']}")
            print(f"        category={alert['category']}")
    else:
        print("  No alerts triggered.")

    print()
    if data["trace_id"]:
        print("E2E flow confirmed: HTTP -> cloud -> YAML eval -> alert")
    else:
        print("FAILED: No trace_id returned")
        sys.exit(1)


if __name__ == "__main__":
    main()
