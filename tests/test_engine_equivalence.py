"""Equivalence tests: fixture traces produce expected alerts via YAML engine.

Acts as a regression test — catches YAML rule changes that break
expected detection behavior.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Ensure SDK is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk" / "src"))

from chainwatch.rules.engine import RuleEngine
from chainwatch.schema import TracePayload

RULES_DIR = str(Path(__file__).resolve().parents[1] / "rules" / "phase0")
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "traces"


@pytest.fixture
def engine() -> RuleEngine:
    e = RuleEngine()
    n = e.load_rules(RULES_DIR)
    assert n == 12, f"Expected 12 rules, loaded {n}"
    return e


def _load_fixture(name: str) -> TracePayload:
    data = json.loads((FIXTURES_DIR / name).read_text())
    return TracePayload(**data)


def test_normal_trace_fires_cw001(engine: RuleEngine):
    """Normal summarizer trace with execute action triggers CW-001."""
    payload = _load_fixture("safe_mode_normal.json")
    alerts = engine.evaluate(payload)
    rule_ids = {a.rule_id for a in alerts}
    # Summarizer doing execute = capability escalation
    assert "CW-001" in rule_ids
    assert len(alerts) == 1


def test_exfiltration_pattern(engine: RuleEngine):
    """Exfiltration pattern fires CW-010, CW-012, CW-031."""
    payload = _load_fixture("exfiltration_pattern.json")
    alerts = engine.evaluate(payload)
    rule_ids = {a.rule_id for a in alerts}
    assert "CW-010" in rule_ids  # read -> external network
    assert "CW-012" in rule_ids  # very_large payload to external
    assert "CW-031" in rule_ids  # sensitive directory access
    assert len(alerts) == 3


def test_capability_escalation(engine: RuleEngine):
    """Capability escalation fires CW-001, CW-030."""
    payload = _load_fixture("capability_escalation.json")
    alerts = engine.evaluate(payload)
    rule_ids = {a.rule_id for a in alerts}
    assert "CW-001" in rule_ids  # summarizer doing write
    assert "CW-030" in rule_ids  # DDL from non-DB agent
    assert len(alerts) == 2


def test_burst_failures(engine: RuleEngine):
    """Burst failures fires CW-022, CW-023, CW-041, CW-050."""
    payload = _load_fixture("burst_failures.json")
    alerts = engine.evaluate(payload)
    rule_ids = {a.rule_id for a in alerts}
    assert "CW-022" in rule_ids  # 3+ consecutive failures
    assert "CW-023" in rule_ids  # first action is network (no preceding read)
    assert "CW-041" in rule_ids  # 3+ network errors
    assert "CW-050" in rule_ids  # 3+ external network calls
    assert len(alerts) == 4
