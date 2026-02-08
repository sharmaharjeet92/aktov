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

from aktov.rules.engine import RuleEngine
from aktov.schema import TracePayload

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
    """Normal summarizer trace with execute action triggers AK-001."""
    payload = _load_fixture("safe_mode_normal.json")
    alerts = engine.evaluate(payload)
    rule_ids = {a.rule_id for a in alerts}
    # Summarizer doing execute = capability escalation
    assert "AK-001" in rule_ids
    assert len(alerts) == 1


def test_exfiltration_pattern(engine: RuleEngine):
    """Exfiltration pattern fires AK-010, AK-012, AK-031."""
    payload = _load_fixture("exfiltration_pattern.json")
    alerts = engine.evaluate(payload)
    rule_ids = {a.rule_id for a in alerts}
    assert "AK-010" in rule_ids  # read -> external network
    assert "AK-012" in rule_ids  # very_large payload to external
    assert "AK-031" in rule_ids  # sensitive directory access
    assert len(alerts) == 3


def test_capability_escalation(engine: RuleEngine):
    """Capability escalation fires AK-001, AK-030."""
    payload = _load_fixture("capability_escalation.json")
    alerts = engine.evaluate(payload)
    rule_ids = {a.rule_id for a in alerts}
    assert "AK-001" in rule_ids  # summarizer doing write
    assert "AK-030" in rule_ids  # DDL from non-DB agent
    assert len(alerts) == 2


def test_burst_failures(engine: RuleEngine):
    """Burst failures fires AK-022, AK-023, AK-041, AK-050."""
    payload = _load_fixture("burst_failures.json")
    alerts = engine.evaluate(payload)
    rule_ids = {a.rule_id for a in alerts}
    assert "AK-022" in rule_ids  # 3+ consecutive failures
    assert "AK-023" in rule_ids  # first action is network (no preceding read)
    assert "AK-041" in rule_ids  # 3+ network errors
    assert "AK-050" in rule_ids  # 3+ external network calls
    assert len(alerts) == 4
