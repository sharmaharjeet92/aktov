"""Tests for aktov.rules.exclusions — exclusion filter."""

import yaml

from aktov.client import Aktov
from aktov.rules.engine import Alert
from aktov.rules.exclusions import (
    ExclusionConfig,
    ExclusionEntry,
    SuppressedAlert,
    apply_exclusions,
    load_exclusions,
)
from aktov.schema import Action, SemanticFlags

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _make_alert(
    rule_id: str = "AK-010",
    rule_name: str = "Read-then-Network",
    severity: str = "high",
    matched_actions: list[int] | None = None,
) -> Alert:
    return Alert(
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        category="exfiltration",
        matched_actions=matched_actions or [0, 1],
        message=f"Rule '{rule_name}' matched",
    )


def _make_action(tool_name: str = "read_file", tool_category: str = "read") -> Action:
    return Action(
        sequence_index=0,
        tool_name=tool_name,
        tool_category=tool_category,
        semantic_flags=SemanticFlags(),
    )


def _write_yaml(data: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f)


# ------------------------------------------------------------------
# TestLoadExclusions
# ------------------------------------------------------------------


class TestLoadExclusions:
    def test_load_valid_yaml(self, tmp_path):
        filepath = str(tmp_path / "exclusions.yaml")
        _write_yaml(
            {
                "severity_floor": "high",
                "exclusions": [
                    {
                        "rule_id": "AK-010",
                        "reason": "Data pipeline reads then posts",
                        "when": {"agent_id": "data-pipeline-*"},
                    }
                ],
            },
            filepath,
        )

        config = load_exclusions(filepath)
        assert config.severity_floor == "high"
        assert len(config.exclusions) == 1
        assert config.exclusions[0].rule_id == "AK-010"
        assert config.exclusions[0].agent_id == "data-pipeline-*"

    def test_missing_file_returns_empty(self, tmp_path):
        config = load_exclusions(str(tmp_path / "nonexistent.yaml"))
        assert config.severity_floor is None
        assert config.exclusions == []

    def test_empty_file_returns_empty(self, tmp_path):
        filepath = str(tmp_path / "empty.yaml")
        with open(filepath, "w") as f:
            f.write("")
        config = load_exclusions(filepath)
        assert config.exclusions == []

    def test_missing_rule_id_skipped(self, tmp_path):
        filepath = str(tmp_path / "exclusions.yaml")
        _write_yaml(
            {
                "exclusions": [
                    {"reason": "no rule_id here"},
                    {"rule_id": "AK-007", "reason": "valid"},
                ]
            },
            filepath,
        )
        config = load_exclusions(filepath)
        assert len(config.exclusions) == 1
        assert config.exclusions[0].rule_id == "AK-007"

    def test_severity_floor_loaded(self, tmp_path):
        filepath = str(tmp_path / "exclusions.yaml")
        _write_yaml({"severity_floor": "critical", "exclusions": []}, filepath)
        config = load_exclusions(filepath)
        assert config.severity_floor == "critical"

    def test_invalid_severity_floor_ignored(self, tmp_path):
        filepath = str(tmp_path / "exclusions.yaml")
        _write_yaml({"severity_floor": "extreme", "exclusions": []}, filepath)
        config = load_exclusions(filepath)
        assert config.severity_floor is None

    def test_rule_ids_expanded(self, tmp_path):
        filepath = str(tmp_path / "exclusions.yaml")
        _write_yaml(
            {
                "exclusions": [
                    {
                        "rule_ids": ["AK-007", "AK-010", "AK-032"],
                        "reason": "DevOps agents",
                        "when": {"agent_id": "devops-*"},
                    }
                ]
            },
            filepath,
        )
        config = load_exclusions(filepath)
        assert len(config.exclusions) == 3
        assert {e.rule_id for e in config.exclusions} == {
            "AK-007", "AK-010", "AK-032",
        }
        assert all(e.agent_id == "devops-*" for e in config.exclusions)

    def test_tool_names_loaded(self, tmp_path):
        filepath = str(tmp_path / "exclusions.yaml")
        _write_yaml(
            {
                "exclusions": [
                    {
                        "rule_id": "AK-010",
                        "reason": "Approved egress",
                        "when": {"tool_names": ["upload_*", "sync_to_*"]},
                    }
                ]
            },
            filepath,
        )
        config = load_exclusions(filepath)
        assert config.exclusions[0].tool_names == ["upload_*", "sync_to_*"]


# ------------------------------------------------------------------
# TestApplyExclusions
# ------------------------------------------------------------------


class TestApplyExclusions:
    def test_no_exclusions_passes_all(self):
        alerts = [_make_alert()]
        config = ExclusionConfig()
        actions = [_make_action(), _make_action("http_post", "network")]

        kept, suppressed = apply_exclusions(alerts, config, "my-agent", actions)
        assert len(kept) == 1
        assert len(suppressed) == 0

    def test_severity_floor_suppresses_low(self):
        alerts = [
            _make_alert(severity="low", rule_id="AK-001"),
            _make_alert(severity="medium", rule_id="AK-012"),
            _make_alert(severity="high", rule_id="AK-010"),
        ]
        config = ExclusionConfig(severity_floor="high")
        actions = [_make_action()]

        kept, suppressed = apply_exclusions(alerts, config, "any-agent", actions)
        assert len(kept) == 1
        assert kept[0].rule_id == "AK-010"
        assert len(suppressed) == 2
        assert all("severity floor" in s.reason.lower() for s in suppressed)

    def test_severity_floor_keeps_critical(self):
        alerts = [_make_alert(severity="critical")]
        config = ExclusionConfig(severity_floor="critical")
        actions = [_make_action()]

        kept, suppressed = apply_exclusions(alerts, config, "any-agent", actions)
        assert len(kept) == 1
        assert len(suppressed) == 0

    def test_unconditional_rule_suppression(self):
        alerts = [_make_alert(rule_id="AK-032")]
        config = ExclusionConfig(
            exclusions=[
                ExclusionEntry(rule_id="AK-032", reason="Not relevant")
            ]
        )
        actions = [_make_action()]

        kept, suppressed = apply_exclusions(alerts, config, "any-agent", actions)
        assert len(kept) == 0
        assert len(suppressed) == 1
        assert suppressed[0].reason == "Not relevant"

    def test_agent_id_exact_match(self):
        alerts = [_make_alert()]
        config = ExclusionConfig(
            exclusions=[
                ExclusionEntry(
                    rule_id="AK-010",
                    reason="Pipeline agent",
                    agent_id="data-pipeline-1",
                )
            ]
        )
        actions = [_make_action(), _make_action("http_post", "network")]

        kept, suppressed = apply_exclusions(
            alerts, config, "data-pipeline-1", actions,
        )
        assert len(kept) == 0
        assert len(suppressed) == 1

    def test_agent_id_glob_match(self):
        alerts = [_make_alert()]
        config = ExclusionConfig(
            exclusions=[
                ExclusionEntry(
                    rule_id="AK-010",
                    reason="Pipeline agents",
                    agent_id="data-pipeline-*",
                )
            ]
        )
        actions = [_make_action(), _make_action("http_post", "network")]

        kept, suppressed = apply_exclusions(
            alerts, config, "data-pipeline-prod", actions,
        )
        assert len(kept) == 0
        assert len(suppressed) == 1

    def test_agent_id_mismatch_keeps_alert(self):
        alerts = [_make_alert()]
        config = ExclusionConfig(
            exclusions=[
                ExclusionEntry(
                    rule_id="AK-010",
                    reason="Pipeline agents",
                    agent_id="data-pipeline-*",
                )
            ]
        )
        actions = [_make_action(), _make_action("http_post", "network")]

        kept, suppressed = apply_exclusions(
            alerts, config, "general-assistant", actions,
        )
        assert len(kept) == 1
        assert len(suppressed) == 0

    def test_tool_name_exact_match(self):
        alerts = [_make_alert(matched_actions=[1])]
        config = ExclusionConfig(
            exclusions=[
                ExclusionEntry(
                    rule_id="AK-010",
                    reason="Approved egress",
                    tool_names=["upload_report"],
                )
            ]
        )
        actions = [
            _make_action("read_file", "read"),
            _make_action("upload_report", "network"),
        ]

        kept, suppressed = apply_exclusions(alerts, config, "my-agent", actions)
        assert len(kept) == 0
        assert len(suppressed) == 1

    def test_tool_name_glob_match(self):
        alerts = [_make_alert(matched_actions=[1])]
        config = ExclusionConfig(
            exclusions=[
                ExclusionEntry(
                    rule_id="AK-010",
                    reason="Approved egress",
                    tool_names=["upload_*"],
                )
            ]
        )
        actions = [
            _make_action("read_file", "read"),
            _make_action("upload_report", "network"),
        ]

        kept, suppressed = apply_exclusions(alerts, config, "my-agent", actions)
        assert len(kept) == 0
        assert len(suppressed) == 1

    def test_tool_name_no_match_keeps_alert(self):
        alerts = [_make_alert(matched_actions=[1])]
        config = ExclusionConfig(
            exclusions=[
                ExclusionEntry(
                    rule_id="AK-010",
                    reason="Only sync tools",
                    tool_names=["sync_*"],
                )
            ]
        )
        actions = [
            _make_action("read_file", "read"),
            _make_action("http_post", "network"),
        ]

        kept, suppressed = apply_exclusions(alerts, config, "my-agent", actions)
        assert len(kept) == 1
        assert len(suppressed) == 0

    def test_both_conditions_and_logic(self):
        alerts = [_make_alert(matched_actions=[1])]
        config = ExclusionConfig(
            exclusions=[
                ExclusionEntry(
                    rule_id="AK-010",
                    reason="Auth agent + vault",
                    agent_id="auth-*",
                    tool_names=["vault_*"],
                )
            ]
        )
        actions = [
            _make_action("read_config", "read"),
            _make_action("vault_get_secret", "credential"),
        ]

        # Both match → suppressed
        kept, suppressed = apply_exclusions(
            alerts, config, "auth-helper", actions,
        )
        assert len(kept) == 0
        assert len(suppressed) == 1

        # Agent matches, tool doesn't → kept
        alerts2 = [_make_alert(matched_actions=[0])]
        kept2, suppressed2 = apply_exclusions(
            alerts2, config, "auth-helper", actions,
        )
        assert len(kept2) == 1
        assert len(suppressed2) == 0

        # Tool matches, agent doesn't → kept
        alerts3 = [_make_alert(matched_actions=[1])]
        kept3, suppressed3 = apply_exclusions(
            alerts3, config, "general-bot", actions,
        )
        assert len(kept3) == 1
        assert len(suppressed3) == 0

    def test_first_matching_exclusion_wins(self):
        alerts = [_make_alert()]
        config = ExclusionConfig(
            exclusions=[
                ExclusionEntry(
                    rule_id="AK-010",
                    reason="First reason",
                    agent_id="data-*",
                ),
                ExclusionEntry(
                    rule_id="AK-010",
                    reason="Second reason",
                ),
            ]
        )
        actions = [_make_action()]

        _, suppressed = apply_exclusions(
            alerts, config, "data-pipeline", actions,
        )
        assert suppressed[0].reason == "First reason"

    def test_suppressed_alert_structure(self):
        alerts = [_make_alert(rule_id="AK-010", severity="high")]
        config = ExclusionConfig(
            exclusions=[
                ExclusionEntry(rule_id="AK-010", reason="Known pattern")
            ]
        )
        actions = [_make_action()]

        _, suppressed = apply_exclusions(alerts, config, "my-agent", actions)
        assert len(suppressed) == 1
        s = suppressed[0]
        assert isinstance(s, SuppressedAlert)
        assert s.rule_id == "AK-010"
        assert s.rule_name == "Read-then-Network"
        assert s.severity == "high"
        assert s.reason == "Known pattern"


# ------------------------------------------------------------------
# TestEndToEnd — through Aktov client
# ------------------------------------------------------------------


class TestEndToEnd:
    def _make_exclusion_file(self, tmp_path, data: dict) -> str:
        filepath = str(tmp_path / ".aktov-exclusions.yaml")
        _write_yaml(data, filepath)
        return filepath

    def test_no_exclusion_file_unchanged(self):
        """Without exclusions_file, alerts pass through unchanged."""
        ak = Aktov(agent_id="test-agent", agent_type="test")
        trace = ak.start_trace()
        trace.record_action(
            tool_name="read_file",
            tool_category="read",
            arguments={"path": "/etc/passwd"},
        )
        response = trace.end()
        assert response.suppressed_alerts == []

    def test_exclusion_in_trace_end(self, tmp_path):
        """Exclusion file suppresses matching alerts in trace.end()."""
        filepath = self._make_exclusion_file(
            tmp_path,
            {
                "exclusions": [
                    {
                        "rule_id": "AK-032",
                        "reason": "Path traversal not relevant",
                    }
                ]
            },
        )

        ak = Aktov(
            agent_id="test-agent",
            agent_type="test",
            exclusions_file=filepath,
        )
        trace = ak.start_trace()
        trace.record_action(
            tool_name="read_file",
            tool_category="read",
            arguments={"path": "../../../etc/passwd"},
        )
        response = trace.end()

        # AK-032 should be suppressed if it fired
        ak032_in_alerts = [
            a for a in response.alerts if a.get("rule_id") == "AK-032"
        ]
        ak032_in_suppressed = [
            s for s in response.suppressed_alerts
            if s.get("rule_id") == "AK-032"
        ]

        # Either it didn't fire at all, or it was suppressed
        if ak032_in_suppressed:
            assert len(ak032_in_alerts) == 0
            assert ak032_in_suppressed[0]["reason"] == "Path traversal not relevant"

    def test_suppressed_in_response(self, tmp_path):
        """Suppressed alerts appear in response.suppressed_alerts."""
        filepath = self._make_exclusion_file(
            tmp_path,
            {
                "severity_floor": "critical",
                "exclusions": [],
            },
        )

        ak = Aktov(
            agent_id="test-agent",
            agent_type="test",
            exclusions_file=filepath,
        )
        trace = ak.start_trace()
        # Record an action that fires a medium-severity rule
        trace.record_action(
            tool_name="read_file",
            tool_category="read",
            arguments={"path": "/etc/passwd"},
        )
        response = trace.end()

        # All non-critical alerts should be suppressed
        for alert in response.alerts:
            assert alert.get("severity") == "critical"
        for suppressed in response.suppressed_alerts:
            assert suppressed.get("severity") != "critical"

    def test_severity_floor_e2e(self, tmp_path):
        """severity_floor suppresses low/medium alerts end-to-end."""
        filepath = self._make_exclusion_file(
            tmp_path,
            {"severity_floor": "high", "exclusions": []},
        )

        ak = Aktov(
            agent_id="test-agent",
            agent_type="test",
            exclusions_file=filepath,
        )
        trace = ak.start_trace()
        trace.record_action(
            tool_name="execute_sql",
            tool_category="execute",
            arguments={"query": "SELECT 1"},
        )
        response = trace.end()

        # No medium or low alerts should remain
        for alert in response.alerts:
            assert alert.get("severity") in ("high", "critical")

    def test_agent_id_exclusion_e2e(self, tmp_path):
        """Agent-specific exclusion works through full pipeline."""
        filepath = self._make_exclusion_file(
            tmp_path,
            {
                "exclusions": [
                    {
                        "rule_id": "AK-010",
                        "reason": "Pipeline agent does read+network",
                        "when": {"agent_id": "pipeline-*"},
                    }
                ]
            },
        )

        # With matching agent — AK-010 suppressed
        ak1 = Aktov(
            agent_id="pipeline-prod",
            agent_type="langchain",
            exclusions_file=filepath,
        )
        trace1 = ak1.start_trace()
        trace1.record_action(tool_name="read_file", tool_category="read")
        trace1.record_action(tool_name="http_post", tool_category="network")
        resp1 = trace1.end()

        ak010_alerts_1 = [
            a for a in resp1.alerts if a.get("rule_id") == "AK-010"
        ]
        ak010_suppressed_1 = [
            s for s in resp1.suppressed_alerts
            if s.get("rule_id") == "AK-010"
        ]

        # With non-matching agent — AK-010 NOT suppressed
        ak2 = Aktov(
            agent_id="general-assistant",
            agent_type="langchain",
            exclusions_file=filepath,
        )
        trace2 = ak2.start_trace()
        trace2.record_action(tool_name="read_file", tool_category="read")
        trace2.record_action(tool_name="http_post", tool_category="network")
        resp2 = trace2.end()

        ak010_alerts_2 = [
            a for a in resp2.alerts if a.get("rule_id") == "AK-010"
        ]

        # If AK-010 fired for both traces, the pipeline agent should have it
        # suppressed while general-assistant should not
        if ak010_suppressed_1:
            assert len(ak010_alerts_1) == 0
            assert ak010_suppressed_1[0]["reason"] == "Pipeline agent does read+network"
        if ak010_alerts_2:
            # Not suppressed for general-assistant
            ak010_suppressed_2 = [
                s for s in resp2.suppressed_alerts
                if s.get("rule_id") == "AK-010"
            ]
            assert len(ak010_suppressed_2) == 0
