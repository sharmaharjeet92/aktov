"""Tests for aktov.schema — Pydantic models for canonical traces."""

from datetime import datetime

import pytest
from aktov.schema import (
    Action,
    ActionOutcome,
    SemanticFlags,
    TracePayload,
    TraceResponse,
)


class TestSemanticFlags:
    """Tests for the SemanticFlags model."""

    def test_default_all_none(self) -> None:
        flags = SemanticFlags()
        assert flags.sql_statement_type is None
        assert flags.http_method is None
        assert flags.is_external is None
        assert flags.sensitive_dir_match is None
        assert flags.has_network_calls is None
        assert flags.argument_size_bucket is None
        assert flags.path_traversal_detected is None

    def test_serialization_round_trip(self) -> None:
        flags = SemanticFlags(
            sql_statement_type="SELECT",
            http_method="POST",
            is_external=True,
            sensitive_dir_match=False,
            has_network_calls=True,
            argument_size_bucket="medium",
            path_traversal_detected=False,
        )
        data = flags.model_dump()
        restored = SemanticFlags(**data)
        assert restored == flags

    def test_json_serialization(self) -> None:
        flags = SemanticFlags(sql_statement_type="INSERT")
        json_str = flags.model_dump_json()
        assert '"INSERT"' in json_str

    def test_rejects_invalid_sql_type(self) -> None:
        with pytest.raises(Exception):
            SemanticFlags(sql_statement_type="INVALID_TYPE")

    def test_rejects_invalid_http_method(self) -> None:
        with pytest.raises(Exception):
            SemanticFlags(http_method="FETCH")


class TestActionOutcome:
    """Tests for the ActionOutcome model."""

    def test_success_outcome(self) -> None:
        outcome = ActionOutcome(status="success")
        assert outcome.status == "success"
        assert outcome.error_class is None

    def test_error_outcome(self) -> None:
        outcome = ActionOutcome(
            status="error",
            error_class="permission_denied",
            response_size_bucket="small",
        )
        assert outcome.status == "error"
        assert outcome.error_class == "permission_denied"


class TestAction:
    """Tests for the Action model."""

    def test_minimal_action(self) -> None:
        action = Action(
            sequence_index=0,
            tool_name="read_file",
            tool_category="read",
        )
        assert action.sequence_index == 0
        assert action.tool_name == "read_file"
        assert action.tool_category == "read"
        assert action.arguments is None
        assert action.outcome is None
        assert isinstance(action.timestamp, datetime)

    def test_action_with_all_fields(self) -> None:
        action = Action(
            sequence_index=1,
            tool_name="execute_sql",
            tool_category="read",
            semantic_flags=SemanticFlags(sql_statement_type="SELECT"),
            arguments={"query": "SELECT 1"},
            outcome=ActionOutcome(status="success"),
            latency_ms=42.5,
        )
        assert action.semantic_flags.sql_statement_type == "SELECT"
        assert action.arguments == {"query": "SELECT 1"}
        assert action.latency_ms == 42.5


class TestTracePayload:
    """Tests for the TracePayload model."""

    def test_safe_mode_rejects_raw_args(self) -> None:
        """SAFE mode must reject actions that contain raw arguments."""
        action_with_args = Action(
            sequence_index=0,
            tool_name="read_file",
            tool_category="read",
            arguments={"path": "/etc/passwd"},
        )
        with pytest.raises(ValueError, match="SAFE mode violation"):
            TracePayload(
                agent_id="test-agent",
                agent_type="test",
                mode="safe",
                actions=[action_with_args],
            )

    def test_safe_mode_accepts_no_args(self) -> None:
        """SAFE mode should accept actions without raw arguments."""
        action_no_args = Action(
            sequence_index=0,
            tool_name="read_file",
            tool_category="read",
        )
        payload = TracePayload(
            agent_id="test-agent",
            agent_type="test",
            mode="safe",
            actions=[action_no_args],
        )
        assert payload.mode == "safe"
        assert len(payload.actions) == 1

    def test_debug_mode_allows_raw_args(self) -> None:
        """DEBUG mode should accept actions with raw arguments."""
        action_with_args = Action(
            sequence_index=0,
            tool_name="read_file",
            tool_category="read",
            arguments={"path": "/etc/passwd"},
        )
        payload = TracePayload(
            agent_id="test-agent",
            agent_type="test",
            mode="debug",
            actions=[action_with_args],
        )
        assert payload.mode == "debug"
        assert payload.actions[0].arguments is not None

    def test_payload_default_session_id(self) -> None:
        payload = TracePayload(
            agent_id="test-agent",
            agent_type="test",
        )
        assert payload.session_id is not None
        assert len(payload.session_id) > 0

    def test_payload_json_serialization(self) -> None:
        payload = TracePayload(
            agent_id="test-agent",
            agent_type="test",
            mode="safe",
            declared_intent="test run",
        )
        json_str = payload.model_dump_json()
        assert "test-agent" in json_str
        assert "safe" in json_str


class TestTraceResponse:
    """Tests for the TraceResponse model."""

    def test_minimal_response(self) -> None:
        resp = TraceResponse(trace_id="tr-123")
        assert resp.trace_id == "tr-123"
        assert resp.rules_evaluated == 0
        assert resp.alerts == []

    def test_response_with_alerts(self) -> None:
        resp = TraceResponse(
            trace_id="tr-456",
            rules_evaluated=5,
            alerts=[{"rule_id": "AK-001", "severity": "high"}],
        )
        assert resp.rules_evaluated == 5
        assert len(resp.alerts) == 1
