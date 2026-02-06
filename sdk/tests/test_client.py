"""Tests for chainwatch.client — ChainWatch client and Trace."""

import pytest

from chainwatch.client import ChainWatch, Trace
from chainwatch.schema import ActionOutcome, SemanticFlags


@pytest.fixture
def safe_client() -> ChainWatch:
    return ChainWatch(
        api_key="test-key",
        mode="safe",
        agent_id="test-agent",
        agent_type="test",
    )


@pytest.fixture
def debug_client() -> ChainWatch:
    return ChainWatch(
        api_key="test-key",
        mode="debug",
        agent_id="test-agent",
        agent_type="test",
    )


class TestChainWatchInit:
    """Tests for ChainWatch initialization."""

    def test_default_mode_is_safe(self) -> None:
        cw = ChainWatch(api_key="key", agent_id="a", agent_type="t")
        assert cw._mode == "safe"

    def test_invalid_mode_raises(self) -> None:
        with pytest.raises(ValueError, match="mode must be"):
            ChainWatch(api_key="key", mode="invalid")

    def test_base_url_trailing_slash_stripped(self) -> None:
        cw = ChainWatch(api_key="key", base_url="https://api.example.com/")
        assert cw._base_url == "https://api.example.com"


class TestStartTrace:
    """Tests for ChainWatch.start_trace."""

    def test_returns_trace(self, safe_client: ChainWatch) -> None:
        trace = safe_client.start_trace()
        assert isinstance(trace, Trace)

    def test_requires_agent_id(self) -> None:
        cw = ChainWatch(api_key="key")
        with pytest.raises(ValueError, match="agent_id"):
            cw.start_trace()

    def test_requires_agent_type(self) -> None:
        cw = ChainWatch(api_key="key", agent_id="a")
        with pytest.raises(ValueError, match="agent_type"):
            cw.start_trace()

    def test_override_at_trace_level(self) -> None:
        cw = ChainWatch(api_key="key", agent_id="a", agent_type="t")
        trace = cw.start_trace(agent_id="b", agent_type="u")
        assert trace._agent_id == "b"
        assert trace._agent_type == "u"


class TestTraceRecordAction:
    """Tests for Trace.record_action."""

    def test_safe_mode_strips_arguments(self, safe_client: ChainWatch) -> None:
        trace = safe_client.start_trace()
        action = trace.record_action(
            tool_name="read_file",
            arguments={"path": "/etc/passwd"},
        )
        # In SAFE mode, arguments should be None on the recorded action
        assert action.arguments is None

    def test_debug_mode_keeps_arguments(self, debug_client: ChainWatch) -> None:
        trace = debug_client.start_trace()
        action = trace.record_action(
            tool_name="read_file",
            arguments={"path": "/etc/passwd"},
        )
        assert action.arguments == {"path": "/etc/passwd"}

    def test_auto_infers_tool_category(self, safe_client: ChainWatch) -> None:
        trace = safe_client.start_trace()
        action = trace.record_action(tool_name="read_file")
        assert action.tool_category == "read"

    def test_explicit_tool_category(self, safe_client: ChainWatch) -> None:
        trace = safe_client.start_trace()
        action = trace.record_action(tool_name="custom_tool", tool_category="network")
        assert action.tool_category == "network"

    def test_unknown_tool_defaults_to_execute(self, safe_client: ChainWatch) -> None:
        trace = safe_client.start_trace()
        action = trace.record_action(tool_name="mystery_function_xyz")
        assert action.tool_category == "execute"

    def test_semantic_flags_extracted_automatically(self, safe_client: ChainWatch) -> None:
        trace = safe_client.start_trace()
        action = trace.record_action(
            tool_name="execute_sql",
            arguments={"query": "SELECT * FROM users"},
        )
        assert action.semantic_flags.sql_statement_type == "SELECT"

    def test_semantic_flags_for_http(self, safe_client: ChainWatch) -> None:
        trace = safe_client.start_trace()
        action = trace.record_action(
            tool_name="http_request",
            arguments={"method": "POST", "url": "https://api.example.com"},
        )
        assert action.semantic_flags.http_method == "POST"
        assert action.semantic_flags.is_external is True
        assert action.semantic_flags.has_network_calls is True

    def test_sensitive_dir_detection(self, safe_client: ChainWatch) -> None:
        trace = safe_client.start_trace()
        action = trace.record_action(
            tool_name="read_file",
            arguments={"path": "/home/user/.ssh/id_rsa"},
        )
        assert action.semantic_flags.sensitive_dir_match is True

    def test_path_traversal_detection(self, safe_client: ChainWatch) -> None:
        trace = safe_client.start_trace()
        action = trace.record_action(
            tool_name="read_file",
            arguments={"path": "../../etc/passwd"},
        )
        assert action.semantic_flags.path_traversal_detected is True

    def test_sequence_index_increments(self, safe_client: ChainWatch) -> None:
        trace = safe_client.start_trace()
        a1 = trace.record_action(tool_name="read_file")
        a2 = trace.record_action(tool_name="write_file")
        a3 = trace.record_action(tool_name="delete_file")
        assert a1.sequence_index == 0
        assert a2.sequence_index == 1
        assert a3.sequence_index == 2

    def test_outcome_as_dict(self, safe_client: ChainWatch) -> None:
        trace = safe_client.start_trace()
        action = trace.record_action(
            tool_name="http_request",
            outcome={"status": "error", "error_class": "timeout"},
        )
        assert action.outcome is not None
        assert action.outcome.status == "error"
        assert action.outcome.error_class == "timeout"

    def test_outcome_as_model(self, safe_client: ChainWatch) -> None:
        trace = safe_client.start_trace()
        outcome = ActionOutcome(status="success")
        action = trace.record_action(
            tool_name="read_file",
            outcome=outcome,
        )
        assert action.outcome is not None
        assert action.outcome.status == "success"

    def test_latency_recorded(self, safe_client: ChainWatch) -> None:
        trace = safe_client.start_trace()
        action = trace.record_action(tool_name="read_file", latency_ms=15.7)
        assert action.latency_ms == 15.7

    def test_none_arguments_gives_empty_flags(self, safe_client: ChainWatch) -> None:
        trace = safe_client.start_trace()
        action = trace.record_action(tool_name="read_file")
        assert action.semantic_flags == SemanticFlags()


class TestCustomToolMap:
    """Tests for custom tool category mapping."""

    def test_custom_map_used(self) -> None:
        cw = ChainWatch(
            api_key="key",
            agent_id="a",
            agent_type="t",
            custom_tool_map={"my_special_reader": "read"},
        )
        trace = cw.start_trace()
        action = trace.record_action(tool_name="my_special_reader")
        assert action.tool_category == "read"

    def test_custom_map_overrides_default(self) -> None:
        cw = ChainWatch(
            api_key="key",
            agent_id="a",
            agent_type="t",
            custom_tool_map={"read_file": "credential"},
        )
        trace = cw.start_trace()
        action = trace.record_action(tool_name="read_file")
        assert action.tool_category == "credential"


class TestTraceBuildPayload:
    """Tests for Trace._build_payload (payload construction)."""

    def test_safe_mode_payload_valid(self, safe_client: ChainWatch) -> None:
        trace = safe_client.start_trace(declared_intent="test intent")
        trace.record_action(tool_name="read_file", arguments={"path": "/tmp/f"})
        trace.record_action(tool_name="write_file", arguments={"path": "/tmp/g"})

        payload = trace._build_payload()
        assert payload.mode == "safe"
        assert payload.agent_id == "test-agent"
        assert payload.declared_intent == "test intent"
        assert len(payload.actions) == 2
        # All arguments should be stripped
        for action in payload.actions:
            assert action.arguments is None

    def test_debug_mode_payload_keeps_args(self, debug_client: ChainWatch) -> None:
        trace = debug_client.start_trace()
        trace.record_action(tool_name="read_file", arguments={"path": "/tmp/f"})

        payload = trace._build_payload()
        assert payload.mode == "debug"
        assert payload.actions[0].arguments == {"path": "/tmp/f"}


class TestHardeningDefaults:
    """Tests for SDK hardening: timeout, max_actions, fire-and-forget."""

    def test_default_timeout_500ms(self, safe_client: ChainWatch) -> None:
        assert safe_client._timeout_ms == 500

    def test_default_max_actions_200(self, safe_client: ChainWatch) -> None:
        assert safe_client._max_actions == 200

    def test_default_raise_on_error_false(self, safe_client: ChainWatch) -> None:
        assert safe_client._raise_on_error is False

    def test_custom_timeout(self) -> None:
        cw = ChainWatch(api_key="k", agent_id="a", agent_type="t", timeout_ms=1000)
        assert cw._timeout_ms == 1000

    def test_max_actions_drops_overflow(self, safe_client: ChainWatch) -> None:
        safe_client._max_actions = 3
        trace = safe_client.start_trace()
        trace.record_action(tool_name="read_file")
        trace.record_action(tool_name="write_file")
        trace.record_action(tool_name="delete_file")
        # 4th action should be dropped
        overflow = trace.record_action(tool_name="http_get")
        assert len(trace._actions) == 3
        assert overflow.tool_name == "http_get"  # stub returned

    def test_max_actions_counter_keeps_incrementing(self, safe_client: ChainWatch) -> None:
        safe_client._max_actions = 2
        trace = safe_client.start_trace()
        trace.record_action(tool_name="a")
        trace.record_action(tool_name="b")
        overflow = trace.record_action(tool_name="c")
        assert overflow.sequence_index == 2  # counter still increments


class TestAgentFingerprint:
    """Tests for agent fingerprint computation."""

    def test_fingerprint_computed(self, safe_client: ChainWatch) -> None:
        trace = safe_client.start_trace()
        trace.record_action(tool_name="read_file")
        trace.record_action(tool_name="write_file")
        payload = trace._build_payload()
        assert payload.agent_fingerprint is not None
        assert len(payload.agent_fingerprint) == 24

    def test_fingerprint_stable_across_order(self, safe_client: ChainWatch) -> None:
        trace1 = safe_client.start_trace()
        trace1.record_action(tool_name="read_file")
        trace1.record_action(tool_name="write_file")

        trace2 = safe_client.start_trace()
        trace2.record_action(tool_name="write_file")
        trace2.record_action(tool_name="read_file")

        p1 = trace1._build_payload()
        p2 = trace2._build_payload()
        assert p1.agent_fingerprint == p2.agent_fingerprint

    def test_fingerprint_differs_by_tools(self, safe_client: ChainWatch) -> None:
        trace1 = safe_client.start_trace()
        trace1.record_action(tool_name="read_file")

        trace2 = safe_client.start_trace()
        trace2.record_action(tool_name="write_file")

        p1 = trace1._build_payload()
        p2 = trace2._build_payload()
        assert p1.agent_fingerprint != p2.agent_fingerprint

    def test_fingerprint_includes_framework(self) -> None:
        cw = ChainWatch(
            api_key="k", agent_id="a", agent_type="t", framework="langchain"
        )
        trace = cw.start_trace()
        trace.record_action(tool_name="read_file")
        p = trace._build_payload()

        cw2 = ChainWatch(
            api_key="k", agent_id="a", agent_type="t", framework="openai"
        )
        trace2 = cw2.start_trace()
        trace2.record_action(tool_name="read_file")
        p2 = trace2._build_payload()

        assert p.agent_fingerprint != p2.agent_fingerprint
