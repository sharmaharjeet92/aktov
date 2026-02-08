"""Tests for framework integrations.

All tests mock framework dependencies — no actual LangChain/OpenAI/MCP
packages needed.
"""

import asyncio
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
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
        assert response.rules_evaluated == 3
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
        """on_tool_start + on_tool_end records action."""
        from aktov.integrations.openai_agents import AktovRunHooks

        hooks = AktovRunHooks(aktov_agent_name="test-agent")

        mock_tool = MagicMock()
        mock_tool.name = "search"
        mock_tool.arguments = {"query": "test"}

        await hooks.on_tool_start(None, None, mock_tool)
        await hooks.on_tool_end(None, None, mock_tool, "result")

        assert len(hooks._trace._actions) == 1
        assert hooks._trace._actions[0].tool_name == "search"

    async def test_end_returns_alerts(self) -> None:
        """hooks.end() evaluates rules and returns TraceResponse."""
        from aktov.integrations.openai_agents import AktovRunHooks

        hooks = AktovRunHooks(aktov_agent_name="test-agent")

        mock_tool = MagicMock()
        mock_tool.name = "read_file"
        mock_tool.arguments = {"path": "../../etc/passwd"}

        await hooks.on_tool_start(None, None, mock_tool)
        await hooks.on_tool_end(None, None, mock_tool, "contents")

        response = hooks.end()
        assert response.status == "evaluated"
        assert response.rules_evaluated == 3
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
    """Tests for the Claude Code PostToolUse hook."""

    def test_append_and_load_actions(self) -> None:
        """Actions can be appended and loaded from trace file."""
        from aktov.hooks.claude_code import _append_action, _load_session_actions

        with tempfile.TemporaryDirectory() as tmpdir:
            import aktov.hooks.claude_code as hook_mod
            original_dir = hook_mod.TRACES_DIR
            hook_mod.TRACES_DIR = Path(tmpdir)

            try:
                action1 = {"tool_name": "Read", "arguments": {"path": "/tmp/test"}}
                action2 = {"tool_name": "Edit", "arguments": {"path": "/tmp/test"}}

                trace_file = _append_action("test-session", action1)
                _append_action("test-session", action2)

                loaded = _load_session_actions(trace_file)
                assert len(loaded) == 2
                assert loaded[0]["tool_name"] == "Read"
                assert loaded[1]["tool_name"] == "Edit"
            finally:
                hook_mod.TRACES_DIR = original_dir

    def test_evaluate_and_alert(self, capsys: pytest.CaptureFixture) -> None:
        """_evaluate_and_alert prints alerts to stderr."""
        from aktov.hooks.claude_code import _evaluate_and_alert

        actions = [
            {"tool_name": "read_file", "arguments": {"path": "../../etc/passwd"}},
        ]

        _evaluate_and_alert("test-agent", actions)

        captured = capsys.readouterr()
        assert "AK-032" in captured.err
        assert "PATH_TRAVERSAL" in captured.err or "path_traversal" in captured.err.lower()

    def test_session_id_stable_within_process(self) -> None:
        """_get_session_id returns consistent value within same process."""
        from aktov.hooks.claude_code import _get_session_id

        id1 = _get_session_id()
        id2 = _get_session_id()
        assert id1 == id2


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
