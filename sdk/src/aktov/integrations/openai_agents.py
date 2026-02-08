"""OpenAI Agent SDK integration for Aktov.

Provides ``RunHooks`` that automatically capture tool invocations
from agents built with the ``openai-agents`` package.

Usage::

    from aktov.integrations.openai_agents import AktovHooks

    hooks = AktovHooks(aktov_agent_name="my-agent")
    result = await Runner.run(agent, input="...", hooks=hooks)
    response = hooks.end()  # → TraceResponse with alerts
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from aktov.client import Aktov
from aktov.schema import TraceResponse

logger = logging.getLogger("aktov")

# Conditional import — openai-agents may not be installed.
try:
    from agents import Agent, RunContextWrapper, RunHooks, Tool

    _HAS_AGENTS = True
except ImportError:
    _HAS_AGENTS = False

    # Provide stubs so the class definition doesn't fail at import time.
    class RunHooks:  # type: ignore[no-redef]
        """Stub base class when openai-agents is not installed."""
        pass

    RunContextWrapper = Any  # type: ignore[assignment,misc]
    Agent = Any  # type: ignore[assignment,misc]
    Tool = Any  # type: ignore[assignment,misc]


class AktovRunHooks(RunHooks):
    """OpenAI Agent SDK hooks that record tool calls via Aktov.

    Pass an instance to ``Runner.run(hooks=...)`` to automatically
    trace all tool invocations.

    Tool arguments are captured by wrapping each tool's ``on_invoke_tool``
    method on first use.  This happens transparently — no changes to
    user code are required.
    """

    def __init__(
        self,
        aktov_agent_name: str,
        *,
        api_key: str | None = None,
        agent_type: str = "openai-agents",
        **kwargs: Any,
    ) -> None:
        if not _HAS_AGENTS:
            raise ImportError(
                "openai-agents is required for the OpenAI Agent SDK integration. "
                "Install it with: pip install openai-agents"
            )
        super().__init__()
        self._client = Aktov(
            api_key=api_key,
            agent_id=aktov_agent_name,
            agent_type=agent_type,
            **kwargs,
        )
        self._trace = self._client.start_trace(
            agent_id=aktov_agent_name,
            agent_type=agent_type,
        )
        self._pending_starts: dict[str, float] = {}
        self._pending_args: dict[str, dict[str, Any] | None] = {}
        self._wrapped_tools: set[int] = set()  # track by id() to avoid re-wrapping

    def _wrap_tool(self, tool: Any) -> None:
        """Wrap a tool's on_invoke_tool to capture arguments.

        The OpenAI Agents SDK does not pass tool arguments to RunHooks
        callbacks.  This method intercepts on_invoke_tool to capture
        the JSON arguments before the tool executes, making them
        available for semantic flag extraction.
        """
        tool_id = id(tool)
        if tool_id in self._wrapped_tools:
            return
        if not hasattr(tool, "on_invoke_tool"):
            return

        original = tool.on_invoke_tool
        hooks_self = self
        tool_name = getattr(tool, "name", None) or str(tool)

        async def _wrapped_invoke(ctx: Any, args_json: str) -> Any:
            try:
                args = json.loads(args_json) if args_json else {}
                if not isinstance(args, dict):
                    args = {"value": args}
            except (json.JSONDecodeError, TypeError):
                args = None
            hooks_self._pending_args[tool_name] = args
            return await original(ctx, args_json)

        tool.on_invoke_tool = _wrapped_invoke
        self._wrapped_tools.add(tool_id)

    async def on_tool_start(
        self,
        context: Any,
        agent: Any,
        tool: Any,
    ) -> None:
        """Called when a tool is about to be invoked."""
        tool_name = getattr(tool, "name", None) or str(tool)
        self._pending_starts[tool_name] = time.monotonic()

        # Wrap on_invoke_tool to capture arguments (one-time per tool instance).
        # This fires before on_invoke_tool is called, so the wrapper is in
        # place when the runner invokes the tool.
        self._wrap_tool(tool)

    async def on_tool_end(
        self,
        context: Any,
        agent: Any,
        tool: Any,
        result: str,
    ) -> None:
        """Called after a tool finishes execution."""
        tool_name = getattr(tool, "name", None) or str(tool)
        start_time = self._pending_starts.pop(tool_name, None)
        latency_ms = (time.monotonic() - start_time) * 1000 if start_time else None

        # Read arguments captured by the on_invoke_tool wrapper
        arguments = self._pending_args.pop(tool_name, None)

        self._trace.record_action(
            tool_name=tool_name,
            arguments=arguments,
            outcome={"status": "success"},
            latency_ms=latency_ms,
        )

    def end(self) -> TraceResponse:
        """Finish the trace and return alerts.

        Call this after ``Runner.run()`` completes.
        """
        return self._trace.end()

    async def end_async(self) -> TraceResponse:
        """Async version of :py:meth:`end`."""
        return await self._trace.end_async()


# Convenience alias
AktovHooks = AktovRunHooks
