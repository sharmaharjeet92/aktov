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

import time
from typing import Any

from aktov.client import Aktov
from aktov.schema import TraceResponse

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

    async def on_tool_start(
        self,
        context: Any,
        agent: Any,
        tool: Any,
    ) -> None:
        """Called when a tool is about to be invoked."""
        tool_name = getattr(tool, "name", None) or str(tool)
        self._pending_starts[tool_name] = time.monotonic()

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

        # Extract arguments if available
        arguments: dict[str, Any] | None = None
        if hasattr(tool, "arguments"):
            arguments = tool.arguments if isinstance(tool.arguments, dict) else None

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
