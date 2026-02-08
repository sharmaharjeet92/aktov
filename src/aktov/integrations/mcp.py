"""MCP (Model Context Protocol) middleware for Aktov.

Wraps an MCP client to intercept ``CallToolRequest`` invocations and
record them as Aktov actions.

Usage::

    from aktov.integrations.mcp import middleware

    wrapped_client = middleware(mcp_client, api_key="ak_...", agent_id="mcp-agent")
    # Use wrapped_client as normal — tool calls are traced automatically.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from aktov.client import Aktov, Trace


class MCPTracingWrapper:
    """Wraps an MCP client to intercept and trace tool calls.

    Proxies all attribute access to the underlying MCP client, but
    intercepts ``call_tool`` to record each invocation through
    Aktov.
    """

    def __init__(
        self,
        mcp_client: Any,
        aktov_client: Aktov,
        trace: Trace,
    ) -> None:
        self._mcp_client = mcp_client
        self._cw_client = aktov_client
        self._trace = trace

    def __getattr__(self, name: str) -> Any:
        """Proxy attribute access to the wrapped MCP client."""
        return getattr(self._mcp_client, name)

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        """Intercept tool calls to record them via Aktov.

        Delegates to the underlying MCP client's ``call_tool`` and
        records timing, outcome, and semantic flags.
        """
        start = time.monotonic()
        error_occurred = False
        result = None

        try:
            result = await self._mcp_client.call_tool(name, arguments, **kwargs)
            return result
        except Exception:
            error_occurred = True
            raise
        finally:
            latency_ms = (time.monotonic() - start) * 1000
            outcome_status = "error" if error_occurred else "success"

            self._trace.record_action(
                tool_name=name,
                arguments=arguments,
                outcome={"status": outcome_status},
                latency_ms=latency_ms,
            )

    def end_trace(self) -> Any:
        """Finish the Aktov trace and submit it.

        Call this when the MCP session is complete.
        """
        return self._trace.end()

    async def end_trace_async(self) -> Any:
        """Async version of :py:meth:`end_trace`."""
        return await self._trace.end_async()


def middleware(
    mcp_client: Any,
    api_key: str,
    agent_id: str,
    *,
    agent_type: str = "mcp",
    declared_intent: str | None = None,
    **kwargs: Any,
) -> MCPTracingWrapper:
    """Wrap an MCP client with Aktov tracing.

    Parameters
    ----------
    mcp_client:
        The MCP client instance to wrap.
    api_key:
        Aktov API key.
    agent_id:
        Identifier for the agent.
    agent_type:
        Framework type (default ``"mcp"``).
    declared_intent:
        Optional intent declaration for the trace.
    **kwargs:
        Additional keyword arguments passed to :class:`Aktov`.

    Returns
    -------
    MCPTracingWrapper
        A wrapped client that traces tool calls automatically.
    """
    ak = Aktov(
        api_key=api_key,
        agent_id=agent_id,
        agent_type=agent_type,
        **kwargs,
    )
    trace = cw.start_trace(
        agent_id=agent_id,
        agent_type=agent_type,
        declared_intent=declared_intent,
    )
    return MCPTracingWrapper(mcp_client, cw, trace)
