"""Anthropic integration for ChainWatch.

Extracts tool_use blocks from Anthropic Messages API responses and
records them as ChainWatch actions.

Usage::

    from chainwatch import ChainWatch
    from chainwatch.integrations.anthropic import AnthropicTracer

    cw = ChainWatch(api_key="cw-...", agent_id="my-agent", agent_type="anthropic")
    tracer = AnthropicTracer(cw)

    with tracer.trace(declared_intent="summarize document") as t:
        response = anthropic_client.messages.create(...)
        tracer.record_tool_uses(response)
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Generator, Optional

from chainwatch.client import ChainWatch, Trace


class AnthropicTracer:
    """Traces Anthropic tool_use blocks through ChainWatch."""

    def __init__(self, client: ChainWatch) -> None:
        self._client = client
        self._active_trace: Trace | None = None

    @contextmanager
    def trace(
        self,
        *,
        agent_id: str | None = None,
        agent_type: str | None = None,
        task_id: str | None = None,
        declared_intent: str | None = None,
    ) -> Generator[Trace, None, None]:
        """Context manager that opens and closes a trace.

        The trace is automatically submitted when the context exits.
        """
        agent_type = agent_type or "anthropic"
        trace = self._client.start_trace(
            agent_id=agent_id,
            agent_type=agent_type,
            task_id=task_id,
            declared_intent=declared_intent,
        )
        self._active_trace = trace
        try:
            yield trace
        finally:
            trace.end()
            self._active_trace = None

    def record_tool_uses(
        self,
        response: Any,
        *,
        latency_ms: float | None = None,
    ) -> list[Any]:
        """Extract and record tool_use blocks from an Anthropic Messages response.

        Handles both object-style and dict-style responses.

        Parameters
        ----------
        response:
            An Anthropic Messages API response.
        latency_ms:
            Optional latency to attribute to each tool call.

        Returns
        -------
        list
            The recorded :class:`Action` objects.
        """
        if self._active_trace is None:
            raise RuntimeError(
                "No active trace. Use AnthropicTracer.trace() context manager first."
            )

        actions = []
        content_blocks = _get_content_blocks(response)

        for block in content_blocks:
            block_type = _get_block_type(block)
            if block_type != "tool_use":
                continue

            tool_name = _get_block_name(block)
            arguments = _get_block_input(block)

            if not isinstance(arguments, dict):
                arguments = {"value": arguments} if arguments else None

            action = self._active_trace.record_action(
                tool_name=tool_name,
                arguments=arguments,
                outcome={"status": "success"},
                latency_ms=latency_ms,
            )
            actions.append(action)

        return actions


# ---------------------------------------------------------------------------
# Response accessors — support both object and dict forms
# ---------------------------------------------------------------------------

def _get_content_blocks(response: Any) -> list[Any]:
    if isinstance(response, dict):
        return response.get("content", [])
    return getattr(response, "content", [])


def _get_block_type(block: Any) -> str:
    if isinstance(block, dict):
        return block.get("type", "")
    return getattr(block, "type", "")


def _get_block_name(block: Any) -> str:
    if isinstance(block, dict):
        return block.get("name", "unknown")
    return getattr(block, "name", "unknown")


def _get_block_input(block: Any) -> Any:
    if isinstance(block, dict):
        return block.get("input", None)
    return getattr(block, "input", None)
