"""LangChain callback handler integration for ChainWatch.

Automatically captures tool invocations from LangChain agents via the
standard callback mechanism.

Usage::

    from chainwatch.integrations.langchain import callback

    handler = callback(api_key="cw-...", agent_id="my-agent", agent_type="langchain")
    agent.run("do something", callbacks=[handler])
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional
from uuid import UUID

from chainwatch.client import ChainWatch, Trace

# Conditional import — LangChain may not be installed.
try:
    from langchain_core.callbacks import BaseCallbackHandler

    _HAS_LANGCHAIN = True
except ImportError:
    _HAS_LANGCHAIN = False

    # Provide a no-op base so the class definition doesn't fail at
    # import time when langchain_core isn't available.
    class BaseCallbackHandler:  # type: ignore[no-redef]
        """Stub base class when langchain_core is not installed."""
        pass


class ChainWatchCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that records tool calls via ChainWatch.

    This handler listens for ``on_tool_start`` and ``on_tool_end`` events
    and records each tool invocation through the active :class:`Trace`.
    """

    def __init__(
        self,
        client: ChainWatch,
        trace: Trace,
    ) -> None:
        if not _HAS_LANGCHAIN:
            raise ImportError(
                "langchain_core is required for the LangChain integration. "
                "Install it with: pip install langchain-core"
            )
        super().__init__()
        self._client = client
        self._trace = trace
        self._pending_starts: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Callback methods
    # ------------------------------------------------------------------

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
        inputs: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Record the start of a tool invocation."""
        tool_name = serialized.get("name", "unknown_tool")

        # Try to parse input_str as JSON for argument extraction
        arguments: dict[str, Any] | None = None
        if inputs is not None:
            arguments = inputs
        else:
            try:
                arguments = json.loads(input_str)
                if not isinstance(arguments, dict):
                    arguments = {"input": input_str}
            except (json.JSONDecodeError, TypeError):
                arguments = {"input": input_str}

        self._pending_starts[str(run_id)] = {
            "tool_name": tool_name,
            "arguments": arguments,
            "start_time": time.monotonic(),
        }

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Record the end of a tool invocation."""
        run_key = str(run_id)
        start_info = self._pending_starts.pop(run_key, None)

        if start_info is None:
            return

        latency_ms = (time.monotonic() - start_info["start_time"]) * 1000

        self._trace.record_action(
            tool_name=start_info["tool_name"],
            arguments=start_info["arguments"],
            outcome={"status": "success"},
            latency_ms=latency_ms,
        )

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Record a failed tool invocation."""
        run_key = str(run_id)
        start_info = self._pending_starts.pop(run_key, None)

        if start_info is None:
            return

        latency_ms = (time.monotonic() - start_info["start_time"]) * 1000

        self._trace.record_action(
            tool_name=start_info["tool_name"],
            arguments=start_info["arguments"],
            outcome={"status": "error", "error_class": "internal_error"},
            latency_ms=latency_ms,
        )


def callback(
    api_key: str,
    agent_id: str,
    agent_type: str = "langchain",
    **kwargs: Any,
) -> ChainWatchCallbackHandler:
    """Factory function that creates a ready-to-use callback handler.

    Parameters
    ----------
    api_key:
        ChainWatch API key.
    agent_id:
        Identifier for the agent being traced.
    agent_type:
        Agent framework type (default ``"langchain"``).
    **kwargs:
        Additional keyword arguments passed to :class:`ChainWatch`.

    Returns
    -------
    ChainWatchCallbackHandler
        A callback handler with an active trace.
    """
    client = ChainWatch(api_key=api_key, agent_id=agent_id, agent_type=agent_type, **kwargs)
    trace = client.start_trace(agent_id=agent_id, agent_type=agent_type)
    return ChainWatchCallbackHandler(client=client, trace=trace)
