"""OpenAI integration for ChainWatch.

Extracts tool calls from OpenAI ChatCompletion responses and records
them as ChainWatch actions.

Usage::

    from chainwatch import ChainWatch
    from chainwatch.integrations.openai import OpenAITracer

    cw = ChainWatch(api_key="cw-...", agent_id="my-agent", agent_type="openai")
    tracer = OpenAITracer(cw)

    with tracer.trace(declared_intent="answer user question") as t:
        response = openai_client.chat.completions.create(...)
        tracer.record_tool_calls(response)
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from typing import Any, Generator, Optional

from chainwatch.client import ChainWatch, Trace


class OpenAITracer:
    """Traces OpenAI ChatCompletion tool calls through ChainWatch."""

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

        Yields the active :class:`Trace` for manual ``record_action``
        calls if needed.
        """
        agent_type = agent_type or "openai"
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

    def record_tool_calls(
        self,
        response: Any,
        *,
        latency_ms: float | None = None,
    ) -> list[Any]:
        """Extract and record tool calls from an OpenAI ChatCompletion response.

        Handles both the object-style response (``response.choices``) and
        plain dict responses.

        Parameters
        ----------
        response:
            An OpenAI ChatCompletion response (object or dict).
        latency_ms:
            Optional latency to attribute to each tool call.

        Returns
        -------
        list
            The recorded :class:`Action` objects.
        """
        if self._active_trace is None:
            raise RuntimeError(
                "No active trace. Use OpenAITracer.trace() context manager first."
            )

        actions = []
        choices = _get_choices(response)

        for choice in choices:
            message = _get_message(choice)
            tool_calls = _get_tool_calls(message)

            for tc in tool_calls:
                tool_name = _get_function_name(tc)
                raw_args = _get_function_arguments(tc)

                # Parse JSON arguments
                arguments: dict[str, Any] | None = None
                if raw_args:
                    try:
                        arguments = json.loads(raw_args)
                        if not isinstance(arguments, dict):
                            arguments = {"value": arguments}
                    except (json.JSONDecodeError, TypeError):
                        arguments = {"raw": raw_args}

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

def _get_choices(response: Any) -> list[Any]:
    if isinstance(response, dict):
        return response.get("choices", [])
    return getattr(response, "choices", [])


def _get_message(choice: Any) -> Any:
    if isinstance(choice, dict):
        return choice.get("message", {})
    return getattr(choice, "message", None) or {}


def _get_tool_calls(message: Any) -> list[Any]:
    if isinstance(message, dict):
        return message.get("tool_calls", []) or []
    return getattr(message, "tool_calls", []) or []


def _get_function_name(tool_call: Any) -> str:
    if isinstance(tool_call, dict):
        fn = tool_call.get("function", {})
        return fn.get("name", "unknown")
    fn = getattr(tool_call, "function", None)
    if fn is None:
        return "unknown"
    return getattr(fn, "name", "unknown")


def _get_function_arguments(tool_call: Any) -> str:
    if isinstance(tool_call, dict):
        fn = tool_call.get("function", {})
        return fn.get("arguments", "")
    fn = getattr(tool_call, "function", None)
    if fn is None:
        return ""
    return getattr(fn, "arguments", "")
