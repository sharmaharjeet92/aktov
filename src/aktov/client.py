"""Aktov client — the main entry point for instrumenting AI agents.

Usage::

    from aktov import Aktov

    ak = Aktov(agent_id="my-agent", agent_type="langchain")
    trace = ak.start_trace(declared_intent="answer user question")

    trace.record_action(
        tool_name="execute_sql",
        arguments={"query": "SELECT * FROM users"},
        outcome={"status": "success"},
        latency_ms=42.0,
    )

    response = trace.end()
    print(response.alerts)  # local rule evaluation results
"""

from __future__ import annotations

import asyncio
import atexit
import hashlib
import logging
import queue
import threading
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

import httpx

from aktov.canonicalization import infer_tool_category
from aktov.rules.engine import RuleEngine
from aktov.rules.exclusions import ExclusionConfig, apply_exclusions, load_exclusions
from aktov.schema import (
    Action,
    ActionOutcome,
    SemanticFlags,
    TracePayload,
    TraceResponse,
)
from aktov.semantic_flags import extract_semantic_flags

logger = logging.getLogger("aktov")


# ---------------------------------------------------------------------------
# Background sender
# ---------------------------------------------------------------------------

class _BackgroundSender:
    """Bounded-queue background sender with daemon thread.

    Payloads are enqueued from the caller thread and sent by a daemon
    worker.  When the queue is full, new payloads are dropped (never
    blocks the caller).  On interpreter shutdown the worker does a
    best-effort flush of remaining items.
    """

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        timeout_ms: int,
        queue_size: int,
        flush_interval_ms: int,
    ) -> None:
        self._base_url = base_url
        self._api_key = api_key
        self._timeout_s = timeout_ms / 1000.0
        self._flush_interval_s = flush_interval_ms / 1000.0
        self._queue: queue.Queue[TracePayload | None] = queue.Queue(maxsize=queue_size)
        self._stop = threading.Event()

        # Metrics
        self.sent_count = 0
        self.dropped_count = 0
        self.error_count = 0
        self.last_error: str | None = None

        self._thread = threading.Thread(target=self._worker, daemon=True, name="aktov-bg")
        self._thread.start()
        atexit.register(self.shutdown)

    def enqueue(self, payload: TracePayload) -> bool:
        """Enqueue a payload for async sending. Returns False if dropped."""
        try:
            self._queue.put_nowait(payload)
            return True
        except queue.Full:
            self.dropped_count += 1
            logger.warning(
                "Aktov background queue full, dropping trace (dropped=%d)",
                self.dropped_count,
            )
            return False

    def shutdown(self) -> None:
        """Signal the worker to stop and do a best-effort flush."""
        self._stop.set()
        try:
            self._queue.put_nowait(None)  # sentinel to wake worker
        except queue.Full:
            pass  # worker will see _stop flag on next iteration
        self._thread.join(timeout=2.0)

    def _worker(self) -> None:
        """Worker loop: drain queue and send payloads."""
        url = f"{self._base_url}/v1/traces"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "User-Agent": "aktov-python/0.2.0",
        }

        while not self._stop.is_set():
            try:
                payload = self._queue.get(timeout=self._flush_interval_s)
            except queue.Empty:
                continue

            if payload is None:  # shutdown sentinel
                break

            self._send_one(payload, url, headers)

        # Best-effort flush remaining items
        while not self._queue.empty():
            try:
                payload = self._queue.get_nowait()
            except queue.Empty:
                break
            if payload is None:
                continue
            self._send_one(payload, url, headers)

    def _send_one(self, payload: TracePayload, url: str, headers: dict) -> None:
        try:
            with httpx.Client(timeout=self._timeout_s) as http:
                resp = http.post(url, content=payload.model_dump_json(), headers=headers)
                resp.raise_for_status()
            self.sent_count += 1
        except Exception as exc:
            self.error_count += 1
            self.last_error = str(exc)
            logger.warning("Aktov background send failed: %s", exc)


# ---------------------------------------------------------------------------
# Trace
# ---------------------------------------------------------------------------

class Trace:
    """Represents an in-progress trace — a sequence of tool actions.

    Create via :py:meth:`Aktov.start_trace`; do not instantiate
    directly.
    """

    def __init__(
        self,
        *,
        client: Aktov,
        agent_id: str,
        agent_type: str,
        task_id: str | None = None,
        session_id: str | None = None,
        declared_intent: str | None = None,
    ) -> None:
        self._client = client
        self._agent_id = agent_id
        self._agent_type = agent_type
        self._task_id = task_id
        self._session_id = session_id or str(uuid.uuid4())
        self._declared_intent = declared_intent
        self._actions: list[Action] = []
        self._sequence_counter = 0

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_action(
        self,
        tool_name: str,
        *,
        tool_category: str | None = None,
        arguments: dict[str, Any] | None = None,
        outcome: dict[str, Any] | ActionOutcome | None = None,
        latency_ms: float | None = None,
    ) -> Action:
        """Record a single tool invocation in this trace.

        * ``tool_category`` is auto-inferred from ``tool_name`` when omitted.
        * Semantic flags are always extracted from ``arguments``.
        * In **SAFE** mode the raw ``arguments`` are stripped before storage.
        """
        # Check max_actions cap
        if self._sequence_counter >= self._client._max_actions:
            logger.warning(
                "Aktov max_actions (%d) reached, dropping '%s'",
                self._client._max_actions,
                tool_name,
            )
            return Action(
                sequence_index=self._sequence_counter,
                tool_name=tool_name,
                tool_category=tool_category or "execute",
                semantic_flags=SemanticFlags(),
                timestamp=datetime.now(UTC),
            )

        # Auto-infer category
        resolved_category = tool_category or infer_tool_category(
            tool_name, self._client._custom_tool_map
        )
        # Clamp to valid literals
        valid_categories = {
            "read", "write", "execute", "network", "credential", "pii", "delete",
        }
        if resolved_category not in valid_categories:
            resolved_category = "execute"

        # Extract semantic flags from raw arguments
        flags = extract_semantic_flags(tool_name, resolved_category, arguments)

        # Build outcome model
        outcome_model: ActionOutcome | None = None
        if outcome is not None:
            if isinstance(outcome, ActionOutcome):
                outcome_model = outcome
            elif isinstance(outcome, dict):
                outcome_model = ActionOutcome(**outcome)

        # Build the action
        action = Action(
            sequence_index=self._sequence_counter,
            tool_name=tool_name,
            tool_category=resolved_category,  # type: ignore[arg-type]
            semantic_flags=flags,
            arguments=arguments if self._client._mode == "debug" else None,
            outcome=outcome_model,
            timestamp=datetime.now(UTC),
            latency_ms=latency_ms,
        )

        self._actions.append(action)
        self._sequence_counter += 1
        return action

    # ------------------------------------------------------------------
    # Submission
    # ------------------------------------------------------------------

    def _build_payload(self) -> TracePayload:
        """Build and validate the trace payload."""
        # Compute agent fingerprint
        tool_names = sorted({a.tool_name for a in self._actions})
        fingerprint_parts = tool_names + [self._agent_type]
        if self._client._framework:
            fingerprint_parts.append(self._client._framework)
        fingerprint_input = "|".join(fingerprint_parts)
        fingerprint = hashlib.sha256(fingerprint_input.encode()).hexdigest()[:24]

        return TracePayload(
            agent_id=self._agent_id,
            agent_type=self._agent_type,
            task_id=self._task_id,
            session_id=self._session_id,
            declared_intent=self._declared_intent,
            mode=self._client._mode,
            actions=self._actions,
            agent_fingerprint=fingerprint,
        )

    def _evaluate_locally(
        self, payload: TracePayload,
    ) -> tuple[list[dict], list[dict], int]:
        """Evaluate the payload against local rules and apply exclusions.

        Returns (alert_dicts, suppressed_dicts, rules_evaluated_count).
        """
        engine = self._client._get_rule_engine()
        alerts = engine.evaluate(payload)

        # Apply exclusion filter
        exclusion_config = self._client._get_exclusion_config()
        if exclusion_config is not None:
            alerts, suppressed = apply_exclusions(
                alerts, exclusion_config, payload.agent_id, payload.actions,
            )
            suppressed_dicts = [asdict(s) for s in suppressed]
        else:
            suppressed_dicts = []

        alert_dicts = [asdict(a) for a in alerts]
        return alert_dicts, suppressed_dicts, len(engine._rules)

    def end(self) -> TraceResponse:
        """Finish the trace, evaluate local rules, and optionally submit to cloud.

        Always evaluates bundled (or custom) rules locally and returns
        alerts immediately.  When an ``api_key`` is configured, the trace
        is also sent to the Aktov cloud API as a best-effort side effect.

        Returns a :class:`TraceResponse` with local alerts populated.
        """
        payload = self._build_payload()

        # Local rule evaluation (always runs)
        alert_dicts, suppressed_dicts, rules_count = self._evaluate_locally(payload)

        # Background mode: evaluate locally, enqueue for cloud, return immediately
        if self._client._bg_sender is not None:
            accepted = self._client._bg_sender.enqueue(payload)
            return TraceResponse(
                status="queued" if accepted else "dropped",
                rules_evaluated=rules_count,
                alerts=alert_dicts,
                suppressed_alerts=suppressed_dicts,
            )

        # No cloud submission if no API key — local only
        if self._client._api_key is None:
            return TraceResponse(
                status="evaluated",
                rules_evaluated=rules_count,
                alerts=alert_dicts,
                suppressed_alerts=suppressed_dicts,
            )

        # Cloud submission (best-effort, fire-and-forget)
        try:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, self._submit_async(payload))
                    cloud_resp = future.result()
            else:
                cloud_resp = asyncio.run(self._submit_async(payload))

            # Merge: cloud trace_id + local alerts
            return TraceResponse(
                trace_id=cloud_resp.trace_id,
                status="sent",
                rules_evaluated=rules_count,
                alerts=alert_dicts,
                suppressed_alerts=suppressed_dicts,
            )
        except Exception as exc:
            if self._client._raise_on_error:
                raise
            logger.warning("Aktov cloud submit failed (local alerts still returned): %s", exc)
            return TraceResponse(
                status="evaluated",
                rules_evaluated=rules_count,
                alerts=alert_dicts,
                suppressed_alerts=suppressed_dicts,
                error_code=type(exc).__name__,
            )

    async def end_async(self) -> TraceResponse:
        """Async version of :py:meth:`end`."""
        payload = self._build_payload()

        # Local rule evaluation (always runs)
        alert_dicts, suppressed_dicts, rules_count = self._evaluate_locally(payload)

        # Background mode: evaluate locally, enqueue for cloud, return immediately
        if self._client._bg_sender is not None:
            accepted = self._client._bg_sender.enqueue(payload)
            return TraceResponse(
                status="queued" if accepted else "dropped",
                rules_evaluated=rules_count,
                alerts=alert_dicts,
                suppressed_alerts=suppressed_dicts,
            )

        # No cloud submission if no API key — local only
        if self._client._api_key is None:
            return TraceResponse(
                status="evaluated",
                rules_evaluated=rules_count,
                alerts=alert_dicts,
                suppressed_alerts=suppressed_dicts,
            )

        # Cloud submission (best-effort)
        try:
            cloud_resp = await self._submit_async(payload)
            return TraceResponse(
                trace_id=cloud_resp.trace_id,
                status="sent",
                rules_evaluated=rules_count,
                alerts=alert_dicts,
                suppressed_alerts=suppressed_dicts,
            )
        except Exception as exc:
            if self._client._raise_on_error:
                raise
            logger.warning("Aktov cloud submit failed (local alerts still returned): %s", exc)
            return TraceResponse(
                status="evaluated",
                rules_evaluated=rules_count,
                alerts=alert_dicts,
                suppressed_alerts=suppressed_dicts,
                error_code=type(exc).__name__,
            )

    async def _submit_async(self, payload: TracePayload) -> TraceResponse:
        """POST the trace payload to the cloud API."""
        url = f"{self._client._base_url}/v1/traces"
        headers = {
            "Authorization": f"Bearer {self._client._api_key}",
            "Content-Type": "application/json",
            "User-Agent": "aktov-python/0.2.0",
        }

        timeout = self._client._timeout_ms / 1000.0

        async with httpx.AsyncClient(timeout=timeout) as http:
            response = await http.post(
                url,
                content=payload.model_dump_json(),
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()
            return TraceResponse(
                trace_id=data.get("trace_id"),
                status="sent",
                rules_evaluated=data.get("rules_evaluated", 0),
                alerts=data.get("alerts", []),
            )


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class Aktov:
    """Top-level Aktov client.

    Parameters
    ----------
    api_key:
        API key for the Aktov cloud service.  Optional — when omitted,
        traces are evaluated locally against bundled rules only.
    mode:
        ``"safe"`` (default) strips raw arguments; ``"debug"`` keeps them.
    base_url:
        API base URL.
    agent_id:
        Default agent identifier (can be overridden per trace).
    agent_type:
        Default agent framework type (can be overridden per trace).
    custom_tool_map:
        Optional mapping of tool names -> categories that takes precedence
        over the built-in map.
    timeout_ms:
        HTTP POST timeout in milliseconds. Default 500ms.
    max_actions:
        Maximum actions per trace. Excess actions are silently dropped.
    raise_on_error:
        If True, trace.end() raises on submission failure.
        If False (default), returns a stub response (fire-and-forget).
    framework:
        Framework name (e.g., "langchain") included in agent fingerprint.
    background:
        If True, trace.end() enqueues payloads to a background thread
        and returns immediately with status="queued".
    queue_size:
        Max depth of the background sender queue (default 1000).
    flush_interval_ms:
        Max wait before the background worker flushes (default 5000ms).
    rules_dir:
        Path to a directory of YAML rule files.  When omitted, the bundled
        sample rules are loaded automatically.
    exclusions_file:
        Path to a YAML exclusion config file.  When provided, alerts
        matching exclusion rules are suppressed and reported separately
        in ``TraceResponse.suppressed_alerts``.
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        mode: str = "safe",
        include_fields: list[str] | None = None,
        base_url: str = "https://api.aktov.dev",
        agent_id: str | None = None,
        agent_type: str | None = None,
        custom_tool_map: dict[str, str] | None = None,
        timeout_ms: int = 500,
        max_actions: int = 200,
        raise_on_error: bool = False,
        framework: str | None = None,
        background: bool = False,
        queue_size: int = 1000,
        flush_interval_ms: int = 5000,
        rules_dir: str | None = None,
        exclusions_file: str | None = None,
    ) -> None:
        if mode not in ("safe", "debug"):
            raise ValueError(f"mode must be 'safe' or 'debug', got {mode!r}")

        self._api_key = api_key
        self._mode = mode
        self._include_fields = include_fields
        self._base_url = base_url.rstrip("/")
        self._agent_id = agent_id
        self._agent_type = agent_type
        self._custom_tool_map = custom_tool_map
        self._timeout_ms = timeout_ms
        self._max_actions = max_actions
        self._raise_on_error = raise_on_error
        self._framework = framework
        self._rules_dir = rules_dir
        self._exclusions_file = exclusions_file

        # Lazy-loaded rule engine (initialized on first trace.end())
        self._rule_engine: RuleEngine | None = None

        # Lazy-loaded exclusion config
        self._exclusion_config: ExclusionConfig | None = None

        # Background sender (only when api_key is provided)
        self._bg_sender: _BackgroundSender | None = None
        if background and api_key:
            self._bg_sender = _BackgroundSender(
                base_url=self._base_url,
                api_key=self._api_key,
                timeout_ms=timeout_ms,
                queue_size=queue_size,
                flush_interval_ms=flush_interval_ms,
            )

    def _get_rule_engine(self) -> RuleEngine:
        """Return the rule engine, lazily loading rules on first call."""
        if self._rule_engine is None:
            self._rule_engine = RuleEngine()
            if self._rules_dir:
                self._rule_engine.load_rules(self._rules_dir)
            else:
                self._rule_engine.load_bundled_rules()
        return self._rule_engine

    def _get_exclusion_config(self) -> ExclusionConfig | None:
        """Return the exclusion config, lazily loading on first call."""
        if self._exclusions_file is None:
            return None
        if self._exclusion_config is None:
            self._exclusion_config = load_exclusions(self._exclusions_file)
        return self._exclusion_config

    @property
    def stats(self) -> dict[str, int | str | None]:
        """Background sender stats. Returns empty dict if not in background mode."""
        if self._bg_sender is None:
            return {}
        return {
            "sent_count": self._bg_sender.sent_count,
            "dropped_count": self._bg_sender.dropped_count,
            "error_count": self._bg_sender.error_count,
            "last_error": self._bg_sender.last_error,
        }

    def start_trace(
        self,
        *,
        agent_id: str | None = None,
        agent_type: str | None = None,
        task_id: str | None = None,
        session_id: str | None = None,
        declared_intent: str | None = None,
    ) -> Trace:
        """Begin a new trace.

        Returns a :class:`Trace` object to record actions into.

        Raises ``ValueError`` if neither instance-level nor call-level
        agent_id / agent_type are provided.
        """
        resolved_agent_id = agent_id or self._agent_id
        resolved_agent_type = agent_type or self._agent_type

        if not resolved_agent_id:
            raise ValueError(
                "agent_id must be provided either at client init or start_trace()"
            )
        if not resolved_agent_type:
            raise ValueError(
                "agent_type must be provided either at client init or start_trace()"
            )

        return Trace(
            client=self,
            agent_id=resolved_agent_id,
            agent_type=resolved_agent_type,
            task_id=task_id,
            session_id=session_id,
            declared_intent=declared_intent,
        )
