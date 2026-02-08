"""Tests for SDK resilience when the cloud is unavailable."""

import time

import pytest
from aktov.client import Aktov
from aktov.schema import TraceResponse


class TestCloudDown:
    """SDK should never crash when the cloud is unreachable."""

    def test_end_returns_local_alerts_when_cloud_unreachable(self) -> None:
        """trace.end() returns local evaluation results when cloud is down."""
        cw = Aktov(
            api_key="ak_test_key",
            agent_id="test-agent",
            agent_type="test",
            base_url="http://localhost:19999",
            timeout_ms=100,
            raise_on_error=False,
        )
        trace = cw.start_trace()
        trace.record_action(tool_name="read_file")

        response = trace.end()

        assert isinstance(response, TraceResponse)
        assert response.trace_id is None
        assert response.status == "evaluated"  # local succeeded, cloud failed
        assert response.error_code is not None  # cloud error recorded
        assert response.rules_evaluated == 3  # bundled sample rules

    def test_end_raises_when_configured(self) -> None:
        """trace.end() raises when raise_on_error=True."""
        cw = Aktov(
            api_key="ak_test_key",
            agent_id="test-agent",
            agent_type="test",
            base_url="http://localhost:19999",
            timeout_ms=100,
            raise_on_error=True,
        )
        trace = cw.start_trace()
        trace.record_action(tool_name="read_file")

        with pytest.raises(Exception):
            trace.end()

    def test_record_action_unaffected_by_cloud_state(self) -> None:
        """record_action never talks to the cloud, always succeeds."""
        cw = Aktov(
            api_key="ak_test_key",
            agent_id="test-agent",
            agent_type="test",
            base_url="http://localhost:19999",
        )
        trace = cw.start_trace()

        action = trace.record_action(
            tool_name="read_file",
            arguments={"path": "/tmp/test"},
        )
        assert action.tool_name == "read_file"


class TestBackgroundSender:
    """Tests for the background sender mode."""

    def test_background_returns_queued_with_local_alerts(self) -> None:
        """trace.end() returns immediately with status='queued' and local alerts."""
        cw = Aktov(
            api_key="ak_test_key",
            agent_id="test-agent",
            agent_type="test",
            base_url="http://localhost:19999",
            timeout_ms=100,
            background=True,
            queue_size=10,
        )
        trace = cw.start_trace()
        trace.record_action(tool_name="read_file")

        response = trace.end()

        assert response.status == "queued"
        assert response.trace_id is None
        assert response.rules_evaluated == 3  # local rules evaluated
        cw._bg_sender.shutdown()

    def test_background_drops_when_full(self) -> None:
        """When queue is full, returns status='dropped'."""
        cw = Aktov(
            api_key="ak_test_key",
            agent_id="test-agent",
            agent_type="test",
            base_url="http://localhost:19999",
            timeout_ms=100,
            background=True,
            queue_size=2,
            flush_interval_ms=60000,
        )
        # Fully stop the worker so it doesn't drain the queue during the test
        cw._bg_sender._stop.set()
        try:
            cw._bg_sender._queue.put_nowait(None)  # wake worker from blocking get
        except Exception:
            pass
        cw._bg_sender._thread.join(timeout=1.0)

        # Fill the queue
        trace1 = cw.start_trace()
        trace1.record_action(tool_name="read_file")
        resp1 = trace1.end()
        assert resp1.status == "queued"

        trace2 = cw.start_trace()
        trace2.record_action(tool_name="write_file")
        resp2 = trace2.end()
        assert resp2.status == "queued"

        # 3rd should be dropped
        trace3 = cw.start_trace()
        trace3.record_action(tool_name="delete_file")
        resp3 = trace3.end()
        assert resp3.status == "dropped"
        assert cw.stats["dropped_count"] == 1
        cw._bg_sender.shutdown()

    def test_background_stats(self) -> None:
        """Stats are available via cw.stats."""
        cw = Aktov(
            api_key="ak_test_key",
            agent_id="test-agent",
            agent_type="test",
            base_url="http://localhost:19999",
            timeout_ms=100,
            background=True,
        )
        stats = cw.stats
        assert stats["sent_count"] == 0
        assert stats["dropped_count"] == 0
        assert stats["error_count"] == 0
        cw._bg_sender.shutdown()

    def test_background_error_increments_on_unreachable(self) -> None:
        """Error count increases when cloud is unreachable."""
        cw = Aktov(
            api_key="ak_test_key",
            agent_id="test-agent",
            agent_type="test",
            base_url="http://localhost:19999",
            timeout_ms=100,
            background=True,
            flush_interval_ms=100,
        )
        trace = cw.start_trace()
        trace.record_action(tool_name="read_file")
        trace.end()

        time.sleep(0.5)

        assert cw.stats["error_count"] >= 1
        assert cw.stats["last_error"] is not None
        cw._bg_sender.shutdown()

    def test_no_stats_without_background(self) -> None:
        """cw.stats returns empty dict when not in background mode."""
        cw = Aktov(
            api_key="ak_test_key",
            agent_id="test-agent",
            agent_type="test",
        )
        assert cw.stats == {}
