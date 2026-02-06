"""Tests for SDK resilience when the cloud is unavailable."""

import pytest

from chainwatch.client import ChainWatch
from chainwatch.schema import TraceResponse


class TestCloudDown:
    """SDK should never crash when the cloud is unreachable."""

    def test_end_returns_stub_when_cloud_unreachable(self) -> None:
        """trace.end() returns a stub response, does not raise."""
        cw = ChainWatch(
            api_key="cw_test_key",
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
        assert response.trace_id == ""
        assert response.rules_evaluated == 0

    def test_end_raises_when_configured(self) -> None:
        """trace.end() raises when raise_on_error=True."""
        cw = ChainWatch(
            api_key="cw_test_key",
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
        cw = ChainWatch(
            api_key="cw_test_key",
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
