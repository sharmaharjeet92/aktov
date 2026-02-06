"""ChainWatch SDK — Detection engineering for AI agents.

Auto-detects agent frameworks, canonicalizes tool invocations into a
standard trace schema, extracts semantic flags client-side, and
transmits traces to the ChainWatch cloud API for rule evaluation.

Quick start::

    from chainwatch import ChainWatch

    cw = ChainWatch(api_key="cw-...", agent_id="my-agent", agent_type="langchain")
    trace = cw.start_trace(declared_intent="answer user question")
    trace.record_action(tool_name="read_file", arguments={"path": "/data/report.csv"})
    response = trace.end()
"""

from chainwatch.client import ChainWatch

__version__ = "0.1.0"
__all__ = ["ChainWatch"]
