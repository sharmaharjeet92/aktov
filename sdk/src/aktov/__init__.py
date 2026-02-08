"""Aktov SDK — Detection engineering for AI agents.

Evaluates agent tool-call traces against YAML detection rules.
Works immediately after install — no API key or cloud required.

Quick start::

    from aktov import Aktov

    ak = Aktov(agent_id="my-agent", agent_type="langchain")
    trace = ak.start_trace(declared_intent="answer user question")
    trace.record_action(tool_name="read_file", arguments={"path": "/data/report.csv"})
    response = trace.end()
    print(response.alerts)   # local rule evaluation results
"""

from aktov.client import Aktov

__version__ = "0.2.0"
__all__ = ["Aktov"]
