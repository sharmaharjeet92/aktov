# aktov

Detection engineering for AI agents. `pip install aktov` + 2 lines of code → alerts when agents do weird or risky things.

The pattern never lies.

## Quick Start

```python
from aktov import Aktov

ak = Aktov(api_key="ak_...")  # SAFE mode by default
```

That's it. Auto-detects your agent framework, extracts semantic flags client-side, transmits only detection-relevant metadata.

## Features

- Framework auto-detection (LangChain, OpenAI, Anthropic, MCP)
- SAFE mode: no raw arguments leave your machine
- 12 built-in detection rules
- Preview CLI: `aktov preview --trace <file>`

## License

Apache-2.0
