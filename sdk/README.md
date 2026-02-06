# chainwatch

Detection engineering for AI agents. `pip install chainwatch` + 2 lines of code → alerts when agents do weird or risky things.

## Quick Start

```python
from chainwatch import ChainWatch

cw = ChainWatch(api_key="cw_...")  # SAFE mode by default
```

That's it. Auto-detects your agent framework, extracts semantic flags client-side, transmits only detection-relevant metadata.

## Features

- Framework auto-detection (LangChain, OpenAI, Anthropic, MCP)
- SAFE mode: no raw arguments leave your machine
- 12 built-in detection rules
- Preview CLI: `chainwatch preview --trace <file>`

## License

Apache-2.0
