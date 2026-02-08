"""Aktov framework integrations.

Plug-and-play integrations for popular AI agent frameworks::

    # Claude Code — zero code, just config
    aktov init claude-code

    # OpenClaw — skill + real-time watcher
    aktov init openclaw

    # OpenAI Agent SDK
    from aktov.integrations.openai_agents import AktovHooks

    # LangChain
    from aktov.integrations.langchain import AktovCallback

    # MCP
    from aktov.integrations.mcp import wrap

    # OpenAI API (raw)
    from aktov.integrations.openai import OpenAITracer

    # Anthropic API (raw)
    from aktov.integrations.anthropic import AnthropicTracer
"""
