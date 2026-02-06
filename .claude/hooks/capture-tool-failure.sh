#!/bin/bash
# ChainWatch — capture Claude Code tool failures as traces
# Runs as async PostToolUseFailure hook. Receives JSON on stdin.

set -o pipefail

CHAINWATCH_ENDPOINT="${CHAINWATCH_ENDPOINT:-http://localhost:8000}"
CHAINWATCH_API_KEY="${CHAINWATCH_API_KEY:-}"
AGENT_ID="${AGENT_ID:-claude-code}"
AGENT_TYPE="${AGENT_TYPE:-development_assistant}"
TRACE_DIR="${CLAUDE_PROJECT_DIR:-.}/.claude/traces"

mkdir -p "$TRACE_DIR"

INPUT=$(cat)
[ -z "$INPUT" ] && exit 0

tool_name=$(echo "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null)
[ -z "$tool_name" ] && exit 0

session_id=$(echo "$INPUT" | jq -r '.session_id // "unknown"' 2>/dev/null)
error_msg=$(echo "$INPUT" | jq -r '.error // "unknown_error"' 2>/dev/null)

# Map tool → category
case "$tool_name" in
  Read|Glob|Grep|WebFetch|WebSearch) category="read" ;;
  Write|Edit|NotebookEdit)           category="write" ;;
  Bash|Task)                         category="execute" ;;
  *)                                 category="execute" ;;
esac

ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
trace=$(jq -n \
  --arg agent_id "$AGENT_ID" \
  --arg agent_type "$AGENT_TYPE" \
  --arg session_id "$session_id" \
  --arg tool_name "$tool_name" \
  --arg category "$category" \
  --arg ts "$ts" \
  '{
    agent_id: $agent_id,
    agent_type: $agent_type,
    task_id: $session_id,
    session_id: $session_id,
    mode: "debug",
    actions: [{
      sequence_index: 0,
      tool_name: $tool_name,
      tool_category: $category,
      semantic_flags: {},
      outcome: {
        status: "error",
        error_class: "internal_error"
      },
      timestamp: $ts,
      latency_ms: 0
    }],
    metadata: {
      framework: "claude_code",
      environment: "development"
    }
  }' 2>/dev/null)

[ -z "$trace" ] && exit 1

echo "$trace" >> "$TRACE_DIR/failures-$(date +%Y%m%d).jsonl" 2>/dev/null

if [ -n "$CHAINWATCH_API_KEY" ]; then
  curl -s -X POST "$CHAINWATCH_ENDPOINT/v1/traces" \
    -H "Authorization: Bearer $CHAINWATCH_API_KEY" \
    -H "Content-Type: application/json" \
    -d "$trace" \
    --max-time 5 > /dev/null 2>&1 || true
fi

exit 0
