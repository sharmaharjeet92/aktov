#!/bin/bash
# ChainWatch — capture Claude Code tool calls as traces
# Runs as async PostToolUse hook. Receives JSON on stdin.
# Logs locally to .claude/traces/ and optionally sends to ChainWatch API.

set -o pipefail

# --- Config (override via env) ---
CHAINWATCH_ENDPOINT="${CHAINWATCH_ENDPOINT:-http://localhost:8000}"
CHAINWATCH_API_KEY="${CHAINWATCH_API_KEY:-}"
AGENT_ID="${AGENT_ID:-claude-code}"
AGENT_TYPE="${AGENT_TYPE:-development_assistant}"
TRACE_DIR="${CLAUDE_PROJECT_DIR:-.}/.claude/traces"
MAX_RESPONSE_SIZE=50000

mkdir -p "$TRACE_DIR"

# --- Read hook input ---
INPUT=$(cat)
[ -z "$INPUT" ] && exit 0

tool_name=$(echo "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null)
[ -z "$tool_name" ] && exit 0

session_id=$(echo "$INPUT" | jq -r '.session_id // "unknown"' 2>/dev/null)
tool_input=$(echo "$INPUT" | jq '.tool_input // {}' 2>/dev/null)
tool_response=$(echo "$INPUT" | jq '.tool_response // {}' 2>/dev/null)

# --- Truncate large responses ---
resp_size=$(echo "$tool_response" | wc -c | tr -d ' ')
if [ "$resp_size" -gt "$MAX_RESPONSE_SIZE" ]; then
  tool_response='{"_truncated": true}'
fi

# --- Map tool → category ---
case "$tool_name" in
  Read|Glob|Grep|WebFetch|WebSearch) category="read" ;;
  Write|Edit|NotebookEdit)           category="write" ;;
  Bash|Task)                         category="execute" ;;
  *)                                 category="execute" ;;
esac

# --- Extract semantic flags ---
flags='{}'
case "$tool_name" in
  WebFetch|WebSearch)
    url=$(echo "$tool_input" | jq -r '.url // empty' 2>/dev/null)
    if [ -n "$url" ]; then
      flags='{"is_external": true, "has_network_calls": true}'
    fi
    ;;
  Read|Write|Edit)
    fpath=$(echo "$tool_input" | jq -r '.file_path // empty' 2>/dev/null)
    if echo "$fpath" | grep -qE '(/\.ssh/|/\.env|/\.aws/|/\.config/|/etc/)'; then
      flags='{"sensitive_dir_match": true}'
    fi
    if echo "$fpath" | grep -qE '\.\./' ; then
      flags=$(echo "$flags" | jq '. + {"path_traversal_detected": true}')
    fi
    ;;
  Bash)
    cmd=$(echo "$tool_input" | jq -r '.command // empty' 2>/dev/null)
    if echo "$cmd" | grep -qE '(curl|wget|http|ssh|scp|rsync)'; then
      flags='{"has_network_calls": true}'
    fi
    ;;
esac

# --- Compute argument size bucket ---
input_size=$(echo "$tool_input" | wc -c | tr -d ' ')
if   [ "$input_size" -lt 1024 ];   then size_bucket="small"
elif [ "$input_size" -lt 10240 ];  then size_bucket="medium"
elif [ "$input_size" -lt 102400 ]; then size_bucket="large"
else                                    size_bucket="very_large"
fi
flags=$(echo "$flags" | jq --arg sb "$size_bucket" '. + {"argument_size_bucket": $sb}')

# --- Build trace ---
ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
trace=$(jq -n \
  --arg agent_id "$AGENT_ID" \
  --arg agent_type "$AGENT_TYPE" \
  --arg session_id "$session_id" \
  --arg tool_name "$tool_name" \
  --arg category "$category" \
  --arg ts "$ts" \
  --argjson flags "$flags" \
  --argjson tool_input "$tool_input" \
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
      semantic_flags: $flags,
      arguments: $tool_input,
      outcome: { status: "success" },
      timestamp: $ts,
      latency_ms: 0
    }],
    metadata: {
      framework: "claude_code",
      environment: "development"
    }
  }' 2>/dev/null)

[ -z "$trace" ] && exit 1

# --- Log locally (always) ---
echo "$trace" >> "$TRACE_DIR/$(date +%Y%m%d).jsonl" 2>/dev/null

# --- Send to ChainWatch API (if configured) ---
if [ -n "$CHAINWATCH_API_KEY" ]; then
  curl -s -X POST "$CHAINWATCH_ENDPOINT/v1/traces" \
    -H "Authorization: Bearer $CHAINWATCH_API_KEY" \
    -H "Content-Type: application/json" \
    -d "$trace" \
    --max-time 5 > /dev/null 2>&1 || true
fi

exit 0
