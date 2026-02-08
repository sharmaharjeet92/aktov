# Aktov — Project Context

## One-Line Summary

Detection engineering for AI agents. `pip install aktov` + 2 lines → alerts when agents do weird or risky things. SAFE mode by default: no raw tool arguments leave your machine. Open-source rules ("Sigma for agents"), cloud adds baselines + anomaly scoring + dashboards.

**Vision:** Cloudflare for agentic detections — enterprise-grade security accessible to solo devs.

---

## Problem Statement

AI agents (LangChain, CrewAI, AutoGen, OpenAI Assistants, Anthropic tool-use, MCP-connected agents) execute multi-step tool call sequences to accomplish tasks. Each tool call may be individually authorized, but the **composition of tool calls** can constitute malicious or anomalous behavior — analogous to LOLBin chains in endpoint security.

No existing product purpose-builds **detection engineering** for agent action traces. LLM observability tools (LangSmith, Arize) track prompt quality and latency. SIEMs ingest generic logs but lack semantic understanding of agent behavior. The gap is a purpose-built detection layer that understands what agents _should_ do versus what they _are_ doing.

### Specific Threat Scenarios Aktov Detects

1. **Prompt Injection → Tool Misuse**: An agent processing user input gets injected with instructions that cause it to invoke tools outside its intended task scope (e.g., a summarization agent suddenly calling `http_post` to an external endpoint).

2. **Action Chain Divergence**: An agent's tool call sequence deviates significantly from its historical behavioral baseline — longer chains, novel tool combinations, unusual argument patterns.

3. **Capability Escalation**: An agent declared as read-only begins invoking write/delete/execute operations, indicating either compromise or misconfiguration.

4. **Exfiltration Staging**: An agent combines data-read tools with network-egress tools in a sequence consistent with data exfiltration patterns (read_file → encode → http_post).

5. **Confused Deputy via Delegation**: Agent A delegates to Agent B, and Agent B executes actions that exceed Agent A's intended scope, creating transitive authority violations.

6. **Memory Poisoning Behavioral Drift**: A long-running agent with persistent memory exhibits gradual behavioral changes after ingesting poisoned content — detectable as slow baseline drift over time.

7. **Credential Abuse Patterns**: An agent begins accessing resources or APIs it has credentials for but has never historically used, indicating potential credential theft or scope exploitation.

8. **Anomalous Argument Patterns**: An agent that normally issues `SELECT` queries begins issuing `DROP`, `UPDATE`, or `INSERT` statements — the tool call is the same (`execute_sql`) but the argument semantics are adversarial.

### Agent Team Threat Scenarios (Multi-Agent Architectures)

Reference architecture: Anthropic's "Building a C Compiler with a team of parallel Claudes" (Feb 2026) — 16 autonomous Claude instances with filesystem/git/code execution access, running in infinite loops across 2,000 sessions with no human in the loop and no orchestration agent. This architecture signals a direction that enterprise development is likely to follow.

9. **Cross-Agent Poisoned Artifact Propagation**: Agent #7 introduces a subtle vulnerability (via prompt injection, hallucination, or adversarial context manipulation). Agents #8-16 pull Agent #7's code, merge it, and build on it — propagating the vulnerability without any individual agent detecting it. The poisoned artifact spreads at machine speed through the shared codebase. Detection requires correlating behavioral changes across agents temporally — identifying that multiple agents' tool patterns shifted _after_ incorporating a specific agent's output.

10. **Coordination Anomaly in Agent Swarms**: In a team of 16 agents, 14 work on compiler features while 2 suddenly begin modifying build scripts, CI configuration, and dependency manifests. Each individual agent's trace looks normal in isolation, but the **aggregate behavior distribution** is anomalous. Detection requires a cross-agent correlation layer that models the expected distribution of task types across the team and flags deviations.

11. **Lock Contention as Adversarial Signal**: In lock-based synchronization architectures (like Carlini's task-lock pattern), an agent that repeatedly claims locks on security-sensitive files (build configs, CI pipelines, credential stores, dependency manifests) while other agents work on feature code exhibits a **resource access pattern anomaly**. The lock acquisition sequence is a behavioral signal — anomalous lock patterns produce low transition probabilities in Markov models trained on normal team coordination.

12. **Emergent Team-Level Capability Escalation**: No individual agent has exfiltration capability, but Agent A has `read_file` access and Agent B has `http_post` access. Through the shared codebase, Agent A writes data to a file that Agent B later transmits externally. The exfiltration capability **emerges from the team composition** without any single agent violating its individual constraints. Detection requires modeling the team's aggregate capability graph, not just individual agent permissions.

13. **Test-Passing Adversarial Output**: In autonomous agent teams, the testing harness IS the safety boundary. An agent that passes all functional tests but introduces a backdoor, exfiltrates source code paths in commit messages, or modifies the build pipeline in a functionally invisible way has bypassed the only verification layer. Aktov detects **what the agent did** (tool call patterns), not whether the output is correct — a fundamentally complementary detection surface to functional testing.

---

## Privacy & Data Handling

### v1 Privacy Model: Two Modes

**No raw prompts or tool arguments leave your machine by default.** This is the simple, true claim that builds trust with solo developers and satisfies enterprise legal review.

#### SAFE Mode (Default)

The SDK transmits only detection-relevant metadata — never raw argument values or outcome content.

**What is sent:**
- `tool_name`, `tool_category`, `sequence_index`, `timestamp`, `latency_ms`
- `outcome.status` (success/failure/error/timeout)
- `outcome.error_class` (coarse category: permission_denied, not_found, timeout, validation, auth, unknown)
- `outcome.response_size_bucket` (0–1KB / 1–10KB / 10–100KB / 100KB+)
- Low-cardinality **semantic flags** computed client-side (booleans + buckets only):
  - `sql_statement_type`: SELECT / INSERT / UPDATE / DELETE / DDL
  - `http_method`: GET / POST / PUT / DELETE / PATCH
  - `is_external`: boolean (target domain is not in known internal list)
  - `sensitive_dir_match`: boolean (file path references /etc, .ssh, .env, etc.)
  - `has_network_calls`: boolean (code execution tool contains network operations)
  - `argument_size_bucket`: small / medium / large / very_large
  - `path_traversal_detected`: boolean

**What is NOT sent:** raw SQL queries, file paths, URLs, HTTP bodies, error messages, code snippets, API responses, credentials, or any other raw argument/outcome values.

**Detection capability:** ~70-80% — all deterministic rules on categorical fields work. Statistical models (n-gram, Markov) operate on composite state `(tool_name, tool_category, semantic_flag_digest)` with full fidelity. Only rules that require inspecting actual argument content (e.g., regex on SQL query strings) are unavailable.

#### DEBUG Mode (Explicit Opt-In)

For users who want deeper detection or need to debug agent behavior, DEBUG mode adds selective field transmission:

```python
cw = Aktov(api_key="ak_...", mode="debug")
# or with explicit field selection:
cw = Aktov(api_key="ak_...", mode="debug", include_fields=["http_method", "status_code", "sql_statement_type", "target_domain"])
```

DEBUG mode sends everything SAFE mode sends, plus allowlisted argument fields. Still no raw bodies, no raw error messages, no code snippets.

**Detection capability:** ~85-95% depending on which fields are included.

#### "Preview What Leaves the Box"

The SDK includes a CLI tool that shows exactly what data will be transmitted for a given trace — before any data is sent. This is the trust UX that eliminates uncertainty for both solos and enterprise security review.

```bash
$ aktov preview --trace example_trace.json
┌──────────────────────────────────────────────────────┐
│ SAFE mode — what will be transmitted:                │
├──────────────────────────────────────────────────────┤
│ tool_name: execute_sql                               │
│ tool_category: read                                  │
│ semantic_flags:                                      │
│   sql_statement_type: SELECT                         │
│   argument_size_bucket: small                        │
│ outcome:                                             │
│   status: success                                    │
│   response_size_bucket: 1-10KB                       │
│                                                      │
│ STRIPPED (not transmitted):                           │
│   arguments.query: "SELECT * FROM users WHERE..."    │
│   outcome.response: "[{id: 1, name: ...}]"          │
└──────────────────────────────────────────────────────┘
```

### v1 Data Handling Guarantees

- SAFE mode default: no raw prompts/args/outcomes sent to cloud
- DEBUG mode opt-in with explicit field allowlisting
- Preview CLI shows exact payload before any data leaves
- Encryption in transit (TLS) and at rest
- Fixed retention: 30 days (non-enterprise), hard delete after window
- Delete-on-request: full org data purge within 30 days of request
- Tenant isolation at the application layer (tenant ID enforced in every query)

### Enterprise Data Handling (Roadmap)

> These features are designed but deferred until enterprise customer demand warrants implementation.

- **Tenant-specific encryption keys** (AWS KMS / GCP CMEK)
- **Row-level security** on all database queries
- **Configurable retention** (30d–365d per org)
- **DPA** (Data Processing Agreement) for enterprise contracts
- **Immutable audit log** with cryptographic chaining for tamper evidence
- **Granular allowlist mode**: per-agent, per-tool field-level control over what is transmitted
- **HMAC-based identity tokenization**: domains, paths, table names tokenized client-side for novelty detection without plaintext
- **Privacy audit logging**: immutable append-only log of all privacy config changes
- **Self-hosted detection engine**: entire pipeline runs in customer's environment — zero data egress

### Aktov Self-Threat Model

Aktov itself is an attack surface. Enterprise buyers will ask how Aktov protects against threats to its own infrastructure.

| Threat | Impact | Mitigation |
| ------ | ------ | ---------- |
| **API key theft** | Attacker can ingest fake traces or read alerts for a tenant | API keys scoped per-org. Key rotation without downtime. Rate limiting per key. |
| **Ingestion poisoning** | Adversary sends crafted traces to shift baselines, creating false negatives for real attacks | Trace authentication via API key + SDK version validation. Anomaly detection on ingestion patterns (volume spikes, schema violations). Baseline manipulation requires sustained high-volume poisoning — CUSUM drift detection also flags this. |
| **Replay attacks** | Replayed traces inflate usage meters or pollute baselines | Trace deduplication via `trace_id` + `ingested_at` uniqueness. Optional nonce/timestamp validation window. |
| **Tenant isolation failure** | Cross-tenant data leakage | Tenant ID propagated in every database query via application-level middleware. Penetration testing on multi-tenant boundaries. Enterprise: tenant-specific encryption keys + RLS. |

### Data Retention and Deletion Policy

| Data Type | v1 Retention | Enterprise (Roadmap) | Deletion Behavior |
| --------- | ------------ | -------------------- | ----------------- |
| **Traces** (semantic flags, metadata) | 30 days | Configurable (30d–365d) | Hard delete after retention window. Cascades to anomaly scores. |
| **Baselines** (n-gram tables, Markov matrices) | Retained while org active | Same | Recomputed from retained traces. Deleted on org termination. |
| **Alerts** | 90 days | Configurable | Hard delete after retention. |
| **Usage meters** | 1 year | Same | Hard delete after retention. |

**Account termination**: All tenant data (traces, baselines, models, alerts, API keys) hard-deleted within 30 days of account closure.

**Delete-on-request**: Deletion requests trigger a full org data purge. Since SAFE mode stores only semantic flags (not raw arguments or end-user PII), most customers have minimal stored data by design.

---

## Product Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Agent Frameworks                          │
│  (LangChain, CrewAI, OpenAI, Anthropic, MCP, AutoGen)      │
└──────────────┬──────────────────────────────────────────────┘
               │ Raw tool calls (arguments, outcomes, timing)
               ▼
┌─────────────────────────────────────────────────────────────┐
│    SDK — Open Source (pip install aktov)                │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  1. Framework auto-detection (or explicit import)     │  │
│  │  2. Field canonicalization (framework → Aktov)   │  │
│  │  3. Tool category auto-mapping (tool → read/write/..) │  │
│  │  4. Semantic flag extraction (client-side, no raw     │  │
│  │     args leave unless DEBUG mode)                     │  │
│  │  5. Trace assembly + async transmission               │  │
│  │                                                       │  │
│  │  Mode: SAFE (default) | DEBUG (opt-in)                │  │
│  │  CLI: aktov preview --trace <file>               │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  Output: Canonical trace (semantic flags + metadata)        │
└──────────────┬──────────────────────────────────────────────┘
               │ Canonicalized traces (JSON)
               ▼
┌─────────────────────────────────────────────────────────────┐
│            Trace Ingestion Layer (Cloud)                     │
│  - REST API endpoint (POST /v1/traces)                      │
│  - Schema + mode validation                                 │
│  - Async queue (for burst handling)                         │
└──────────────┬──────────────────────────────────────────────┘
               │
               ▼
┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
│          Open-Source Detection Layer                         │
│                                                             │
│  ┌─────────────────────┐                                    │
│  │  Rule-Based Engine   │  Deterministic rules (AK-001     │
│  │  (YAML / Python DSL) │  through AK-051). Open-source    │
│  │  - Pattern matching  │  rule library: "Sigma for agents" │
│  │  - Semantic flag     │                                   │
│  │    analysis          │                                   │
│  │  - Severity scoring  │                                   │
│  └─────────┬───────────┘                                    │
└ ─ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│        Cloud-Only: Statistical Behavioral Engine            │
│                                                             │
│  ┌──────────────────────────────┐                           │
│  │  Behavioral Baseline Engine  │                           │
│  │  - Per-agent-type profiles   │                           │
│  │  - N-gram sequence models    │                           │
│  │    (Layer 2: CW-200 series)  │                           │
│  │  - Markov transition scoring │                           │
│  │    (Layer 3: CW-300 series)  │                           │
│  │  - CUSUM drift detection     │                           │
│  └──────────────┬───────────────┘                           │
│                 │                                           │
│                 ▼                                           │
│  ┌─────────────────────────────┐                            │
│  │  Alert Correlation & Triage │                            │
│  │  (Funnel of Fidelity)       │                            │
│  │  L1→direct, L2+L3→corr.    │                            │
│  └─────────────────────────────┘                            │
└──────────────┬──────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│               Output Layer (Cloud)                          │
│  - Alert API (webhooks to Slack, PagerDuty, SIEM)          │
│  - Web UI (alert feed, trace explorer, rule editor)        │
│  - Anomaly score dashboards + drift timeline               │
│  - Alert context: matched rule, baseline deviation,        │
│    anomaly score decomposition, recommended response       │
└─────────────────────────────────────────────────────────────┘
```

### Canonical Trace Schema

Every ingested trace conforms to this schema.

```json
{
  "trace_id": "uuid",
  "agent_id": "string — unique identifier for the agent instance",
  "agent_type": "string — declared agent category (e.g., 'code_review', 'customer_support', 'data_analysis')",
  "task_id": "string — the specific task/run this trace belongs to",
  "session_id": "string — groups related tasks in a long-running session",
  "org_id": "string — tenant identifier",
  "declared_intent": "string — optional, the human-readable task description",
  "team_context": {
    "team_id": "string — optional, identifier for the agent team",
    "team_role": "string — optional, this agent's role within the team",
    "team_size": "integer — optional, total agents in the team",
    "shared_resource_id": "string — optional, shared repo/filesystem identifier",
    "coordination_events": [
      {
        "type": "enum — lock_acquired | lock_released | merge_completed | push | pull | conflict_resolved",
        "resource": "string — what was locked/merged/pushed",
        "source_agent_id": "string — for merges: whose output was incorporated",
        "timestamp": "ISO 8601"
      }
    ]
  },
  "actions": [
    {
      "sequence_index": 0,
      "tool_name": "string — canonical tool identifier",
      "tool_category": "enum — read | write | execute | network | credential | pii | delete",
      "semantic_flags": {
        "description": "Low-cardinality flags computed client-side by SDK. Always present in SAFE mode.",
        "example": {
          "sql_statement_type": "SELECT",
          "argument_size_bucket": "small"
        }
      },
      "arguments": {
        "description": "Raw tool arguments. Only present in DEBUG mode (never sent in SAFE mode).",
        "example": {
          "query": "SELECT * FROM orders WHERE date > '2025-01-01'",
          "limit": 100
        }
      },
      "outcome": {
        "status": "enum — success | failure | error | timeout",
        "error_class": "enum — permission_denied | not_found | timeout | validation | auth | unknown",
        "response_size_bucket": "enum — 0-1KB | 1-10KB | 10-100KB | 100KB+"
      },
      "timestamp": "ISO 8601",
      "latency_ms": "integer"
    }
  ],
  "metadata": {
    "framework": "string — langchain | openai | anthropic | mcp | crewai | autogen | custom",
    "model": "string — underlying LLM if known",
    "sdk_version": "string",
    "source_ip": "string — optional",
    "environment": "enum — production | staging | development"
  }
}
```

**SAFE mode (default):** SDK computes `semantic_flags` and `outcome` fields client-side. Raw `arguments` are never transmitted. Detection capability: ~70-80%.

**DEBUG mode:** SDK sends everything SAFE mode sends, plus raw `arguments` for allowlisted fields. Detection capability: ~85-95%.

Use `aktov preview --trace <file>` to inspect exactly what will be transmitted before any data leaves.

### Detection Rule Format

Rules are expressed as code, version-controlled, testable. Two formats supported.

**v1 SaaS rule authoring**: Customer-authored custom rules use YAML + constrained expression language only. Python DSL rules are Aktov-authored system rules only (shipped as part of the detection rule library). Customer Python DSL is available in future on-prem/local tier.

#### Declarative YAML Rules

```yaml
rule_id: CW-2025-001
name: read_only_agent_write_operation
description: >
  Detects when an agent with a read-only declared intent
  performs a write, delete, or execute operation.
severity: high
category: capability_escalation

match:
  conditions:
    - field: agent_type
      in: ["summarizer", "analyzer", "reader", "reporter"]
    - field: actions[*].tool_category
      contains_any: ["write", "delete", "execute"]
  logic: ALL
context:
  - include: full_action_trace
  - include: agent_baseline_comparison
response:
  alert: true
  block: false # v1 is detect-only, not inline blocking
  recommended_action: "Review agent configuration. Verify no prompt injection in recent inputs."
tags:
  - capability_escalation
  - prompt_injection_indicator
mitre_mapping: null # future: map to agent-specific ATT&CK-style framework
```

#### Python DSL Rules (for complex logic)

```python
from aktov.rules import Rule, when, action_chain

@Rule(
    id="CW-2025-007",
    name="exfiltration_staging_pattern",
    severity="critical",
    category="data_exfiltration",
)
def detect_exfil_staging(trace):
    """
    Detects sequential pattern: data read → encoding/transformation → network egress.
    Classic exfiltration staging behavior adapted for agent tool chains.
    """
    chain = action_chain(trace)

    has_data_read = chain.any(tool_category="read")
    has_network_egress = chain.any(tool_category="network")
    read_before_egress = chain.sequence(
        first=lambda a: a.tool_category == "read",
        then=lambda a: a.tool_category == "network",
        max_gap=5  # max 5 intermediate steps
    )

    # Check for external domain via semantic flag (works in SAFE mode)
    external_egress = chain.any(
        lambda a: a.tool_category == "network"
        and a.semantic_flags.get("is_external", False)
    )

    return (
        has_data_read
        and has_network_egress
        and read_before_egress
        and external_egress
        and trace.declared_intent_category not in ["api_integration", "webhook_handler"]
    )
```

#### Python DSL Rule Using Semantic Flags

```python
@Rule(
    id="CW-2025-030",
    name="sql_ddl_from_readonly_agent",
    severity="critical",
    category="argument_anomaly",
)
def detect_sql_ddl(trace):
    """
    Detects SQL DDL operations (DROP, ALTER, CREATE, TRUNCATE) from agents
    whose baseline is SELECT-only. Uses semantic flags (works in SAFE mode).
    """
    chain = action_chain(trace)
    return chain.any(
        lambda a: a.tool_name in ["execute_sql", "query_database", "run_query"]
        and a.semantic_flags.get("sql_statement_type") in ["DDL", "DELETE", "TRUNCATE"]
    )
```

---

## Behavioral Modeling Engine (Core Detection IP)

The deterministic rule library (AK-001 through AK-051) is Layer 1 — necessary for immediate, explainable value but easily replicable. Any detection engineer can write conditional logic on categorical fields. The compounding advantage comes from the full system: **canonicalization + rule ecosystem + corpus/tuning loops + statistical behavioral modeling** that learns what "normal" looks like per agent archetype and detects novel anomalies that no predefined rule anticipates.

This follows the same evolutionary path as endpoint security: signature-based AV → behavioral detection → UEBA. Aktov's detection architecture is a layered Funnel of Fidelity with three detection layers.

### Layer 1: Deterministic Rules (Current Rule Library)

High-confidence, zero-ambiguity detections. "Read-only agent performed write" is always an alert, no statistical judgment needed. These are **high-fidelity, low-volume** detections — they fire rarely but signal-to-noise ratio is near-perfect.

### Layer 2: N-Gram Sequence Anomaly Detection

Agent action traces are **discrete sequential data with a finite vocabulary** (tool names or tool categories). This is structurally identical to how **syscall sequence analysis** works in host-based intrusion detection (Forrest et al., immune-system-inspired anomaly detection using n-gram models on syscall traces).

**How it works:**

- For each agent archetype, build a **frequency table of bigrams** observed across historical traces (trigrams added in v1.1)
- Tool vocabulary for a typical agent is 5–50 tools, so a bigram matrix is 50×50 = 2,500 cells — trivially storable and computable
- On each new trace, extract all n-grams and check against the frequency table
- **Zero-frequency n-grams** (tool sequences never previously observed for this agent type) are anomalous by definition
- **Low-frequency n-grams** (observed <0.1% of the time) are suspicious and scored accordingly

**State representation design (critical for detection quality):**
The "state" in the n-gram model is not just the tool name — it's a composite of features that balance granularity against false positive rate:

```
State = (tool_name, tool_category, semantic_flag_digest)

Examples:
- ("execute_sql", "read", "SELECT")       -- normal read query
- ("execute_sql", "write", "DDL:DROP")     -- destructive DDL
- ("http_request", "network", "POST:external")  -- external POST
- ("read_file", "read", "sensitive_dir")   -- sensitive path access
```

The `semantic_flag_digest` is derived from the **semantic flags** computed client-side by the SDK (e.g., `sql_statement_type`, `http_method`, `is_external`). These flags are always available in both SAFE and DEBUG modes, ensuring full statistical model fidelity regardless of privacy mode. The state space design is where detection engineering judgment becomes irreplaceable — getting the granularity wrong produces either excessive false positives (too granular) or missed detections (too coarse).

**Cardinality control:** Only low-cardinality extracted values go into the state digest (e.g., `sql_statement_type` has ~6 values, `http_method` has ~5, `is_external` is boolean). High-cardinality values (actual domains, file paths, table names) are tracked separately for novelty/frequency analysis but excluded from the n-gram/Markov state to keep the vocabulary tractable.

**Detection outputs:**

- `zero_frequency_ngram`: A tool sequence never seen in this agent's history — **medium-high fidelity**
- `low_frequency_ngram`: A tool sequence seen <0.1% — **medium fidelity**, requires correlation
- `ngram_novelty_score`: Aggregate score for the trace based on proportion of novel n-grams

### Layer 3: Markov Transition Probability Scoring

A first-order Markov model computes `P(next_tool | current_tool)` — the probability of each tool transition given the previous tool. Higher-order models capture longer dependencies: `P(next | prev_2)` or `P(next | prev_3)`.

**How it works:**

- Build a **transition probability matrix** per agent archetype from historical traces
- For a well-baselined summarizer agent: `P(generate_text | read_file) = 0.85`, `P(http_post | read_file) = 0.001`
- On each new trace, compute the **product of transition probabilities** for the entire action chain
- Traces with one or more extremely low-probability transitions get flagged
- The **aggregate trace anomaly score** = -log(P(trace)) = -Σ log(P(action*i | action*{i-1}))
- Higher scores = more anomalous

**Detection outputs:**

- `trace_anomaly_score`: Aggregate log-probability score for the full trace
- `transition_anomalies`: List of specific transitions with probability < threshold
- `baseline_drift_score`: Sliding-window comparison of recent anomaly scores vs. historical distribution — detects **gradual behavioral drift** from memory poisoning

**Funnel of Fidelity integration:**

- Layer 1 (rules) alerts go **directly to analyst** — no triage needed
- Layer 2 (n-gram) alerts get **correlated with Layer 3 scores** — a zero-frequency n-gram + low aggregate Markov score = high-priority investigation
- Layer 3 (Markov) anomalies alone are tracked as **leading indicators** for baseline drift but don't fire standalone alerts unless they persist across multiple traces (reduces false positives from legitimate one-off tool usage)

### Baseline Computation Pipeline

```
Traces (per agent type, rolling window)
    │
    ▼
┌─────────────────────────────┐
│  N-Gram Frequency Tables    │
│  - Bigram counts (v1)       │
│  - Trigram counts (v1.1)    │
│  - Per-state (composite)    │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│  Markov Transition Matrices │
│  - 1st order P(t|t-1)      │
│  - 2nd order P(t|t-1,t-2)  │
│  - Per agent archetype      │
│  - Smoothed (Laplace)       │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│  Anomaly Score Distribution │
│  - Historical score mean/σ  │
│  - Drift detection (CUSUM)  │
│  - Threshold calibration    │
│    per agent archetype      │
└─────────────────────────────┘
```

**Recomputation cadence:** Baselines recompute incrementally — each new trace updates the frequency tables and transition matrices in near-real-time via online learning (no batch recomputation needed). Full recomputation runs daily as a consistency check.

**Smoothing:** Laplace smoothing (add-1) on the transition matrix prevents zero-probability transitions from producing infinite anomaly scores. This means truly novel transitions get a very high score but not infinity — allowing threshold-based alerting to function.

**Explainability:** Every anomaly score decomposes into the specific transitions that contributed most to the score. Alert context includes: "This agent has never executed `http_post` after `read_file` in 12,000 previous traces. The transition probability is 0.00008. This is a **first-occurrence transition anomaly**." This is more explainable than most ML detections and maps directly to the analyst question "has this ever happened before?"

---

## Agent Team Detection Architecture (v1.5 / v2)

### Why Agent Teams Change the Threat Model

The Anthropic C compiler project (Feb 2026) demonstrated 16 autonomous agents with full filesystem/git/code execution access running in infinite loops with no human oversight. This architecture will become standard for enterprise software development, infrastructure management, and data pipeline operations. It introduces failure modes that per-agent detection cannot catch.

### Team-Level Telemetry Model

In addition to individual agent traces, Aktov ingests **team context** when agents operate in coordinated groups:

```json
{
  "trace_id": "uuid",
  "agent_id": "agent-7",
  "team_id": "compiler-team-alpha",
  "team_role": "feature_developer",
  "team_size": 16,
  "shared_resource_id": "git:repo/claudes-compiler",
  "coordination_events": [
    {
      "type": "lock_acquired",
      "resource": "current_tasks/parse_if_statement.txt",
      "timestamp": "ISO 8601"
    },
    {
      "type": "merge_completed",
      "source_agent": "agent-3",
      "conflicts_resolved": 2,
      "timestamp": "ISO 8601"
    },
    {
      "type": "lock_released",
      "resource": "current_tasks/parse_if_statement.txt",
      "timestamp": "ISO 8601"
    }
  ],
  "mode": "safe",
  "actions": [ ... ]
}
```

### Team-Level Detection Layers

**Cross-Agent Behavioral Correlation:**

- Model the expected **distribution of task types** across the team (e.g., 80% feature development, 10% testing, 5% documentation, 5% code quality)
- Alert when the distribution shifts anomalously (e.g., 3 of 16 agents simultaneously begin modifying CI/CD configuration)
- Uses chi-squared test on the team-level task category distribution vs. historical baseline

**Temporal Causality Analysis:**

- Track **behavioral changes that correlate temporally with merge events**
- If Agent #7 pushes code at T1, and Agents #8, #9, #12 all exhibit tool pattern changes after pulling at T2 > T1, flag the merge event as a **potential poisoned artifact propagation vector**
- Uses Granger causality testing on per-agent anomaly scores relative to merge timestamps

**Resource Access Pattern Modeling:**

- Build a Markov model on **lock acquisition sequences** per agent
- An agent that normally locks feature files but suddenly begins locking build scripts, CI configs, or credential stores produces a **low-probability lock transition**
- Detects adversarial agents targeting infrastructure-level resources

**Team Capability Graph Analysis:**

- Model the aggregate **capability surface** of the team — which tools each agent has access to and which resources each agent touches
- Identify **emergent capability paths** — Agent A writes data to a shared file, Agent B reads that file and transmits externally
- Flag capability paths that constitute exfiltration, privilege escalation, or unauthorized access when composed across agents, even when no individual agent violates its own constraints

### Team Detection Rules (v2 — AK-100 Series)

| Rule ID | Rule Name                         | Detection Layer         | Description                                                                               |
| ------- | --------------------------------- | ----------------------- | ----------------------------------------------------------------------------------------- |
| AK-100  | Team task distribution anomaly    | Cross-agent correlation | Task type distribution deviates significantly from historical team baseline               |
| CW-101  | Post-merge behavioral shift       | Temporal causality      | Multiple agents' tool patterns change after incorporating specific agent's output         |
| CW-102  | Infrastructure lock concentration | Resource access         | Single agent acquires disproportionate locks on security-sensitive resources              |
| CW-103  | Emergent exfiltration path        | Capability graph        | Cross-agent tool composition creates data egress capability no individual agent possesses |
| CW-104  | Agent role deviation              | Cross-agent correlation | Agent assigned "documentation" role begins executing code modification tools              |
| CW-105  | Cascade failure propagation       | Temporal causality      | Error rates across multiple agents spike after specific merge event                       |
| CW-106  | Shadow agent detection            | Cross-agent correlation | Unregistered agent instance detected pushing to shared resource                           |

---

## Tech Stack

### Phase 0 (Ship First)

- **Language**: Python 3.12+
- **API Framework**: FastAPI (async, high-throughput trace ingestion)
- **Database**: PostgreSQL 16 (everything — traces, rules, alerts, config)
- **Detection**: Synchronous rule evaluation in request path (no queue)
- **Alert delivery**: Background thread / asyncio task for webhooks
- **Auth**: API key per org (simple table lookup)
- **Hosting**: Railway or Fly.io (minimize DevOps)
- **CI/CD**: GitLab CI/CD
- **Monitoring**: Sentry (errors)
- **Encryption**: TLS in transit, encryption at rest (standard provider)

### Phase 1 Additions (When Triggers Hit)

- **Task Queue**: Celery or Arq with Redis broker (async rule eval + baseline jobs)
- **Time-Series**: TimescaleDB extension on PostgreSQL (when trace queries > 1s)
- **Cache**: Redis (rate limiting, hot baseline caches)
- **Auth**: Clerk or Auth0 (when multi-user access needed)
- **Analytics**: PostHog (product analytics)
- **Billing**: Stripe (usage-based metering on trace count)
- **Charts**: Recharts (anomaly score timeline, baseline deviation graphs)

### Frontend

- **Phase 0**: Minimal or none — webhook-only MVP is viable. If building UI: alert feed + trace viewer only.
- **Phase 1**: Next.js 14+ (App Router), Tailwind CSS + shadcn/ui, React Query + Zustand

### SDKs (Client Libraries)

- **Python SDK**: `aktov` (open-source) — auto-detect framework, schema canonicalization, semantic flag extraction, SAFE/DEBUG modes. Callback integrations for LangChain, CrewAI, AutoGen, raw OpenAI/Anthropic, MCP.
- **TypeScript SDK**: `aktov-js` — callback integrations for Vercel AI SDK, LangChain.js, MCP clients
- Priority: Python SDK first (majority of agent frameworks are Python-native)

---

## Data Model (PostgreSQL)

> **Phase 0** uses: `organizations`, `org_configs`, `agents`, `traces`, `detection_rules`, `alerts`, `notification_channels`, `usage_meters`, `audit_log`. Statistical tables (`baselines`, `ngram_models`, `markov_models`, `anomaly_scores`) and team tables are Phase 1+.

### Core Tables

```sql
-- Multi-tenant organizations
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    plan TEXT NOT NULL DEFAULT 'free', -- free | indie | pro | team | enterprise
    trace_limit_monthly INTEGER NOT NULL DEFAULT 10000,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Organization configuration
CREATE TABLE org_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) UNIQUE,
    default_mode TEXT NOT NULL DEFAULT 'safe', -- safe | debug
    trace_retention_days INTEGER NOT NULL DEFAULT 30, -- 7 for free, 30 for indie/pro, configurable for enterprise
    updated_at TIMESTAMPTZ DEFAULT now(),
    updated_by TEXT
);

-- Registered agent identities
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id),
    agent_id_external TEXT NOT NULL, -- customer's identifier for the agent
    agent_type TEXT, -- declared category
    declared_intent TEXT, -- human-readable purpose
    framework TEXT, -- langchain, openai, anthropic, mcp, etc.
    first_seen TIMESTAMPTZ DEFAULT now(),
    last_seen TIMESTAMPTZ,
    UNIQUE(org_id, agent_id_external)
);

-- Action traces (TimescaleDB hypertable)
CREATE TABLE traces (
    id UUID DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL,
    agent_id UUID REFERENCES agents(id),
    task_id TEXT,
    session_id TEXT,
    declared_intent TEXT,
    action_count INTEGER NOT NULL,
    mode TEXT NOT NULL DEFAULT 'safe', -- safe | debug — mode trace was ingested with
    actions JSONB NOT NULL, -- array of canonicalized action objects (semantic flags always, raw args in debug only)
    semantic_flags JSONB, -- denormalized semantic flags for fast detection queries
    metadata JSONB,
    environment TEXT DEFAULT 'production',
    ingested_at TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (id, ingested_at)
);
-- Phase 1: Convert to TimescaleDB hypertable when trace queries on time windows exceed 1s
-- SELECT create_hypertable('traces', 'ingested_at');

-- Behavioral baselines per agent type
CREATE TABLE baselines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id),
    agent_type TEXT NOT NULL,
    baseline_window TEXT NOT NULL DEFAULT '7d', -- rolling window
    avg_chain_length FLOAT,
    stddev_chain_length FLOAT,
    tool_frequency JSONB, -- {"read_file": 0.45, "generate_text": 0.30, ...}
    common_sequences JSONB, -- [["read_file", "generate_text", "return"], ...]
    semantic_flag_baselines JSONB, -- {"sql_statement_type": {"SELECT": 0.95, "INSERT": 0.05}, ...}
    sample_count INTEGER,
    computed_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(org_id, agent_type, baseline_window)
);

-- N-gram frequency tables for sequence anomaly detection (Layer 2)
CREATE TABLE ngram_models (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id),
    agent_type TEXT NOT NULL,
    ngram_order INTEGER NOT NULL, -- 2 = bigram, 3 = trigram, 4 = 4-gram
    frequency_table JSONB NOT NULL, -- {"(read_file:read:SELECT, execute_sql:read:SELECT)": 4521, ...}
    total_ngrams BIGINT NOT NULL, -- total count for normalization
    vocabulary_size INTEGER NOT NULL, -- number of distinct states observed
    zero_frequency_threshold FLOAT DEFAULT 0.0, -- below this = zero-frequency alert
    low_frequency_threshold FLOAT DEFAULT 0.001, -- below this = low-frequency alert
    sample_trace_count INTEGER, -- number of traces used to build this model
    computed_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(org_id, agent_type, ngram_order)
);

-- Markov transition matrices for probability scoring (Layer 3)
CREATE TABLE markov_models (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id),
    agent_type TEXT NOT NULL,
    model_order INTEGER NOT NULL DEFAULT 1, -- 1 = first-order, 2 = second-order
    transition_matrix JSONB NOT NULL, -- {"state_A": {"state_B": 0.85, "state_C": 0.10, ...}, ...}
    smoothing_method TEXT NOT NULL DEFAULT 'laplace', -- laplace | kneser_ney | none
    smoothing_parameter FLOAT DEFAULT 1.0, -- alpha for Laplace smoothing
    state_vocabulary JSONB NOT NULL, -- list of all observed states
    score_distribution JSONB, -- {"mean": 12.3, "stddev": 4.1, "p95": 20.5, "p99": 28.7}
    sample_trace_count INTEGER,
    computed_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(org_id, agent_type, model_order)
);

-- Anomaly score history per agent (for drift detection via CUSUM)
CREATE TABLE anomaly_scores (
    agent_id UUID REFERENCES agents(id),
    trace_id UUID NOT NULL,
    rule_layer TEXT NOT NULL, -- 'deterministic' | 'ngram' | 'markov'
    trace_anomaly_score FLOAT, -- aggregate -log(P(trace)) for markov
    ngram_novelty_score FLOAT, -- proportion of novel n-grams
    zero_frequency_ngrams JSONB, -- list of zero-frequency n-grams found
    transition_anomalies JSONB, -- list of low-probability transitions
    scored_at TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (agent_id, trace_id, rule_layer)
);

-- Agent teams (for multi-agent coordination detection)
CREATE TABLE agent_teams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id),
    team_id_external TEXT NOT NULL, -- customer's identifier for the team
    team_name TEXT,
    team_size INTEGER,
    shared_resource_ids JSONB DEFAULT '[]'::jsonb, -- git repos, shared filesystems, etc.
    coordination_model TEXT, -- 'lock_based' | 'orchestrated' | 'consensus' | 'independent'
    created_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(org_id, team_id_external)
);

-- Agent team membership (maps agents to teams with roles)
CREATE TABLE agent_team_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES agents(id),
    team_id UUID REFERENCES agent_teams(id),
    team_role TEXT, -- 'feature_developer' | 'code_reviewer' | 'documentation' | 'ci_cd' | etc.
    joined_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(agent_id, team_id)
);

-- Team-level behavioral baselines
CREATE TABLE team_baselines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id UUID REFERENCES agent_teams(id),
    baseline_window TEXT NOT NULL DEFAULT '7d',
    task_distribution JSONB, -- {"feature_dev": 0.80, "testing": 0.10, "docs": 0.05, "ci_cd": 0.05}
    merge_frequency_per_hour FLOAT,
    avg_conflict_rate FLOAT,
    lock_contention_patterns JSONB, -- per-resource lock frequency distribution
    inter_agent_dependency_graph JSONB, -- which agents' outputs feed into which agents
    sample_count INTEGER,
    computed_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(team_id, baseline_window)
);

-- Coordination events (merges, locks, shared resource access)
CREATE TABLE coordination_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL,
    team_id UUID REFERENCES agent_teams(id),
    agent_id UUID REFERENCES agents(id),
    event_type TEXT NOT NULL, -- 'lock_acquired' | 'lock_released' | 'merge_completed' | 'push' | 'pull' | 'conflict_resolved'
    resource TEXT, -- what was locked/merged/pushed
    source_agent_id UUID, -- for merge events: whose code was incorporated
    metadata JSONB, -- event-specific data (conflicts_resolved, merge_size, etc.)
    event_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_coordination_events_team ON coordination_events(team_id, event_at DESC);
CREATE INDEX idx_coordination_events_agent ON coordination_events(agent_id, event_at DESC);

-- Detection rules (customer-defined + system default)
CREATE TABLE detection_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id), -- NULL for system rules
    rule_id_human TEXT NOT NULL, -- e.g., "CW-2025-001"
    name TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL, -- critical | high | medium | low | info
    category TEXT NOT NULL,
    rule_type TEXT NOT NULL, -- yaml | python
    rule_content TEXT NOT NULL, -- the actual rule definition
    enabled BOOLEAN DEFAULT true,
    is_system_rule BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- Generated alerts
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL,
    trace_id UUID NOT NULL,
    agent_id UUID REFERENCES agents(id),
    rule_id UUID REFERENCES detection_rules(id),
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    context JSONB, -- trace data, baseline comparison, matched patterns
    status TEXT DEFAULT 'open', -- open | acknowledged | resolved | false_positive
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Alert notification destinations
CREATE TABLE notification_channels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id),
    channel_type TEXT NOT NULL, -- webhook | slack | pagerduty | email
    config JSONB NOT NULL, -- channel-specific configuration
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Usage metering for billing
CREATE TABLE usage_meters (
    org_id UUID REFERENCES organizations(id),
    period_start DATE NOT NULL, -- monthly billing period
    trace_count INTEGER DEFAULT 0,
    alert_count INTEGER DEFAULT 0,
    PRIMARY KEY (org_id, period_start)
);

-- Audit log — immutable append-only, tracks config changes
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id),
    action TEXT NOT NULL, -- config_changed | rule_created | rule_updated | agent_registered
    previous_value JSONB,
    new_value JSONB,
    changed_by TEXT NOT NULL, -- user ID or API key ID
    created_at TIMESTAMPTZ DEFAULT now()
);
```

---

## API Design

### Trace Ingestion

```
POST /v1/traces
Authorization: Bearer <api_key>
Content-Type: application/json

{
  "agent_id": "my-summarizer-agent",
  "agent_type": "summarizer",
  "task_id": "task_abc123",
  "declared_intent": "Summarize Q4 revenue report",
  "mode": "safe",
  "actions": [
    {
      "tool_name": "read_file",
      "tool_category": "read",
      "semantic_flags": {
        "sensitive_dir_match": false,
        "argument_size_bucket": "small"
      },
      "outcome": {"status": "success", "error_class": null, "response_size_bucket": "10-100KB"},
      "timestamp": "2025-06-15T10:30:00Z",
      "latency_ms": 120
    },
    {
      "tool_name": "generate_text",
      "tool_category": "execute",
      "semantic_flags": {
        "argument_size_bucket": "medium"
      },
      "outcome": {"status": "success", "error_class": null, "response_size_bucket": "1-10KB"},
      "timestamp": "2025-06-15T10:30:02Z",
      "latency_ms": 1850
    }
  ],
  "metadata": {
    "framework": "langchain",
    "model": "claude-sonnet-4-5-20250929",
    "environment": "production"
  }
}

Response: 201 Created
{
  "trace_id": "uuid",
  "rules_evaluated": 18,
  "alerts": []
}
```

**Ingestion validation rules:**

- `agent_id` is REQUIRED
- `actions` must be a non-empty array with valid `tool_name` and `tool_category` fields
- SDK auto-populates `tool_category` via built-in mapping; server validates against known categories

### Alerts

```
GET /v1/alerts?status=open&severity=critical,high&limit=50
GET /v1/alerts/{alert_id}
PATCH /v1/alerts/{alert_id}  — update status (acknowledge, resolve, false_positive)
```

#### Example Alert (API Response)

```json
{
  "alert_id": "a1b2c3d4-...",
  "severity": "critical",
  "rule_id": "AK-001",
  "rule_name": "Read-only agent write operation",
  "category": "capability_escalation",
  "agent_id": "my-summarizer-agent",
  "agent_type": "summarizer",
  "trace_id": "t9x8y7z6-...",
  "title": "Read-only agent performed write operation",
  "description": "Agent 'my-summarizer-agent' (type: summarizer) invoked tool 'write_file' (category: write). This agent's baseline is read-only — no write operations in 847 previous traces.",
  "matched_action": {
    "sequence_index": 3,
    "tool_name": "write_file",
    "tool_category": "write",
    "semantic_flags": {"sensitive_dir_match": true, "argument_size_bucket": "medium"}
  },
  "context": {
    "baseline_write_frequency": 0.0,
    "total_baseline_traces": 847,
    "anomaly_score": null
  },
  "status": "open",
  "created_at": "2025-06-15T10:31:05Z"
}
```

#### Example Slack Notification

```
🚨 *Aktov Alert — CRITICAL*
*Read-only agent performed write operation* (AK-001)

Agent: `my-summarizer-agent` (summarizer)
Tool: `write_file` → category: *write*
Trace: `t9x8y7z6-...`

This agent has *never* performed a write in 847 previous traces.
Possible prompt injection or misconfiguration.

[View Alert →](https://app.aktov.dev/alerts/a1b2c3d4)
```

### Rules

```
GET /v1/rules — list all rules (system + custom)
POST /v1/rules — create custom YAML rule
PUT /v1/rules/{rule_id} — update rule
DELETE /v1/rules/{rule_id} — delete custom rule (cannot delete system rules)
POST /v1/rules/{rule_id}/test — dry-run rule against historical traces
```

### Baselines

```
GET /v1/agents/{agent_id}/baseline — current behavioral baseline
GET /v1/agents/{agent_id}/traces — historical traces for an agent
```

---

## SDK Design (Python) — Open Source

### v1 Framework Support

| Framework | Integration Type | Priority |
|---|---|---|
| **LangChain** | Callback handler | v1 launch |
| **OpenAI** (function calling) | Tracer wrapper | v1 launch |
| **Anthropic** (tool use) | Tracer wrapper | v1 launch |
| **MCP** | Client middleware | v1 launch |
| **CrewAI** | Callback handler | v1.1 |
| **AutoGen** | Callback handler | v1.1 |
| **Generic** | Manual `record_action()` | v1 launch |

### Minimal Integration (2 Lines)

```python
from aktov import Aktov

cw = Aktov(api_key="ak_...")  # SAFE mode by default — no raw args leave
```

That's it. The SDK auto-detects the agent framework, canonicalizes fields, computes semantic flags client-side, and transmits only detection-relevant metadata.

### SAFE vs DEBUG Mode

```python
# SAFE mode (default) — no raw arguments transmitted
cw = Aktov(api_key="ak_...")

# DEBUG mode — adds selective raw field transmission for deeper detection
cw = Aktov(api_key="ak_...", mode="debug")

# DEBUG mode with explicit field selection
cw = Aktov(api_key="ak_...", mode="debug", include_fields=["sql_statement_type", "target_domain", "status_code"])
```

### Schema Canonicalization

The SDK normalizes framework-specific fields into Aktov's canonical schema. Auto-detection inspects trace structure to determine framework; explicit integration imports are available as override.

| Framework Field | Aktov Canonical | Notes |
|---|---|---|
| LangChain `AgentAction.tool` | `tool_name` | |
| LangChain `AgentAction.tool_input` | `arguments` | |
| OpenAI `tool_calls[].function.name` | `tool_name` | |
| OpenAI `tool_calls[].function.arguments` | `arguments` | JSON string → dict |
| MCP `CallToolRequest.name` | `tool_name` | |
| MCP `CallToolRequest.arguments` | `arguments` | |
| Anthropic `tool_use.name` | `tool_name` | |
| Anthropic `tool_use.input` | `arguments` | |

**Tool category auto-mapping:** SDK ships with a built-in tool → category mapping for common tools across frameworks. Customer can override via config. Categories: `read | write | execute | network | credential | pii | delete`

### LangChain Integration

```python
from aktov.integrations import langchain

# Drop-in callback handler for LangChain
callback = langchain.callback(
    api_key="ak_...",
    agent_id="my-summarizer",
    agent_type="summarizer",
)

# Attach to any LangChain agent
agent = create_react_agent(llm, tools, callbacks=[callback])
agent.invoke({"input": "Summarize Q4 revenue"})
# Aktov captures the full action trace
# Only semantic flags are transmitted (SAFE mode default)
```

### OpenAI Function Calling Integration

```python
from aktov.integrations import openai as cw_openai

tracer = cw_openai.tracer(api_key="ak_...", agent_id="my-assistant")

with tracer.trace(task_id="task_123", declared_intent="Answer customer query"):
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[...],
        tools=[...],
    )
    tracer.record_tool_calls(response)
    # SDK auto-canonicalizes OpenAI tool_calls → Aktov schema
```

### MCP Client Integration

```python
from aktov.integrations import mcp

# Wraps an MCP client to intercept all tool invocations
monitored_client = mcp.middleware(
    mcp_client=original_client,
    api_key="ak_...",
    agent_id="mcp-agent-1",
)
# All MCP tool calls traced — semantic flags only in SAFE mode
```

### Generic / Framework-Agnostic

```python
from aktov import Aktov

cw = Aktov(api_key="ak_...")

trace = cw.start_trace(
    agent_id="custom-agent",
    agent_type="data_pipeline",
    declared_intent="Process daily ETL"
)

trace.record_action(
    tool_name="query_database",
    tool_category="read",
    arguments={"query": "SELECT * FROM orders WHERE date > '2025-01-01'"},
    outcome="success"
)
# SAFE mode: SDK extracts semantic flags client-side, transmits:
# {
#   "tool_name": "query_database", "tool_category": "read",
#   "semantic_flags": {"sql_statement_type": "SELECT", "argument_size_bucket": "small"},
#   "outcome": {"status": "success", "response_size_bucket": "1-10KB"}
# }
# Raw arguments NEVER leave — computed and discarded locally.

alerts = trace.end()  # sends trace, returns any synchronous alerts
```

### Preview CLI (Trust UX)

```bash
# See exactly what will be transmitted — before any data is sent
$ aktov preview --trace example_trace.json
$ aktov preview --trace example_trace.json --mode debug

# Pipe from stdin for CI/CD integration
$ cat trace.json | aktov preview --mode safe
```

---

## Build Phases

### Phase 0 — Ship This First

**Goal:** Detect-only cloud service + OSS SDK + deterministic rule pack + webhook delivery. Simplest system that can evolve.

**OSS (SDK + Rule Library)**

- Python SDK (`pip install aktov`) with framework auto-detection
- Schema canonicalization: LangChain, OpenAI, Anthropic, MCP → canonical schema
- Built-in tool → category auto-mapping with customer override
- SAFE mode (default): client-side semantic flag extraction, no raw args transmitted
- DEBUG mode (opt-in): selective field transmission
- Preview CLI (`aktov preview --trace <file>`)
- 10-12 deterministic rules that work in SAFE mode without baselines (see Phase 0 Rule Pack below)
- Local rule evaluation (run deterministic rules without cloud connection)

**Cloud**

- Trace ingestion API: `POST /v1/traces` (single trace per request)
- Auth: API key per org (simple, no Clerk/Auth0 yet)
- Storage: Postgres 16 JSONB tables (no TimescaleDB yet)
- Detection: **synchronous** evaluation of Phase 0 rules at ingestion time (no queue)
- Alert delivery: webhook + email (Slack = webhook to Slack incoming hook)
- Alert dedup: `(org_id, agent_id, rule_id)` suppressed for 1 hour with count aggregation
- Minimal UI: alert feed + trace viewer (or skip UI entirely — webhook-only MVP)
- Usage metering (trace count per month)

**Architecture:**

```
SDK → POST /v1/traces → FastAPI → Postgres (store) → Rule eval (sync) → Webhook (async background thread)
```

No Celery. No Redis. No TimescaleDB. No PostHog. One process, one database.

#### Phase 0 Rule Pack (Baseline-Free, SAFE-Mode Compatible)

These rules fire on categorical fields and semantic flags — no behavioral baseline needed, no raw args needed.

| Rule ID | Rule Name | Trigger |
|---|---|---|
| AK-001 | Read-only agent write operation | `agent_type` in read-only set AND `tool_category` in [write, delete, execute] |
| AK-010 | Read → external network egress | `tool_category=read` followed by `tool_category=network` + `is_external=true` in same trace |
| AK-012 | Large payload to external network | `tool_category=network` + `is_external=true` + `argument_size_bucket=very_large` |
| AK-023 | Write/execute/network with no preceding read | First tool in trace is write/execute/network category (no read phase) |
| AK-030 | SQL DDL from non-DB agent | `sql_statement_type` in [DDL, DELETE, TRUNCATE] AND `agent_type` not in DB archetypes |
| AK-031 | Sensitive directory access | `sensitive_dir_match=true` |
| AK-032 | Path traversal detected | `path_traversal_detected=true` |
| AK-007 | Credential tool from non-credential agent | `tool_category=credential` AND `agent_type` not in credential-authorized set |
| AK-022 | Burst of failed tool calls | 3+ consecutive `outcome.status` in [failure, error] within one trace |
| AK-020 | Extreme chain length | `action_count > 50` (static threshold, no baseline needed) |
| AK-050 | Multiple external domains | 3+ distinct `is_external=true` network calls in one trace |
| AK-041 | Repeated network failures | 3+ `tool_category=network` with `outcome.status=error` (possible scanning) |

### Phase 1 — After You Have Users + Data

Add complexity only when evidence warrants it (see Phase Gate Checklist below).

- **Queue + async workers** (Celery or Arq with Redis)
- **TimescaleDB** hypertable on traces table (if time-window queries demand it)
- **Layer 2**: Bigram frequency novelty detection (per agent_type, after 30-trace cold start)
- **Layer 3**: First-order Markov transition probability scoring
- Composite state: `(tool_name, tool_category, semantic_flag_digest)`
- Per-agent behavioral baselines (chain length, tool frequency)
- Anomaly score history + CUSUM drift detection
- Funnel of Fidelity alert correlation
- Custom YAML rules via API
- Web UI dashboards: anomaly score timeline, baseline deviation graphs
- Stripe billing integration
- Auth upgrade: Clerk or Auth0 (multi-user, org support)

### v1.5 Scope

- Agent team awareness (team context ingestion, team baselines)
- **AK-100**: Team task distribution anomaly detection
- **CW-104**: Agent role deviation within team
- Enterprise privacy modes (granular allowlists, HMAC tokenization, privacy audit logging)
- Trigram models (when per-archetype trace counts exceed 5K)

### Out of Scope (v2+)

- TypeScript SDK
- Custom rule authoring UI
- Inline blocking / policy enforcement (v1 is detect-only)
- Cross-customer anonymized baselines
- Full agent team detection suite (CW-101 through CW-106)
- Higher-order Markov models (2nd, 3rd order)
- SIEM export integrations (Splunk, Sentinel, Elastic)
- SOC 2 / compliance reporting
- Self-hosted detection engine deployment

### Phase Gate Checklist

Do not add complexity until evidence triggers it.

| Complexity | Trigger | Rationale |
|---|---|---|
| Async queue (Celery/Arq) | Ingestion p95 > 300ms or > 50 traces/sec sustained | Sync eval is fine until scale demands it |
| TimescaleDB | Trace queries > 1s for 7-day time windows | Plain Postgres is fine for <1M traces |
| Trigram models | Per-agent-type trace count >= 5K | Bigrams cover 80%+ of value; trigrams need data density |
| Markov scoring | Per-agent-type trace count >= 100 | Need enough transitions for meaningful probabilities |
| Auth provider (Clerk/Auth0) | Multi-user access needed or > 10 orgs | API key auth is sufficient for solo/small teams |
| Enterprise privacy controls | Enterprise deal blocked on it | Don't build on spec; build on demand |
| RBAC | Multi-user org requests it | Single-user API key is fine for Phase 0 |
| Custom YAML rules API | Users ask for custom rules | Ship system rules first, validate the rule format |

---

## Detection Rule Library

### Three-Tier Detection Architecture

**Layer 1 — Deterministic Rules (Phase 0, AK-001 to AK-051)**
High-confidence conditional logic on categorical fields. Zero ambiguity. Fires rarely, near-perfect signal-to-noise. Alert goes directly to analyst. Phase 0 ships 10-12 baseline-free rules; full library grows over time.

**Layer 2 — N-Gram Sequence Anomaly Detection (Phase 1, CW-200 series)**
Statistical detection of novel or rare tool sequences via bigram frequency analysis (trigrams in v1.1). Medium fidelity. Correlated with Layer 3 scores before alerting. Catches adversarial patterns no predefined rule anticipates. Activates after 30 traces per agent_type (cold-start gate).

**Layer 3 — Markov Transition Probability Scoring (Phase 1, CW-300 series)**
Aggregate trace anomaly scoring based on transition probabilities. Lower fidelity standalone, but essential for drift detection and composite correlation. Tracked as leading indicators; fires standalone alerts only on persistent anomalies. Activates after 100 traces per agent_type.

**Layer 4 — Agent Team Correlation (v1.5/v2, AK-100 series)**
Cross-agent behavioral analysis for multi-agent architectures. Detects coordination anomalies, poisoned artifact propagation, and emergent capability paths that per-agent detection cannot catch.

### Layer 1: Deterministic Rules

| Rule ID | Rule Name                                | Category               |
| ------- | ---------------------------------------- | ---------------------- |
| AK-001  | Read-only agent write operation          | Capability escalation  |
| AK-002  | Tool outside declared manifest           | Capability escalation  |
| AK-003  | Tool category distribution deviation     | Capability escalation  |
| AK-010  | Sequential read → network egress         | Exfiltration           |
| AK-011  | High-entropy payload before network call | Exfiltration           |
| AK-012  | Abnormally large payload in network args | Exfiltration           |
| AK-020  | Chain length exceeds baseline            | Chain anomaly          |
| AK-021  | Novel tool combination                   | Chain anomaly          |
| AK-022  | Repeated failed tool calls               | Chain anomaly          |
| AK-023  | Write/execute/network with no preceding read | Chain anomaly       |
| AK-030  | SQL DDL from SELECT-baseline agent       | Argument anomaly       |
| AK-031  | File path references sensitive directory | Argument anomaly       |
| AK-032  | HTTP target is novel external domain     | Argument anomaly       |
| AK-040  | Activity outside time-of-day pattern     | Temporal anomaly       |
| AK-041  | Tool call burst above normal rate        | Temporal anomaly       |
| AK-042  | Agent reactivation after dormancy        | Temporal anomaly       |
| AK-050  | Delegated agent exceeds scope            | Delegation             |
| AK-051  | Delegation chain depth threshold         | Delegation             |

### Layer 2: N-Gram Sequence Anomaly Rules

| Rule ID | Rule Name                                  | Description                                                                                                                                                                |
| ------- | ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CW-200  | Zero-frequency bigram                      | Tool pair transition never observed in agent's history                                                                                                                     |
| CW-201  | Zero-frequency trigram (v1.1)              | 3-tool sequence never observed. Requires trigram models (v1.1).                                                                                                            |
| CW-202  | Low-frequency bigram cluster               | Trace contains 3+ bigrams below 0.1% frequency threshold                                                                                                                   |
| CW-203  | Sudden vocabulary expansion                | Agent uses tools in this trace that have never appeared in any prior trace                                                                                                 |
| CW-204  | Sequence length outlier with novel n-grams | Chain length >2σ AND contains zero-frequency n-grams (compound signal)                                                                                                     |
| CW-205  | Semantic state transition anomaly          | Tool transitions that are normal by tool-name but anomalous by semantic state (e.g., `execute_sql→execute_sql` is normal, but `execute_sql:SELECT→execute_sql:DDL` is not) |

### Layer 3: Markov Transition Probability Rules

| Rule ID | Rule Name                                 | Description                                                                          |
| ------- | ----------------------------------------- | ------------------------------------------------------------------------------------ |
| CW-300  | Trace anomaly score threshold             | Aggregate -log(P(trace)) exceeds archetype-specific p99 threshold                    |
| CW-301  | Single extreme low-probability transition | Any transition P < 0.0001 in the trace                                               |
| CW-302  | Behavioral drift (CUSUM)                  | Rolling average anomaly score has shifted >2σ over past 7 days                       |
| CW-303  | Sudden baseline break                     | Anomaly score jumps >3σ from one trace to the next for the same agent                |
| CW-304  | Correlated n-gram + Markov anomaly        | Layer 2 zero-frequency n-gram + Layer 3 score >p95 = high-confidence composite alert |

### Layer 4: Agent Team Detection Rules (v1.5/v2)

| Rule ID | Rule Name                         | Detection Layer         | Description                                                                               |
| ------- | --------------------------------- | ----------------------- | ----------------------------------------------------------------------------------------- |
| AK-100  | Team task distribution anomaly    | Cross-agent correlation | Task type distribution deviates significantly from historical team baseline               |
| CW-101  | Post-merge behavioral shift       | Temporal causality      | Multiple agents' tool patterns change after incorporating specific agent's output         |
| CW-102  | Infrastructure lock concentration | Resource access         | Single agent acquires disproportionate locks on security-sensitive resources              |
| CW-103  | Emergent exfiltration path        | Capability graph        | Cross-agent tool composition creates data egress capability no individual agent possesses |
| CW-104  | Agent role deviation              | Cross-agent correlation | Agent assigned "documentation" role begins executing code modification tools              |
| CW-105  | Cascade failure propagation       | Temporal causality      | Error rates across multiple agents spike after specific merge event                       |
| CW-106  | Shadow agent detection            | Cross-agent correlation | Unregistered agent instance detected pushing to shared resource                           |

### Layer 1 Rule Details

#### Capability Escalation

- `AK-001`: Read-only agent performs write/delete/execute
- `AK-002`: Agent invokes tool outside its declared tool manifest
- `AK-003`: Agent's tool_category distribution deviates >2σ from baseline

#### Exfiltration Patterns

- `AK-010`: Sequential read → network egress pattern
- `AK-011`: High-entropy payload before network egress (suggests encoding/compression)
- `AK-012`: Abnormally large payload in network egress tool arguments

#### Action Chain Anomalies

- `AK-020`: Chain length exceeds 3σ of agent baseline
- `AK-021`: Novel tool combination never seen in agent's history
- `AK-022`: Repeated failed tool calls (brute-force pattern)
- `AK-023`: Write/execute/network tool with no preceding read tool in the trace (high-risk tool first)

#### Argument Anomalies

- `AK-030`: SQL arguments contain DDL/DML when baseline is SELECT-only
- `AK-031`: File path references sensitive directory
- `AK-032`: HTTP target domain is novel/unseen in agent history

#### Temporal Anomalies

- `AK-040`: Agent activity outside historical time-of-day pattern
- `AK-041`: Burst of tool calls significantly above normal rate
- `AK-042`: Agent reactivation after extended dormancy period

#### Delegation / Multi-Agent

- `AK-050`: Delegated agent exceeds delegator's historical scope
- `AK-051`: Delegation chain depth exceeds threshold

---

## Pricing Model

### Open-Core Model

Aktov follows the **Cloudflare model** — enterprise-grade agent security accessible to everyone.

**Open-source (free forever):**
- Python SDK with framework auto-detection, schema canonicalization, SAFE/DEBUG modes
- Deterministic detection rule library (AK-001 through AK-051) — "Sigma for agents"
- Preview CLI (`aktov preview`)
- Local rule evaluation (run deterministic rules without cloud)

**Cloud (paid):**
- Trace ingestion + server-side rule evaluation + alert delivery (Phase 0)
- Statistical behavioral modeling: bigram novelty + Markov scoring (Phase 1)
- Per-agent behavioral baselines with drift detection (Phase 1)
- Alert pipeline with Funnel of Fidelity correlation (Phase 1)
- Web UI: alert feed, trace explorer, anomaly dashboards (Phase 1)
- Webhook integrations (Slack, PagerDuty, generic)
- Usage metering and billing

### Pricing Tiers

| Tier       | Monthly Price | Traces/Month | Agents    | What You Get                                                                                     |
| ---------- | ------------- | ------------ | --------- | ------------------------------------------------------------------------------------------------ |
| OSS        | $0            | —            | —         | SDK + deterministic rules (AK-001–051). Run locally, no cloud.                                   |
| Free Cloud | $0            | 5,000        | 3         | Cloud ingestion + deterministic rules + alert feed. 7-day retention. No stats layers.            |
| Indie      | $19           | 25,000       | 5         | Cloud Layer 1-3 detection, email + webhook alerts, anomaly dashboards. 30-day retention.         |
| Pro        | $79           | 250,000      | 25        | Custom YAML rules, full anomaly score history, baseline dashboards, priority support.             |
| Team       | $249          | 1,000,000    | 100       | Multi-user access, audit log export, Layer 1-3 detection, anomaly dashboards.                    |
| Enterprise | $499+         | 5,000,000    | Unlimited | Agent team detection (Layer 4), SSO/SAML, SLA, dedicated support, DEBUG mode field allowlists.   |
| Scale      | Custom        | 20,000,000+  | Unlimited | Self-hosted option, SIEM export, custom integrations, SOC 2 attestation.                         |

Overage: Indie hard-caps at limit (no surprise bills). Pro+ tiers: $0.30 per 1,000 traces above limit.

**Agent team pricing:** Teams of >10 coordinated agents require Team tier or above. Enterprise tier includes full agent team detection (AK-100 series), cross-agent correlation, and coordination event analysis.

---

## Go-To-Market Strategy

### Launch Sequence

1. **Open-source SDK + rule library on GitHub** — "Sigma for AI Agents" positioning, `pip install aktov`
2. **DEF CON Singapore paper** (Feb 15 deadline) — establishes threat model and credibility
3. **Blog series**: "Agent Action Traces Are the New Endpoint Telemetry" — technical content marketing
4. **Product Hunt / Hacker News launch** — "2 lines of code. Detections in 5 minutes." Self-serve signup funnel
5. **Conference circuit**: BSides, fwd:cloudsec, AI engineer summit — security + AI crossover audience

### DX-Led Positioning

Lead all marketing with: **"2 lines of code. Detections in 5 minutes."** The headline is frictionless DX, not privacy. Privacy is a feature ("SAFE mode: no raw arguments leave your machine"), not the headline. Enterprise-grade privacy controls are available for enterprise buyers — but the landing page speaks to the solo dev first.

**Cloudflare analogy:** Enterprise-grade agent security, accessible to everyone. Free OSS tier for solo devs, paid cloud for teams who want statistical detection + dashboards.

### Target Personas

- **Primary**: Solo developers and indie hackers deploying AI agents — want plug-and-play detection, zero config
- **Secondary**: Security engineers at companies deploying production AI agents
- **Tertiary**: Platform engineering teams building internal agent frameworks and agent team harnesses
- **Enterprise**: CISOs and security leadership at organizations adopting autonomous agent teams — the Anthropic C compiler architecture is their near-future reality

### Positioning

Aktov is **detection engineering for AI agents**. Not governance. Not compliance. Not observability. Detection. Open-source rule library + cloud statistical modeling. The same methodology that protects endpoints, networks, and cloud infrastructure — applied to the newest attack surface.

**Solo dev narrative:** Your agent runs tools. Aktov tells you when something looks wrong. Install the SDK, get detections. No config, no privacy concerns — SAFE mode means nothing raw leaves your machine.

**Enterprise narrative:** When your organization runs 16 autonomous agents building software with no human in the loop — Aktov is the detection layer that tells you which agent is compromised, which merge introduced the vulnerability, and which cross-agent interaction created an exfiltration path. Enterprise-grade privacy controls, tenant isolation, and audit logging included.

---

## Key Technical Decisions & Rationale

1. **Plug-and-play DX as primary differentiator**: `pip install aktov` + 2 lines of code → detections working. Auto-detect framework, auto-categorize tools, auto-baseline. The Cloudflare model — enterprise-grade security accessible to solo devs. DX is what gets adoption; detection quality is what keeps it.

2. **SAFE mode by default, not full-args**: The SDK defaults to SAFE mode — no raw arguments transmitted, only semantic flags. This builds immediate trust with solo devs ("nothing leaves my machine") and satisfies enterprise legal ("we don't collect their data"). DEBUG mode is one flag away for users who want deeper detection. Simplify the privacy *implementation*, not the privacy *posture*.

3. **Open-core model**: Open-source the SDK and deterministic rule library (AK-001–051). Statistical behavioral modeling (n-gram, Markov), alerting pipeline, and dashboards are cloud-only paid features. This gives: (a) OSS credibility and trust, (b) community-contributed detection rules, (c) natural upsell from free to paid, (d) defensible moat in the statistical layer.

4. **Client-side semantic flag extraction**: The SDK computes low-cardinality semantic flags (sql_statement_type, http_method, is_external, etc.) from raw arguments locally and discards the raw values before transmission. This is the architectural innovation that enables ~70-80% detection coverage with zero raw data leaving the machine.

5. **Detect-only in v1, no inline blocking**: Blocking requires being in the critical path of agent execution (proxy architecture), which adds latency, reliability risk, and dramatically increases integration complexity. Detection via async trace ingestion is low-friction and non-breaking. Blocking is a v2 feature once trust is established.

6. **Plain PostgreSQL first, TimescaleDB when needed**: Phase 0 uses plain Postgres JSONB for everything. TimescaleDB hypertable added in Phase 1 when trace queries on time windows exceed 1s. Avoids premature infrastructure complexity. One database, one process.

7. **Python-first SDK**: >80% of production agent frameworks (LangChain, CrewAI, AutoGen, DSPy) are Python. TypeScript SDK (Vercel AI SDK, LangChain.js) is v2.

8. **Rules as code, not GUI-configured**: Detection rules expressed as YAML/Python are version-controllable, testable, peer-reviewable, and composable. This attracts security engineers (the buyer persona) and creates workflow switching costs. Open-sourcing the rule library makes it "Sigma for agents" — community contributions compound the rule library over time.

9. **Trace-level ingestion, not streaming**: Agents complete tasks in seconds to minutes. Ingesting the complete trace post-execution (rather than streaming individual tool calls) simplifies architecture and allows detection rules to reason about the full action chain. Streaming support for long-running agents is a v2 feature.

10. **N-gram + Markov as statistical foundation, not neural networks**: The behavioral modeling engine uses proven statistical methods (n-gram frequency tables, Markov transition matrices) rather than deep learning. Rationale: (a) agent tool vocabularies are small (5-50 tools), so the state space is tractable for exact computation, (b) training data is self-generating from normal operations — no labeled dataset required, (c) anomaly scores are fully explainable — every alert decomposes into specific transitions that the analyst can verify, (d) online incremental learning means baselines update with each trace without batch recomputation. The math is commodity — the value is in the tuned system (threshold calibration, archetype priors, suppression, cold-start handling) built on real agent trace data.

11. **Composite state representation for Markov models**: The state is `(tool_name, tool_category, semantic_flag_digest)` — not just the tool name. This captures semantically meaningful distinctions (e.g., `execute_sql:SELECT` vs `execute_sql:DDL`) without exploding the state space. The semantic_flag_digest is derived from client-side extracted flags, ensuring full statistical model fidelity in SAFE mode. This state design is the primary detection engineering judgment call.

12. **Layered detection with Funnel of Fidelity correlation**: Layer 1 (rules) alerts go directly to analysts. Layer 2 (n-gram) alerts are correlated with Layer 3 (Markov) scores before surfacing — a zero-frequency n-gram with a high aggregate anomaly score is a high-priority investigation; a zero-frequency n-gram with a normal aggregate score is lower priority. Layer 3 anomalies alone are tracked as leading indicators for drift but don't fire standalone alerts unless they persist.

13. **Agent team detection as a separate architectural layer**: Team-level detection (AK-100 series) operates on a different data model than per-agent detection. Keeping it separate allows v1 to ship without team complexity while preserving a clean extension point for v1.5/v2.

---

## Competitive Landscape

| Company         | What They Do             | Why They Don't Solve This                                                                                 |
| --------------- | ------------------------ | --------------------------------------------------------------------------------------------------------- |
| LangSmith       | LLM tracing & evaluation | ML quality focus, not security. Ingests full prompts/completions (privacy concern). No detection rules.   |
| Arize AI        | ML observability         | Model performance monitoring. Collects full inference data. No agent-specific behavioral analysis.        |
| Galileo         | LLM evaluation           | Prompt quality metrics. No tool chain security analysis.                                                  |
| Splunk/Sentinel | SIEM                     | Can ingest any log, but no semantic understanding of agent tool sequences. No agent-aware canonicalization.|
| Pangea          | API security for LLMs    | Input/output scanning (prompt injection). No action trace behavioral analysis.                            |
| Protect AI      | ML supply chain security | Model scanning, not runtime agent behavior.                                                               |
| Lasso Security  | LLM security             | Prompt-level protection. Not tool chain anomaly detection.                                                |
| CalypsoAI       | LLM gateway              | Request-level filtering. No multi-step behavioral analysis.                                               |

**DX differentiation**: No competitor offers `pip install` + 2 lines → working detections. LangSmith, Arize, and others require significant integration work and configuration. Aktov's open-source SDK with framework auto-detection and schema canonicalization makes adoption frictionless for solo devs and small teams.

**Privacy differentiation**: Most LLM observability tools ingest full prompts, completions, and tool call arguments to their cloud. Aktov's SAFE mode (default) transmits only semantic flags — no raw arguments leave the machine. This is a structural trust advantage, not a feature toggle.

**Open-core differentiation**: The open-source rule library ("Sigma for agents") creates community-driven detection rule growth. Competitors with closed rule sets can't match community contributions. The compounding moat is the full system: canonicalization at the edge, rule ecosystem, corpus + tuning loops (threshold calibration, archetype priors, suppression logic), and distribution (dev-first wedge). Statistical models are commodity math — the value is in the *tuned system* built on real agent trace data.

**Agent team differentiation**: No existing product monitors the behavioral patterns of autonomous agent teams. Cross-agent correlation, poisoned artifact propagation detection, and emergent capability analysis are novel detection surfaces.

Aktov's unique position: **post-prompt, pre-consequence detection** — analyzing what agents _do_ after receiving instructions, not filtering the instructions themselves. Open-source rules + cloud statistical modeling + SAFE-mode privacy. Cloudflare for agentic detections.

---

## Success Metrics

### Phase 0: Ship It (Months 1-3)

- **Month 2**: OSS SDK on PyPI, Phase 0 cloud live (FastAPI + Postgres + 12 rules + webhook alerts)
- **Month 3**: 10 beta users, 50K traces ingested, first real alert fired, cold-start validated

### Phase 1: Stats + Growth (Months 4-8)

- **Month 5**: Bigram + Markov scoring live, baseline dashboards, 500 OSS installs
- **Month 8**: 2,000 OSS installs, 100 cloud signups (free + indie), 30 paying customers, $1,500 MRR, community rules appearing

### Phase 2: Scale (Months 9-14)

- **Month 11**: 5,000 OSS installs, 150 paying customers, $8,000 MRR, agent team awareness (v1.5) in beta
- **Month 14**: 10,000 OSS installs, 300 paying customers, $18,000 MRR, first enterprise customer

### Phase 3: Enterprise (Months 15-18)

- **Month 15**: Agent team detection (Layer 4) GA, 5 enterprise customers ($499+/month), $25K MRR
- **Month 18**: 500 paying customers, $45K MRR, 50+ community-contributed detection rules

---

## Open Questions for Development

### Trace Ingestion & Infrastructure

1. Should trace ingestion support batch mode (array of traces per request) for high-volume agent team customers (16+ agents generating traces simultaneously)?
2. ~~Mode validation~~ **RESOLVED**: Server **strictly rejects** SAFE traces containing raw `arguments` (422). SDK provides `AK_DEV_MODE=1` env var to allow sending debug fields during local development without switching modes. In production, mode is enforced.

### Behavioral Modeling Engine

3. What's the right baseline recomputation cadence? Online incremental updates per-trace for n-gram/Markov, with daily full recomputation as consistency check — is this sufficient, or do enterprise customers need on-demand recomputation triggers?
4. ~~N-gram order~~ **RESOLVED**: v1 uses **bigrams only**. Trigrams added in v1.1 when per-archetype trace counts exceed 5K. 4-grams deferred. Reduces scope and avoids sparsity in low-volume agents.
5. Laplace smoothing parameter α = 1.0 as default — should this be tunable per-customer or per-agent-archetype? Some archetypes have naturally more variable behavior and need softer smoothing.
6. CUSUM drift detection window: 7-day rolling window for anomaly score drift. Is this appropriate for all agent types? Long-running infrastructure agents may need longer windows; short-lived task agents may need shorter.
7. ~~State representation~~ **RESOLVED**: The `semantic_flag_digest` uses low-cardinality semantic flags only (sql_statement_type, http_method, is_external, etc.). Digest is a canonical sorted key-value string. These flags are always available in both SAFE and DEBUG modes, ensuring full statistical model fidelity.

### Detection Quality

8. ~~Python DSL sandboxing~~ **RESOLVED**: v1 SaaS supports YAML rules + constrained expression language only for customer-authored rules. Python DSL is reserved for Aktov-authored system rules. Customer Python DSL available only in future on-prem/local tier or via hardened sandbox (microVM/WASM). This eliminates the RCE-as-a-feature risk.
9. ~~Alert deduplication~~ **RESOLVED**: Suppress repeated alerts for same `rule_id + agent_id` within a **1-hour window** with count aggregation. Configurable window in v1.1. For statistical layers (L2/L3), deduplication is score-threshold-based: only re-alert if anomaly score increases by >1σ from the suppressed alert.
10. ~~Cold start~~ **RESOLVED**: **Deterministic rules only for the first 30 traces per agent_type.** After 30 traces, bigram frequency tables activate. Markov scoring activates after 100 traces. No cross-customer data sharing in v1. Curated archetype priors (e.g., "summarizer typically uses read→summarize→write") shipped as defaults in cloud — not learned from customer data, hand-authored by Aktov.

### Open-Core & Community

11. What's the right governance model for community-contributed detection rules? PR review process, quality bar, attribution?
12. Should the OSS SDK support local rule evaluation without any cloud connection (fully offline mode)?

### Agent Teams

13. How should coordination events be ingested — as part of the trace payload (current design) or as a separate event stream? Separate stream allows coordination monitoring even when individual traces aren't sent (e.g., agent team using third-party harness that doesn't have Aktov SDK).
14. For Granger causality analysis on merge events (CW-101): what minimum trace volume per-agent is needed for statistically significant causal inference? Preliminary estimate: 50+ traces per agent, meaning teams need to be running for several hours before temporal causality detection activates.
15. Team capability graph analysis (CW-103) requires modeling cross-agent resource dependencies. Should this be statically declared by the customer (explicit capability manifest per agent) or dynamically inferred from observed tool usage? Dynamic inference is more powerful but requires longer baseline period.

### Enterprise Readiness

16. Should v1 support agent auto-registration (first trace creates the agent record) or require explicit registration? Enterprise customers likely want explicit registration with approval workflows.
17. RBAC model for team access: who can view alerts, modify privacy config, manage rules? Enterprise customers will need role-based access control from day one.
