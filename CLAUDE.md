# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Aktov** — Detection engineering for AI agents. `pip install aktov` + 2 lines → alerts when agents do weird or risky things.

**Vision:** Cloudflare for agentic detections — enterprise-grade security accessible to solo devs.

**Business model:** Open-core. OSS SDK + deterministic rule library ("Sigma for agents"). Cloud adds statistical behavioral modeling, alerting pipeline, and dashboards.

**Current state:** Phase 0 ~80% complete. SDK (119 tests passing), Cloud (written, not DB-tested), 12 YAML rules (all firing). See `.claude/brain.md` for full context.

## Product Trajectory

```
Phase 0 (ship first)          Phase 1 (users + data)        v1.5                    v2+
─────────────────────         ──────────────────────        ─────────────           ──────────
FastAPI + Postgres             + Queue (Celery/Arq)          Agent teams             TypeScript SDK
12 deterministic rules         + Bigram novelty (L2)         Enterprise privacy      Inline blocking
Sync rule eval                 + Markov scoring (L3)         Trigram models          SIEM export
Webhook alerts                 + Baselines + drift           AK-100 series           Self-hosted
API key auth                   + Dashboards + UI                                     SOC 2
SAFE/DEBUG modes               + Stripe billing
Preview CLI                    + Clerk/Auth0
                               + TimescaleDB (if needed)
                               + Custom YAML rules API

One process, one database.     Add only when evidence        Enterprise demand       Scale demand
No Celery, Redis, Timescale.   triggers it (see gates).      warrants it.            warrants it.
```

## Architecture

### Privacy: SAFE / DEBUG (Two Modes)

- **SAFE (default):** No raw args leave. SDK computes semantic flags client-side (sql_statement_type, http_method, is_external, etc.) and transmits only those + tool_name, tool_category, timing, outcome status. Detection: ~70-80%.
- **DEBUG (opt-in):** Adds selective raw field transmission via allowlist. Detection: ~85-95%.
- **Preview CLI:** `aktov preview --trace <file>` shows exactly what will be sent.

### Detection: Layered Funnel of Fidelity

- **Layer 1 (Phase 0):** 12 deterministic rules on categorical fields + semantic flags. Baseline-free, SAFE-mode compatible.
- **Layer 2 (Phase 1):** Bigram frequency novelty detection. Activates after 30 traces per agent_type.
- **Layer 3 (Phase 1):** First-order Markov transition probability scoring. Activates after 100 traces.
- **Layer 4 (v1.5):** Agent team correlation (AK-100 series).

### Phase 0 Tech Stack

| Component | Choice | NOT in Phase 0 |
|---|---|---|
| Language | Python 3.12+ | |
| API | FastAPI | |
| Database | PostgreSQL 16 (JSONB) | TimescaleDB (Phase 1) |
| Detection | Sync eval in request path | Celery/Arq (Phase 1) |
| Alert delivery | Background thread / asyncio | Redis (Phase 1) |
| Auth | API key per org | Clerk/Auth0 (Phase 1) |
| Monitoring | Sentry | PostHog (Phase 1) |
| Billing | Manual / free | Stripe (Phase 1) |

### SDK: `aktov` (Open Source)

- Framework auto-detection: LangChain, OpenAI, Anthropic, MCP (v1), CrewAI + AutoGen (v1.1)
- Schema canonicalization: framework fields → `tool_name`, `tool_category`, `arguments`
- Tool category auto-mapping with customer override
- Semantic flag extraction (client-side, SAFE mode)
- Canonical trace schema: `tool_name`, `tool_category`, `semantic_flags`, `outcome` (status, error_class, response_size_bucket), `timestamp`, `latency_ms`

## Locked Decisions

These are final. Do not reopen.

| Decision | Answer | Rationale |
|---|---|---|
| Cold start | Deterministic rules only for first 30 traces per agent_type. Bigrams at 30, Markov at 100. | Avoids false positives on day 1 |
| N-gram order | Bigrams only in v1. Trigrams at 5K traces per agent_type. | Reduces scope, avoids sparsity |
| Retention | 30 days fixed (non-enterprise). 7 days for free tier. | Simple default, configurable later |
| Alert dedup | `(org_id, agent_id, rule_id)` suppressed 1 hour. Critical: only if identical evidence. | Prevents alert storms |
| Mode validation | Server rejects SAFE traces containing raw `arguments` (422). `AK_DEV_MODE=1` env var for local dev. | Strict enforcement |
| v1 SaaS rules | YAML + constrained expressions only for customers. Python DSL is Aktov-authored system rules only. | Eliminates RCE risk |
| Phase 0 rules | 12 baseline-free, SAFE-mode compatible rules (AK-001, 007, 010, 012, 020, 022, 023, 030, 031, 032, 041, 050) | Ship fast, high signal |

## Phase Gates

Do NOT add complexity until evidence triggers it.

| Complexity | Trigger |
|---|---|
| Async queue (Celery/Arq) | Ingestion p95 > 300ms or > 50 traces/sec sustained |
| TimescaleDB | Trace queries > 1s for 7-day time windows |
| Trigram models | Per-agent-type trace count >= 5K |
| Markov scoring | Per-agent-type trace count >= 100 |
| Auth provider (Clerk/Auth0) | Multi-user access needed or > 10 orgs |
| Enterprise privacy controls | Enterprise deal blocked on it |
| RBAC | Multi-user org requests it |
| Custom YAML rules API | Users ask for custom rules |

## GTM Priorities

First-mover advantage is critical. Speed > polish.

1. **OSS SDK + rule library on GitHub** — "Sigma for AI Agents", `pip install aktov`. This is the adoption flywheel.
2. **DEF CON Singapore paper** — establishes threat model credibility.
3. **Product Hunt / HN launch** — "2 lines of code. Detections in 5 minutes."
4. **Free cloud tier** — 5K traces, 3 agents, 7-day retention. Deterministic rules only. Conversion funnel to Indie ($19/mo).

**Positioning:** Lead with DX, not privacy. Privacy is a feature ("SAFE mode: nothing raw leaves your machine"), not the headline.

**Personas (priority order):**
1. Solo devs / indie hackers deploying AI agents
2. Security engineers at companies with production agents
3. Platform engineering teams
4. Enterprise CISOs (agent team architectures)

## Work Split (Parallel Streams)

Phase 0 can be parallelized into 4 independent streams:

| Stream | Scope | Dependencies |
|---|---|---|
| **SDK** | Python SDK, canonicalization (LangChain/OpenAI/Anthropic/MCP), SAFE/DEBUG modes, semantic flag extractors, preview CLI | None — ships to PyPI independently |
| **Cloud** | FastAPI ingestion API, Postgres schema (organizations, agents, traces, alerts, rules tables), API key auth, webhook sender | Needs canonical trace schema from SDK |
| **Rules** | 12 Phase 0 rules as YAML + Python DSL, rule evaluation engine, alert generation | Needs trace schema from SDK |
| **GTM** | GitLab repo setup, README/docs, landing page copy, DEF CON paper, PyPI package config | Can start immediately |

**Critical path:** SDK defines the canonical trace schema → Cloud + Rules consume it. GTM runs in parallel from day 1.

## Pricing (Open-Core)

| Tier | Price | Traces/Mo | What |
|---|---|---|---|
| OSS | $0 | — | SDK + 12 rules locally |
| Free Cloud | $0 | 5K | Cloud deterministic rules + alerts (7-day retention) |
| Indie | $19 | 25K | Cloud L1-3, webhooks, dashboards (30-day retention) |
| Pro | $79 | 250K | Custom rules, full anomaly history, priority support |
| Team | $249 | 1M | Multi-user, audit log export |
| Enterprise | $499+ | 5M | Agent teams (L4), SSO, SLA |
| Scale | Custom | 20M+ | Self-hosted, SIEM export, SOC 2 |

## Reference

The full specification lives in `context.md`. Key sections:

- **Privacy & Data Handling** — SAFE/DEBUG modes, data handling guarantees, self-threat model
- **Product Architecture** — Architecture diagram, canonical trace schema, detection rule format
- **Behavioral Modeling Engine** — N-gram, Markov, baseline computation, explainability
- **Build Phases** — Phase 0/1 scope, Phase 0 rule pack, phase gate checklist
- **Data Model** — Full PostgreSQL schema (Phase 0 tables + Phase 1 statistical tables)
- **API Design** — Trace ingestion, alerts, rules, baselines, example alert JSON + Slack notification
- **SDK Design** — Framework support matrix, canonicalization table, integration examples
- **Detection Rule Library** — Full AK rule catalog (Layer 1-4)
- **Go-To-Market** — Launch sequence, positioning, target personas
- **Key Technical Decisions** — 13 locked decisions with rationale

## Brain & Worklog

### Brain (`.claude/brain.md`)
- Read this file at the start of every session for project context
- When an important decision is made (architecture, tech choice, convention, pattern), add it to brain.md immediately
- Keep it concise — facts and rationale, not narrative

### Worklog (`.claude/worklog/`)
- After every work session or significant milestone, create/update a worklog entry
- File naming: `YYYY-MM-DD.md` (one file per day, append if multiple sessions)
- Format: What was done, files touched, decisions made, issues resolved, current state, next steps
- Always list files created/modified/deleted in the "Files touched" section
- This is the project's institutional memory — future sessions depend on it
