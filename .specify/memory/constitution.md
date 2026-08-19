# SIEM v2 Constitution

Governing principles for a security information and event management platform that
collects, normalizes, correlates, and retains security-relevant log and telemetry data.

## Core Principles

### I. Ingest Never Blocks (NON-NEGOTIABLE)

Log collection MUST NOT lose events and MUST NOT stall upstream producers. Every collector
writes to a durable, replayable buffer (append-only queue or WAL) before any parsing,
enrichment, or indexing occurs. Downstream failure (parser crash, index unavailable,
correlation backlog) degrades latency, never durability. Backpressure is applied at
well-defined boundaries with bounded queues and explicit drop policy; any drop MUST be
counted, logged, and alerted — silent loss is a defect. All pipeline stages are idempotent
and keyed so replay after failure cannot duplicate results.

**Rationale:** A SIEM that loses events during the incident it exists to detect is worse
than no SIEM, because it creates false confidence in a clean timeline.

### II. Normalize at the Edge, Preserve the Raw

Every event is normalized to a single documented schema (ECS-compatible field names, RFC 3339
UTC timestamps, explicit `event.dataset` / `observer` / `host` identity) as early in the
pipeline as possible. The unmodified raw payload MUST be retained alongside the normalized
form for the full retention period. Parsers are versioned, declarative where possible, and
paired with fixture-based regression tests using real (sanitized) samples. Unparseable input
lands in a dead-letter stream with the raw bytes and parse error — never discarded, never
force-fit into wrong fields.

**Rationale:** Correlation and hunting are only possible on a common schema; forensics and
re-parsing after a parser bug are only possible from the raw.

### III. Detections Are Code, Tested Like Code (NON-NEGOTIABLE)

Correlation rules, detections, and enrichment logic live in version control, are reviewed,
and ship through the same pipeline as application code. Every rule MUST have: a stated
hypothesis, MITRE ATT&CK mapping where applicable, at least one true-positive fixture that
fires it and at least one near-miss fixture that does not, and a documented severity and
response expectation. Rules are written test-first: the fixture and expected alert exist and
fail before the rule is implemented. No rule reaches production without passing its fixtures
in CI.

**Rationale:** An untested detection is an unverified claim about safety; rule rot and silent
non-firing are the dominant SIEM failure mode.

### IV. The Pipeline Monitors Itself

The system MUST continuously verify its own liveness and correctness, not merely export
metrics. Required signals per source, per stage: events in/out, parse failure rate,
end-to-end and per-stage latency, buffer depth, correlation windows evaluated, and alerts
produced. Absence of data is itself an alert condition: any source silent beyond its expected
cadence, and any stage whose output rate falls to zero while input continues, MUST raise an
operational alert. Health checks assert semantic outcomes (correlations produced, alerts
delivered), never just process liveness. Where safe and deterministic, degraded stages
self-heal — restart, reconnect, rebuild state, or replay from the buffer — and every automatic
recovery is logged with cause and outcome.

**Rationale:** SIEM outages are usually silent: the dashboards stay green while zero events
flow. Detecting "zero" must be as loud as detecting an attack.

### V. Security and Tenancy Are Design Constraints, Not Features

Data is encrypted in transit (mTLS between collectors and ingest) and at rest. Every access
to event data is authorized against an explicit tenant and role, enforced server-side at the
query layer — never by client-side filtering. Access to log data is itself audited into an
append-only stream that operators cannot alter. Secrets come from a secret manager or
environment, never source or config files in the repo. Fields carrying credentials, tokens,
PII, or regulated data are classified in the schema and masked or tokenized by policy before
storage. Retention, deletion, and legal-hold behavior are configuration, enforced by the
platform.

**Rationale:** A SIEM aggregates the most sensitive data in the estate; a compromise of it is
a compromise of everything it watches.

### VI. Deterministic, Reproducible Analysis

Given the same events and the same rule version, correlation MUST produce the same result.
Time semantics are explicit everywhere: event time drives correlation windows, ingest time is
recorded separately, and out-of-order and late-arriving events are handled by a stated
watermark policy rather than incidentally. Correlation state is externalized and recoverable
so a restart resumes rather than resets. Every alert carries the rule version, the window, and
the identifiers of the contributing events so an analyst can reconstruct exactly why it fired.

**Rationale:** An alert an analyst cannot reproduce or explain is an alert they will learn to
ignore.

### VII. Bounded, Measured Cost

Storage tiering (hot / warm / cold / archive), retention per dataset, and index cardinality
are explicit configuration with defined defaults, not emergent behavior. Any change to
parsing, enrichment, or indexing MUST state its expected effect on volume, cardinality, and
query cost. High-cardinality fields are indexed only with justification. Ingest volume and
storage growth are tracked per source and alerted on deviation, so a misbehaving log source is
caught in hours, not on the invoice.

**Rationale:** Uncontrolled cost is the reason SIEM coverage gets cut, which turns a budget
problem into a security gap.

## Operational & Data Requirements

- **Schema governance:** The normalized schema is versioned; field additions are backward
  compatible, field removals or type changes are breaking and require a migration plan plus a
  re-parse or dual-write strategy for existing data.
- **Time integrity:** Collectors record their own clock skew; events with implausible
  timestamps are flagged, not silently corrected.
- **Source onboarding:** A new log source is not "onboarded" until it has a parser with
  fixtures, a documented expected event cadence used for silence alerting, a retention and
  classification decision, and at least one detection or a written statement that none applies.
- **Delivery guarantees:** At-least-once end to end, with idempotent writes keyed on a stable
  event ID so at-least-once presents as effectively-once in query results.
- **Performance targets:** Ingest-to-searchable and ingest-to-alert latency have stated SLOs
  per tier; sustained ingest throughput and burst capacity are stated and load-tested. Targets
  live in the plan for each feature and are verified before release.
- **Availability:** Collection survives control-plane loss — collectors buffer locally and
  drain on recovery. Planned maintenance of query or correlation tiers never stops ingest.
- **Data handling:** No production event data in development environments unless sanitized;
  fixtures committed to the repo MUST be sanitized and MUST NOT contain real credentials, keys,
  or personal data.

## Development Workflow & Quality Gates

- **Test-first, always:** Tests are written and failing before implementation. Minimum 80%
  coverage on parsing, correlation, and access-control code; these paths additionally require
  fixture-based tests, not only unit tests.
- **Required test layers:** unit (parsers, rule predicates, schema mapping), integration
  (collector → buffer → parse → index → query, against real dependencies), and end-to-end
  replay (a recorded attack scenario produces the expected alerts within SLO).
- **Immutability in code:** Event records and configuration are treated as immutable values;
  transformations return new objects. In-place mutation of an event as it moves through the
  pipeline is prohibited — it destroys replayability and makes provenance unreconstructable.
- **File organization:** Small, focused modules organized by domain (collector, parser,
  pipeline, correlation, query, tenancy). 200–400 lines typical, 800 hard maximum.
- **Boundary validation:** All external input — agent payloads, syslog frames, API requests,
  rule definitions, configuration — is schema-validated at the boundary and rejected with a
  clear, non-leaking error.
- **Error handling:** Errors are handled explicitly at every level, never swallowed. Server
  logs carry full context; user-facing messages disclose nothing about internal structure or
  other tenants.
- **Review gates:** Every change is reviewed for correctness, security, and constitution
  compliance. Changes touching parsing, correlation, retention, or access control require a
  security-focused review. CRITICAL and HIGH findings block merge.
- **Pre-merge checks:** No hardcoded secrets; parameterized queries only; rate limits on all
  external endpoints; new or changed rules pass their fixtures; migrations have a tested
  rollback.
- **Operational readiness:** No feature ships without its metrics, its silence/zero-output
  alert, its runbook entry, and a stated rollback procedure.

## Governance

This constitution supersedes other practices and conventions in this project. Where a
guideline elsewhere conflicts with a principle here, this document wins.

- Every plan MUST pass the Constitution Check gate before design work proceeds, and again
  before implementation.
- Violations are permitted only when recorded in the plan's Complexity Tracking section with
  the principle violated, the concrete reason no compliant alternative works, and the simpler
  approach that was rejected and why. "Faster to build" is not a justification.
- Principles marked NON-NEGOTIABLE (I, III) admit no exceptions; a change requiring one is a
  constitutional amendment, not a plan waiver.
- Amendments require a written rationale, review approval, a migration plan for affected code
  and data, and a version bump. Semantic versioning applies: MAJOR for removed or redefined
  principles, MINOR for a new principle or materially expanded requirements, PATCH for
  clarifications that do not change obligations.
- Compliance is re-verified at review time, not assumed from prior approval. Any production
  incident traced to a principle violation triggers a review of whether the gate that should
  have caught it needs strengthening.

**Version**: 1.0.0 | **Ratified**: 2026-08-18 | **Last Amended**: 2026-08-18
