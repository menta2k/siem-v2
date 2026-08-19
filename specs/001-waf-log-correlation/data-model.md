# Data Model: Multi-Provider WAF Log Correlation & Request Flow Analysis

**Feature**: `001-waf-log-correlation` | **Date**: 2026-08-18 | **Phase**: 1

Derived from the spec's Key Entities, constrained by Phase 0 research. Storage placement follows from
R6 (cardinality), R7 (retention gaps) and R8 (tenancy enforcement).

## Storage placement

| Store | Holds | Why |
|---|---|---|
| **VictoriaLogs** | Raw Record, Normalized Event, Request Flow (materialized), Dead-Letter Record | Append-only, high-volume, time-ranged, full-text searchable on every field |
| **PostgreSQL** | Access Principal, Tenant, Log Source, Detection, Alert, Evaluation Run, Retention Policy, Legal Hold, Audit Record | Mutable, relational, transactional; audit needs immutability guarantees VictoriaLogs cannot give (R7) |
| **Valkey** | In-flight correlation state, query cache, rate-limit counters | Hot, short-lived, keyed; persistence enabled so restart resumes (FR-023) |
| **RustFS** (S3-compatible, Object Lock) | Cold partitions, immutable audit export, legal-hold copies | Supplies the immutability and long retention VictoriaLogs lacks. Accessed via the S3 API only. ⚠️ Object Lock enforcement is unverified — V9 (R13) |

## VictoriaLogs field discipline (R6 — non-negotiable)

**Stream fields (low cardinality only)**: `tenant`, `provider`, `dataset`, `zone`, `record_kind`

**Regular fields (any cardinality, all indexed)**: `correlation_key`, `ray_id`, `client_ip`, `flow_id`,
`rule_id`, `user_agent`, everything else.

> The VictoriaLogs docs state near-verbatim that `ip`, `user_id` and `trace_id` must **never** be stream
> fields. Violating this degrades ingestion and query performance and inflates disk I/O. There is no cost
> to compliance: all fields are indexed for search regardless of cardinality, and exact field match
> (`correlation_key:="..."`) is the documented fast path.

---

## Core entities

### Raw Record
One provider log entry exactly as delivered. Immutable.

| Field | Type | Notes |
|---|---|---|
| `raw_id` | ULID | Deterministic from source + batch + line offset, so redelivery yields the same id (FR-007) |
| `tenant` | string | Stream field |
| `provider` | enum | `cloudflare` \| `datadome` \| `f5asm` \| `nginx` |
| `source_id` | string | FK → Log Source |
| `received_at` | timestamp | When we received it (FR-011) |
| `batch_id` | string | Delivery batch, for replay and dedup |
| `payload` | bytes/string | Unmodified original (FR-010) |
| `content_encoding` | string | As delivered |
| `parser_version` | string | Version that processed it |
| `record_kind` | const | `raw` — stream field |

*Retention*: same schedule as its normalized event (FR-010).

### Normalized Event
Common-schema interpretation of one raw record. Schema in
[`contracts/normalized-event.schema.json`](./contracts/normalized-event.schema.json).

| Group | Fields |
|---|---|
| Identity | `event_id`, `raw_id`, `tenant`, `provider`, `dataset`, `schema_version`, `parser_version` |
| Correlation | `identifiers[]` (**all** per-request ids this record carries — the bridge input, R11a), `correlation_key`, `correlation_key_source` (`ray_id`\|`vendor_request_id`\|`heuristic`), `ray_id`, `vendor_request_id` |
| Time | `event_time` (at provider), `received_at`, `clock_skew_ms`, `time_quality` (`ok`\|`skewed`\|`implausible`) |
| Layer | `layer` (`edge`\|`bot_management`\|`app_firewall`\|`origin`), `layer_order_hint` |
| Client | `client_ip`, `client_asn`, `client_country`, `user_agent` |
| Request | `http_method`, `http_host`, `http_path`, `http_query`, `http_version`, `request_headers`, `request_body_ref`, `body_truncated` |
| Response | `response_status`, `response_bytes`, `duration_ms` |
| Verdict | embedded Verdict (below) |
| Quality | `data_quality_flags[]`, `unmapped_fields{}` |

**Validation rules**
- `event_time` and `received_at` both required, RFC 3339 UTC (FR-011).
- `event_time` more than 24h in the future or 30d in the past → `time_quality: implausible`, flagged not
  corrected (FR-013).
- Unrecognized provider values → `unmapped_fields`, surfaced verbatim, never coerced (FR-014).
- Classified sensitive fields masked/tokenized **before** write (FR-015).
- Parse failure → Dead-Letter Record, never a partial event (FR-012).

### Verdict
One layer's decision. Embedded in Normalized Event, projected into Request Flow.

| Field | Type | Notes |
|---|---|---|
| `action` | enum | `allowed`\|`logged`\|`rate_limited`\|`challenged`\|`challenge_passed`\|`challenge_failed`\|`blocked` (FR-025) |
| `terminating` | bool | Did this decision end the request (FR-027) |
| `rule_id` / `rule_name` / `rule_version` | string | Provider rule identity |
| `category` | string | Attack/violation class |
| `score` / `threshold` | number | e.g. DataDome bot score, CRS anomaly score |
| `reason_raw` | object | Provider's unmodified decision content (FR-028) |
| `mapped` | bool | False → surfaced as unmapped (FR-014) |

**Provider mapping notes (R3, R4)**
- Cloudflare: from `SecurityAction`/`SecurityRuleID` + `Security*` arrays, **or** legacy
  `WAFAction`/`WAFRuleID`/`FirewallMatches*` — **which family is populated is V5, unverified**.
- DataDome: extracted from `X-DataDome-*` fields **inside the Cloudflare record** (R3), not a separate
  source. `X-DataDome-Traffic-Rule-Response` carries the action but is plan-gated and off by default.
- F5 ASM: violations/signatures/attack types from the syslog or key-value format.
- nginx: status code only; `layer: origin`, usually non-terminating.

### Request Flow
The materialized correlated unit — the primary read object (R5).

| Field | Type | Notes |
|---|---|---|
| `flow_id` | ULID | |
| `tenant` | string | Stream field |
| `correlation_key` | string | Regular field (R6) |
| `events[]` | array | Ordered Normalized Events, causal order (FR-017) |
| `layers_present[]` / `layers_missing[]` | array | Absent layers explicit, never silently omitted (FR-019) |
| `completeness` | enum | `complete`\|`partial`\|`ambiguous` |
| `correlation_method` | enum | `exact`\|`heuristic` (FR-072c) |
| `correlation_confidence` | float | 0–1 |
| `effective_outcome` | enum | Final normalized action (FR-027) |
| `terminating_layer` | enum | Which layer ended it |
| `first_seen` / `last_seen` / `closed_at` | timestamp | |
| `timing_attribution` | map | Per-layer duration (FR-029) |
| `amended` | bool | True if a record arrived after close (FR-018 edge case) |
| `data_quality_flags[]` | array | Skew, truncation, unmapped, masked |

**State transitions**

```
open ──(all expected layers present)──────────→ complete
  │
  ├──(late-arrival window elapsed, layers missing)──→ partial
  │
  └──(≥2 equally-good candidates)──────────────────→ ambiguous

complete/partial ──(record arrives post-close)──→ amended (in place, never a second flow)
```

**Rules**
- Causal order from the known path (edge → bot_management → app_firewall → origin), **not** raw
  timestamp order (FR-017, and the clock-skew edge case).
- Late-arrival window default 15 min (spec Assumptions); after that the flow closes partial (FR-019) so
  in-flight state stays bounded.
- Ambiguous matches are never resolved by guessing (FR-021, FR-072d).
- Reprocessing the same records yields an identical flow (FR-022).

### Correlation Identifier Bridge (R11a, FR-072f/g)

Each record contributes an **identifier set**, not a single key. Records are unioned transitively across
shared identifiers; a component's canonical id is its smallest member, so flow identity is deterministic
regardless of arrival order (FR-022, FR-072g).

| Provider | Identifiers carried |
|---|---|
| Cloudflare | `RayID` **and** `x-datadome-requestid` — the bridging record |
| DataDome (pull) | `requestid` |
| nginx | `CF-Ray` |
| F5 ASM | `CF-Ray` (subject to V2) |

DataDome and nginx share no identifier directly; they join **transitively at exact tier** through the
Cloudflare record. This is why the Cloudflare custom-field capture matters even though pull already
delivers complete DataDome decisions.

### In-flight Correlation State (Valkey)
`key: {tenant}:{correlation_key}` → partial flow + arrival log. TTL = late-arrival window. Persistence
on, so restart resumes rather than resets (FR-023).

### Dead-Letter Record
`dl_id`, `raw_id`, `provider`, `payload`, `failure_reason`, `parser_version`, `received_at`,
`reprocess_state` (`pending`\|`reprocessed`\|`abandoned`). Never discarded; reprocessable after a parser
fix (FR-012, FR-063).

---

## Relational entities (PostgreSQL)

### Tenant / Access Principal
`tenant(id, name, vl_account_id, vl_project_id, retention_policy_id, created_at)` —
`vl_account_id`/`vl_project_id` map to VictoriaLogs' advisory tenancy headers, injected **server-side
only** (R8).

`principal(id, tenant_id, identity, role, property_scope[], permissions[], active)`. Roles: `analyst`,
`engineer`, `admin`. Permissions include `view_flows`, `view_raw`, `view_sensitive`, `export`,
`run_evaluation`, `manage_detections`, `manage_retention`, `manage_sources`.

> **FR-074b**: the API never accepts raw LogsQL. Structured parameters are compiled to LogsQL
> server-side with tenant headers injected, so cross-tenant access is *inexpressible*, not merely
> refused — and LogsQL injection is closed off (R8).

### Log Source
`id, tenant_id, provider, delivery_mode, push_config, pull_config, pull_watermark,
expected_cadence_seconds, data_classification, retention_policy_id, parser_version, detection_posture,
enabled, last_record_at, health_state`

- `delivery_mode` ∈ `push` | `pull`. Cloudflare pushes; nginx and F5 are agent-delivered; **DataDome is
  pulled** from its log export API (R3).
- `pull_config` = `{endpoint, interval_seconds}`; `pull_watermark` is the per-source resume point, so a
  restart neither re-reads nor skips a window (FR-001a).

`expected_cadence_seconds` drives silence alerting (FR-044). A source is not onboarded until parser +
fixtures + cadence + classification + retention + detection posture all exist (FR-008).

### Detection
`id, name, version, condition, severity, category, expected_response, fixtures_ref, mitre_attack[],
enabled, baseline_stats`

Defined in versioned repo files, loaded into PostgreSQL on deploy. **Activation is gated on passing one
positive and one near-miss fixture** (FR-051, Constitution III).

### Alert
`id, tenant_id, detection_id, detection_version, fired_at, severity, evidence, linked_flow_ids[],
delivery_state, acknowledged_by, acknowledged_at, grouping_key, suppressed_until`
(FR-048, FR-049, FR-050)

### Evaluation Run
`id, tenant_id, flow_id, event_id, engine (owasp_crs|cf_expression), engine_version, ruleset_version,
parameters (paranoia_level, thresholds), expression, operator_id, started_at, completed_at,
matched_rules[], anomaly_score, resulting_action, input_completeness, compared_to_run_id, outcome`

- `engine_version` + `ruleset_version` pinned per run so FR-033/SC-015 repeatability survives upgrades.
- `input_completeness` records truncated/masked/expired input so FR-035's warning is data-driven.
- **`anomaly_score` extraction is V1 — unverified.** Coraza has no typed accessor; the value lives in
  `TX:ANOMALY_SCORE`. Must be validated empirically before this field is trusted.

### Retention Policy / Legal Hold
`retention_policy(id, name, hot_days, warm_days, cold_months, data_category, applies_to)` — one
VictoriaLogs tenant/instance **per retention class**, because retention is a per-instance flag and expiry
is per-day-partition (R7).

`legal_hold(id, tenant_id, scope_filter, reason, placed_by, placed_at, released_at, preserved_refs[])` —
enforced by `retentiond`, which refuses expiry while a hold is open and copies held partitions to
Object-Locked storage in RustFS. VictoriaLogs cannot enforce this itself (R7).

> **The hold registry is the primary enforcement, and Object Lock is defence in depth — deliberately.**
> `retentiond` refusing expiry does not depend on the object store honouring Object Lock, so a V9 failure
> degrades tamper-resistance without breaking hold correctness.

### Audit Record
`id, tenant_id, principal_id, action, scope, target_ref, occurred_at, outcome, detail` — append-only,
no UPDATE/DELETE grant to any application role, periodically exported to Object-Locked storage in RustFS.
Covers every data access, export, evaluation and configuration change (FR-055).

> PostgreSQL grants are the first line of defence; the Object-Locked export is what makes the trail
> provably unalterable. **That second guarantee is contingent on V9.**

---

## Entity relationships

```
Tenant ─┬─< Access Principal
        ├─< Log Source ──< Raw Record ──1:1─> Normalized Event ──*:1─> Request Flow
        │                      │                                          │
        │                      └──(parse failure)──> Dead-Letter Record    │
        ├─< Retention Policy ──< Legal Hold                                │
        ├─< Detection ──< Alert ────────────────(evidence)─────────────────┤
        └─< Evaluation Run ────────────────────(subject)───────────────────┘

Audit Record ──references──> every action above
```

## Cross-cutting validation

| Rule | Requirement |
|---|---|
| All external input schema-validated at the boundary | FR-058 |
| Sensitive fields classified and masked before storage | FR-015, FR-056 |
| Events immutable once written; transformations produce new values | Constitution — Development Workflow |
| Every write carries tenant, injected server-side | FR-074, R8 |
| Every raw record has a deterministic id for idempotent redelivery | FR-007 |
| Correlation key never a stream field | R6 |
