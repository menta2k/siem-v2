# Implementation Plan: Multi-Provider WAF Log Correlation & Request Flow Analysis

**Branch**: `001-waf-log-correlation` | **Date**: 2026-08-18 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/001-waf-log-correlation/spec.md`

## Summary

Collect WAF and access logs from Cloudflare (Logpush push), DataDome (**pull** from its log export API,
plus header enrichment captured inside the Cloudflare record), F5 BIG-IP ASM and nginx (both via Vector);
normalize them to one schema;
correlate the records belonging to a single HTTP request into an ordered request flow despite
out-of-order, delayed and duplicate delivery; express each layer's verdict and reason in a common
vocabulary; and let an operator re-evaluate a captured request against OWASP CRS or a Cloudflare rule
expression to test a verdict without touching production.

The technical approach that follows from Phase 0 research:

- **Correlation happens at ingest time, in the Go processor**, writing a materialized flow document —
  not at query time via LogsQL's `join` pipe, which buffers the joined side in RAM and does not survive
  SIEM-scale windows (R5).
- **Records carry identifier *sets*, unioned transitively**, so DataDome joins nginx at exact tier
  through the Cloudflare record that carries both ids — no clock dependence (R11a).
- **OWASP evaluation is embedded** (Coraza, pure Go); **Cloudflare rule evaluation is a Rust sidecar**
  (wirefilter has no viable Go binding and a moving C ABI) (R1, R2).
- **Tiering, legal hold and the audit trail live outside VictoriaLogs**, which has no tiered storage, no
  immutability and only per-day-partition expiry (R7).
- **Tenant isolation is enforced by our gateway**, because VictoriaLogs' tenancy headers are advisory and
  unauthenticated (R8).

## Technical Context

**Language/Version**: Go 1.25.4 (backend, verified locally); Rust 1.93 (wirefilter sidecar only);
TypeScript / Node 23.3 (frontend)

**Primary Dependencies**:
- Backend: go-kratos/kratos v2 (framework), Coraza v3.7.0 + coraza-coreruleset v4.25.0 (CRS 4.25 LTS),
  NATS JetStream client, VictoriaLogs HTTP clients, Valkey client, `pgx` (PostgreSQL), protobuf +
  `protoc-gen-openapi` for API docs
- Sidecar: cloudflare/wirefilter (pinned), axum or tonic
- Frontend: Nuxt 3 + Vuetify 3
- Collection: Vector (nginx `file` source, F5 `syslog` source)
- Object storage: RustFS (S3-compatible); AWS SDK for Go v2 as the client, no vendor-specific calls

**Storage**:
- VictoriaLogs — raw records, normalized events, materialized flows (hot + warm)
- PostgreSQL — users/roles/tenants, detections, evaluation runs, retention policies, legal holds,
  source config, append-only audit trail
- Valkey — in-flight correlation state (persistence enabled), query cache, rate limiting
- NATS JetStream — durable replayable ingest buffer
- **RustFS** (S3-compatible object storage) with Object Lock — cold archive, immutable audit export,
  legal-hold preservation. Accessed via the S3 API only, so any S3-compatible store is a config swap (R13)

**Testing**: `go test` (table-driven) + `testcontainers-go` for integration against real VictoriaLogs /
PostgreSQL / Valkey / NATS; fixture-based parser and detection tests; Vitest + Playwright (frontend);
recorded-scenario replay for end-to-end

**Target Platform**: Linux x86-64; each service as a standalone static binary and as a container

**Project Type**: Multi-service web application — backend log processor, backend API service, rule
sidecar, frontend

**Performance Goals**: 2,000 records/sec sustained per provider, ≥8,000/sec combined, 3× burst for 5
minutes with zero loss; 95% searchable within 30s; 95% of flows complete within 60s of the last
contributing record; 95% of hot-window searches under 5s; OWASP evaluation under 10s

**Constraints**: No record loss under any downstream failure; collection continues while query/frontend
tiers are down; evaluation cannot affect production traffic; deterministic re-evaluation; tenant scope
enforced server-side; sensitive fields masked before storage

**Scale/Scope**: ~700M records/day at target rate; 4 providers (3 collection paths); 30d hot / 90d warm /
12mo cold default; single tenant at launch, multi-tenant-ready

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Gate | Pre-Phase-0 | Post-Phase-1 | How the design satisfies it |
|---|---|---|---|---|
| **I. Ingest Never Blocks** (NON-NEGOTIABLE) | Durable replayable buffer before parsing; no silent drops; idempotent replay | PASS | **PASS** | Logpush receiver and Vector legs write to NATS JetStream before any parsing (R9). Vector legs add disk buffers + end-to-end acks (R10). Dedup on RayID makes at-least-once delivery idempotent. Drops counted and alerted (FR-006). |
| **II. Normalize at Edge, Preserve Raw** | Common schema; raw retained full period; versioned parsers with fixtures; dead-letter never discards | PASS | **PASS** | Raw record stored in VictoriaLogs alongside normalized event, same retention. Parsers versioned with sanitized fixtures. Dead-letter stream with original bytes + parse error, reprocessable (FR-012, FR-063). |
| **III. Detections Are Code, Tested Like Code** (NON-NEGOTIABLE) | Rules in VCS; positive + near-miss fixtures; test-first; CI-gated | PASS | **PASS** | Detections in PostgreSQL but *defined* in versioned repo files, loaded on deploy; activation gated on passing a positive and a negative fixture (FR-051). |
| **IV. Pipeline Monitors Itself** | Per-source/per-stage signals; silence and zero-output alert; semantic health checks; logged self-heal | PASS | **PASS** | Metrics per source and stage (FR-060); source-silence and zero-output detections (FR-044, FR-045); health checks assert flows produced and alerts delivered (FR-061); bounded recovery logged with cause and outcome (FR-062). |
| **V. Security & Tenancy by Design** | mTLS; server-side tenant authz; immutable audit; secrets external; field classification | PASS | **PASS** ⚠️ | Backend is the sole gateway; clients never reach VictoriaLogs and never submit raw LogsQL (R8). Audit trail in PostgreSQL append-only + Object-Locked export to RustFS (R7, R13). Classification and masking pre-storage (FR-015). ⚠️ *VictoriaLogs mTLS is Enterprise-gated*, and ✅ *RustFS Object Lock verified enforced (V9 PASS, single-node)* — see Complexity Tracking. |
| **VI. Deterministic, Reproducible Analysis** | Same input + rule version → same result; explicit time semantics; recoverable state; alert provenance | PASS | **PASS** | Event time and receipt time stored separately (FR-011); watermark/late-arrival policy explicit (FR-024); correlation state persisted in Valkey (FR-023); Coraza determinism secured by disabling `@rbl`/`@geoLookup`/persistent collections and pinning CRS + engine versions (R2). |
| **VII. Bounded, Measured Cost** | Explicit tiering/retention/cardinality; volume deviation alerting | PASS | **PASS** ⚠️ | Cardinality rule enforced: correlation key is a regular field, never a stream field (R6). Volume and growth tracked per source with deviation alerting (FR-064). ⚠️ *Tiering is not native to VictoriaLogs* and must be built — see Complexity Tracking. |

**Gate result**: PASS with six justified deviations recorded in Complexity Tracking. No NON-NEGOTIABLE
principle is violated or waived. The RustFS deviation, previously the one unresolved risk, has been
**verified by conformance test (V9 PASS)** for single-node; residual risk is now the project's pre-1.0
maturity and untested distributed mode, not the correctness of Object Lock itself.

## Project Structure

### Documentation (this feature)

```text
specs/001-waf-log-correlation/
├── plan.md              # This file
├── spec.md              # Feature specification
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output
│   ├── README.md
│   ├── openapi.yaml             # Public REST API (generated from proto, checked in)
│   ├── proto/                   # Kratos/protobuf service definitions
│   ├── ingest-logpush.md        # Cloudflare Logpush receiver contract
│   ├── ingest-vector.md         # Vector → processor contract
│   ├── wirefilter-sidecar.md    # Go ↔ Rust evaluation contract
│   └── normalized-event.schema.json  # The common schema (Principle II)
├── checklists/
│   └── requirements.md
└── tasks.md             # Phase 2 output (/speckit-tasks — NOT created here)
```

### Source Code (repository root)

```text
backend/
├── api/                          # protobuf definitions + generated code + OpenAPI
│   ├── flow/v1/
│   ├── evaluation/v1/
│   ├── alert/v1/
│   ├── admin/v1/
│   └── openapi.yaml
├── cmd/
│   ├── logproc/                  # ingest + normalize + correlate (collection tier)
│   ├── apiserver/                # query, evaluation, alerting, admin (analysis tier)
│   └── retentiond/               # tiering, expiry, legal hold, archive
├── internal/
│   ├── conf/                     # config structs (Kratos)
│   ├── server/                   # HTTP/gRPC server wiring
│   ├── service/                  # Kratos service layer (API handlers)
│   ├── biz/                      # domain logic, storage-agnostic
│   │   ├── flow/
│   │   ├── verdict/
│   │   ├── evaluation/
│   │   ├── detection/
│   │   ├── retention/
│   │   └── tenancy/
│   ├── data/                     # repository implementations
│   │   ├── victorialogs/
│   │   ├── postgres/
│   │   ├── valkey/
│   │   └── jetstream/
│   ├── ingest/
│   │   ├── logpush/              # CF receiver: validation handshake, auth, gunzip, dedup
│   │   ├── vectorhttp/           # receiver for Vector-delivered nginx/F5
│   │   └── puller/               # DataDome log export polling + per-source watermark
│   ├── normalize/
│   │   ├── cloudflare/           # incl. x-datadome-* bridge id extraction
│   │   ├── datadome/             # one adapter, aliases pull + header field shapes
│   │   ├── f5asm/
│   │   ├── nginx/
│   │   └── schema/               # common schema types + versioning
│   ├── correlate/                # identifier union-find, ordering, late arrival, partial close
│   ├── owasp/                    # Coraza embedding
│   ├── cfrules/                  # client for the wirefilter sidecar
│   ├── alerting/
│   ├── audit/
│   └── observability/
├── configs/
├── test/
│   ├── fixtures/                 # sanitized provider samples per parser
│   ├── integration/
│   └── scenarios/                # recorded attack replays (end-to-end)
└── Makefile

wirefilter-svc/                   # Rust sidecar — the only Rust in the project
├── src/
├── Cargo.toml
└── Dockerfile

frontend/
├── app/
│   ├── pages/                    # search, flow detail, evaluation, alerts, admin
│   ├── components/
│   │   ├── flow/                 # timeline visualization
│   │   ├── verdict/
│   │   └── evaluation/
│   ├── composables/
│   └── plugins/
├── tests/
└── nuxt.config.ts

deploy/
├── docker/                       # per-service Dockerfiles
├── compose/                      # full local stack
├── vector/                       # nginx + F5 pipeline configs
├── victorialogs/                 # per-retention-class instances
├── rustfs/                       # object storage: buckets, Object Lock config, policies
└── vmauth/                       # tenant header mapping

Makefile                          # top-level: build, test, lint, docker, run
```

**Structure Decision**: Multi-service layout driven by two hard requirements. FR-065 and SC-022 demand
collection continue while the analysis tier is down, which forces `logproc` and `apiserver` to be
separately deployable — they are separate binaries, not one binary with flags. `retentiond` is separated
because tiering and expiry are long-running batch operations (VictoriaLogs deletion rewrites data, R7)
that must never share a process with the latency-sensitive ingest path. `wirefilter-svc` is isolated in
Rust for the reasons in R1. The backend follows Kratos' `biz`/`data`/`service` layering so domain logic
stays storage-agnostic — which matters here because R7 makes it likely the storage tiering will change.

## Complexity Tracking

> Deviations from the constitution or from the stated stack that require justification.

| Violation | Why Needed | Simpler Alternative Rejected Because |
|---|---|---|
| **Tiered retention and legal hold built outside the log store** (Principle VII expects tiering to be explicit configuration; FR-039/FR-040) | VictoriaLogs has no tiered storage, no S3 offload for queryable data, no immutability and no legal-hold primitive. Expiry granularity is a whole per-day partition; record-level deletion rewrites all stored logs (R7). Meeting FR-039/FR-040 requires a retention service, per-retention-class instances, and an Object-Locked cold archive in RustFS (R13). | Relying on `-retentionPeriod` alone cannot express per-category retention, cannot preserve data under hold past expiry, and cannot prove immutability for audit. Switching to a store with native tiering (Elasticsearch ILM, ClickHouse TTL+tiers) was rejected because VictoriaLogs is a stated stack choice and outperforms the alternatives on ingest cost for this volume; the gap is bounded and lives in one service. |
| **PostgreSQL added beyond the stated stack** | Transactional, mutable, relational state that a log store cannot hold: identities, roles, tenants, detections, evaluation runs, retention policies, hold registry, and an append-only audit trail operators cannot alter (FR-055). | Keeping this in VictoriaLogs was rejected: it is append-oriented, has no transactions or relational integrity, and `-delete.enable` gives no per-record protection — so it cannot satisfy the immutability the audit requirement depends on. |
| **NATS JetStream added beyond the stated stack** | Constitution Principle I (NON-NEGOTIABLE) requires a durable replayable buffer before parsing, and FR-063 requires operator-driven replay after a parser fix. | A hand-rolled disk WAL was rejected as a correctness-critical component not worth writing from scratch. Vector disk buffers alone were rejected because the Logpush leg never passes through Vector. Kafka/Redpanda was rejected as disproportionate at 8k eps and is recorded as the documented scale-out path. |
| **A Rust service in a Go project** (wirefilter sidecar) | No viable Go binding to wirefilter exists; its C ABI is actively changing; cgo would break portable builds and give no crash isolation for FR-073d (R1). | cgo binding rejected — forces a Rust toolchain into every Go build and Docker stage, kills cross-compilation, and shares a process with collection. Pure-Go reimplementation rejected — a second implementation of Cloudflare's expression semantics that silently drifts is a critical failure mode for a security tool. |
| **RustFS used pre-1.0 for compliance-critical storage** (Principle V requires an audit trail operators cannot alter; FR-040, FR-055) | Directed stack choice. Apache-2.0 and S3-compatible, avoiding MinIO's AGPL constraints, and consistent with the project's existing Rust footprint. Cold archive is write-once/read-rarely, so performance risk is low. | **Substantially mitigated. V9 PASS (2026-08-19)**: Object Lock is genuinely *enforced*, not merely API-accepted — delete refused under COMPLIANCE retention against root credentials, and refused under isolated legal hold even with `BypassGovernanceRetention: true` (R13). Remaining risk is maturity, not correctness: RustFS is pre-1.0 with maintainers advising against production use, and Distributed Mode is "Under Testing" while V9 exercised single-node only. Mitigations retained: S3 API only so any store is a config swap; the conformance test stays in CI; the audit/hold bucket stays separable. **Re-run V9 against the production topology before relying on it in a cluster.** |
| **VictoriaLogs mTLS is Enterprise-gated** (Principle V requires mTLS in transit) | Client-certificate verification at `vlstorage` is an Enterprise feature in VictoriaLogs. | Not a true waiver: VictoriaLogs is never client-reachable. It is confined to a private network segment reachable only by the backend, with TLS terminated at our gateway and mTLS enforced on every hop we control (collectors → ingest, service → service). If the deployment later requires mTLS to storage itself, that is an Enterprise licence decision, not a design change. |

## Phase Status

- [x] **Phase 0** — `research.md` complete; all Technical Context unknowns resolved; 9 empirical
      verification tasks (V1–V11) identified and carried forward
- [x] **Phase 1** — `data-model.md`, `contracts/`, `quickstart.md` generated; Constitution re-checked
- [ ] **Phase 2** — `tasks.md` (created by `/speckit-tasks`, not by this command)
