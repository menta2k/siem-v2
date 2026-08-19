# Quickstart & Validation Guide

**Feature**: `001-waf-log-correlation` | **Phase**: 1

How to run the stack and prove the feature works. Scenarios map to spec acceptance criteria; each is
runnable and has an unambiguous pass condition.

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Go | 1.25+ | Backend (Coraza v3.7.0 requires 1.25.0) |
| Rust | 1.80+ | wirefilter sidecar only |
| Node | 20+ | Frontend |
| Docker + Compose | recent | Full local stack |
| protoc | 3.20+ | API generation |

Verified present on this machine: Go 1.25.4, Rust/cargo 1.93, Node 23.3, Docker 29.3, Make 4.3,
protoc 28.3.

## Bring up the stack

```bash
make dev-up          # VictoriaLogs, PostgreSQL, Valkey, NATS JetStream, Vector, RustFS, wirefilter-svc
make migrate         # PostgreSQL schema
make seed-dev        # one tenant, one admin principal, four log sources, baseline detections
make run-logproc     # collection tier   (or: make run-all)
make run-apiserver   # analysis tier
make run-frontend    # Nuxt dev server on :3000
```

Standalone binaries without Docker:

```bash
make build           # -> bin/logproc, bin/apiserver, bin/retentiond
./bin/logproc   --conf configs/logproc.yaml
./bin/apiserver --conf configs/apiserver.yaml
```

## Makefile targets

| Target | Does |
|---|---|
| `make build` | All Go binaries, static, `CGO_ENABLED=0` |
| `make api` | Regenerate protobuf + OpenAPI; fails CI if the committed spec is stale |
| `make test` | Unit + fixture tests |
| `make test-integration` | testcontainers against real VictoriaLogs/PostgreSQL/Valkey/NATS |
| `make test-scenarios` | Recorded end-to-end attack replays |
| `make test-detections` | Every detection against its positive + near-miss fixtures (Constitution III gate) |
| `make lint` | golangci-lint, clippy, eslint |
| `make docker` | Container images for every service |
| `make load-test` | Sustained + burst load harness |
| `make test-objectlock` | **V9 gate** — proves Object Lock retention and legal hold are genuinely enforced against the configured S3 store |

---

## Validation scenarios

### S1 — Flow reconstruction from out-of-order delivery (P1, FR-016/017/018)

```bash
make test-scenarios SCENARIO=out-of-order
```

Replays a known corpus with providers deliberately delivered in reverse order, with delays and injected
clock skew.

**Pass**: every request yields one flow; layer order matches ground truth for 100% of the corpus
(SC-003); no duplicate flows; late records amend in place rather than creating a second flow.

### S2 — Duplicate and partial delivery (FR-007, FR-019)

```bash
make test-scenarios SCENARIO=duplicates-and-gaps
```

**Pass**: redelivered records produce no duplicate layer, count or alert evidence; requests missing a
provider close as `partial` after the late-arrival window with the absent layer listed in
`layers_missing` — never silently omitted.

### S3 — Verdict normalization (P2, FR-025/026/027)

```bash
make test SCENARIO=verdicts
```

**Pass**: each provider decision maps to the correct normalized action with its rule/signature, score
and threshold; the terminating layer is identified; unknown reason codes appear verbatim with
`mapped: false` rather than being coerced.

### S4 — OWASP evaluation (P3, FR-030/033)

```bash
curl -X POST localhost:8000/api/v1/evaluations \
  -H 'Authorization: Bearer <token>' \
  -d '{"engine":"owasp_crs","flow_id":"<known-sqli-flow>","paranoia_level":1}'
```

**Pass**: every matching CRS rule is listed (not just the first interruption), with anomaly score,
threshold and would-block; a benign request matches nothing; ten repeat runs are byte-identical
(SC-015); `engine_version` and `ruleset_version` are recorded.

> **V1 blocks the score half of this scenario.** Coraza exposes no typed anomaly-score accessor — the
> value lives in `TX:ANOMALY_SCORE`. Validate extraction empirically before treating `anomaly_score` as
> trustworthy.

### S5 — Cloudflare expression evaluation (FR-031, FR-073b)

```bash
curl -X POST localhost:8000/api/v1/evaluations \
  -d '{"engine":"cf_expression","flow_id":"<flow>","expression":"http.request.uri.path contains \"/admin\""}'
```

**Pass**: correct match/no-match with the determining fields; `fidelity_note` states this is
expression-level and not full Cloudflare product evaluation; predicates over uncaptured fields appear as
caveats, never as a silent false.

**Also verify degradation**: stop `wirefilter-svc`, re-run — the API reports evaluation unavailable while
OWASP evaluation and all other functions keep working.

### S6 — Pipeline self-monitoring (P4, FR-044/045)

```bash
make test-scenarios SCENARIO=pipeline-health
```

Stops one provider feed; separately stalls the correlation stage while ingest continues.

**Pass**: source-silence alert within 5 min of cadence lapse (SC-009); zero-output alert within 5 min
even though every process is still running and healthy by liveness check (SC-010). This is the scenario
the constitution's Principle IV exists for — a green dashboard over a dead pipeline must fail here.

### S7 — Durability (FR-004/005, SC-012)

```bash
make test-scenarios SCENARIO=kill-restart
```

Kills each component mid-load; takes VictoriaLogs down for 60s under sustained ingest.

**Pass**: zero record loss; in-progress flows resume from persisted correlation state rather than
resetting (FR-023); everything buffered during the outage drains on recovery.

### S8 — Load (SC-004/005)

```bash
make load-test RATE=2000 PROVIDERS=4 DURATION=24h
make load-test RATE=6000 PROVIDERS=4 DURATION=5m   # 3x burst
```

**Pass**: zero loss at 4×2,000/sec sustained; zero loss through the burst; 95% searchable within 30s;
95% of flows complete within 60s of the last contributing record.

> **V7**: run against realistic data shape, not synthetic uniform records — VictoriaMetrics' own
> guidance is to benchmark with 1–10% of real production data.

### S9 — Tenant isolation (FR-074, SC-027)

```bash
make test-integration SUITE=tenancy
```

**Pass**: no query, export, alert or evaluation returns out-of-tenant data across all attempts,
including deliberately malformed and injected inputs. Confirm by inspection that **no code path passes a
client-supplied string into LogsQL** — the structural guarantee behind FR-074b.

### S10 — Retention, hold and audit (P5/P6, FR-039/040/055)

```bash
make test-integration SUITE=retention
```

**Pass**: data past expiry is removed from every tier; held data survives its expiry and the prevented
expiry is recorded; audit entries exist for every access, export, evaluation and config change; no
application role can UPDATE or DELETE an audit row.

### S11 — Object Lock enforcement (V9, FR-040/FR-055) ✅ PASSING

```bash
make test-objectlock
```

Runs the S3 Object Lock conformance suite against whichever store is configured (RustFS by default):
enable Object Lock on a bucket, write an object under retention, apply a legal hold, then **attempt to
delete and overwrite both**.

**Pass**: `PutObjectLockConfiguration`, `PutObjectRetention` and `PutObjectLegalHold` all succeed, **and
the delete and overwrite attempts are actually refused**. An API that accepts the calls but still permits
deletion is a **failure**, not a partial pass — it is precisely the silent-non-guarantee this test exists
to catch.

> **Status: PASSING against `rustfs/rustfs:latest`, single-node (2026-08-19).** Delete was refused under
> COMPLIANCE retention using root credentials, and refused under isolated legal hold even when explicitly
> requesting `BypassGovernanceRetention`. FR-040 and FR-055 are proven at the storage layer.
>
> **Still re-run this against the production topology.** Upstream marks Distributed Mode "Under Testing"
> and the suite has only exercised single-node. The test stays in CI so an upstream regression or a store
> swap is caught rather than assumed.

---

## Configuration that must be right before real data flows

| Item | Why | Ref |
|---|---|---|
| Logpush `timestamp_format = "rfc3339"` | API default is `unixnano`; a mismatch silently misparses every timestamp | R4 |
| Logpush custom fields use **`transformed_request_fields`**, lower-case names | Worker-injected headers are NOT client-sent, so `request_fields` captures nothing; the dashboard cannot set transformed fields; capitalised names log nothing. All three fail silently | R3 |
| `x-datadome-requestid` among the captured headers | It is the bridge between DataDome's and Cloudflare's identifier spaces; without it DataDome joins degrade to heuristic | R11a |
| DataDome configured as a **pull** source, not the webhook | The webhook carries attack summaries with no per-request id — nothing to correlate | R3 |
| DataDome export includes **allowed** traffic | Blocks-only export makes "DataDome allowed, F5 blocked" invisible — a primary purpose of the system | R3 |
| Edge Log Delivery enabled | Standard Logpush has no max-delay SLA; SC-006/SC-007 depend on a bounded interval | R4 |
| nginx `log_format` includes `$http_cf_ray` | The exact join to Cloudflare depends on it | R11 |
| F5 logs `CF-Ray` (likely via iRule) | **V2, unverified** — if it fails, F5 falls back to heuristic join and SC-024 is unreachable for that layer | R11 |
| Vector disk buffers + end-to-end acks on | Without acks, a crash silently loses in-flight events | R10 |
| VictoriaLogs stream fields low-cardinality only | `correlation_key` as a stream field would degrade the whole store | R6 |
| `vmauth` in front of VictoriaLogs | Its tenancy headers are unauthenticated and advisory | R8 |
| RustFS bucket created **with Object Lock enabled at creation** | S3 Object Lock cannot be enabled on an existing bucket after the fact — getting this wrong means recreating the bucket and re-copying the archive | R13 |
| Object storage accessed via S3 API only, no RustFS-specific calls | Keeps the V9 risk cheap to reverse — swapping stores stays a config change | R13 |

## Outstanding verification items

V1–V9 from [research.md](./research.md#consolidated-verification-tasks-carried-into-phase-1) are carried
into `/speckit-tasks` as explicit spike and lab tasks. Three block acceptance claims rather than merely
informing implementation:

- **V1** (Coraza anomaly-score extraction) — blocks the score half of FR-030
- **V2** (F5 `CF-Ray` logging) — blocks SC-024's exact-join target for the F5 layer
- ~~**V9** (RustFS Object Lock enforcement)~~ — ✅ **PASSED**, single-node; re-run on production topology
- **V10** (DataDome export entitlement) — blocks the DataDome source existing at all
- **V11** (`transformed_request_fields` populates) — blocks the exact-tier DataDome bridge

V9 is done and passed. **V2** (F5 `CF-Ray` logging) is now the highest-risk open item: a failure there
makes SC-024's exact-join target unreachable for the F5 layer and would warrant revising that criterion.
