# Phase 0 Research: Multi-Provider WAF Log Correlation & Request Flow Analysis

**Feature**: `001-waf-log-correlation` | **Date**: 2026-08-18 | **Plan**: [plan.md](./plan.md)

All Technical Context unknowns are resolved below. Each decision records what was chosen, why, what
was rejected, and — where the research surfaced something that must be proven in the environment
rather than read from a document — an explicit verification task carried into Phase 1.

---

## R1: Cloudflare rule evaluation — how to reach wirefilter from Go

**Decision**: Run wirefilter in a **separate Rust sidecar service** exposing a narrow HTTP/gRPC
`Evaluate(scheme, expression, request_fields) -> {matched, caveats, error}` contract. The Go backend
talks to it over the network via a thin client that treats the sidecar as optional and degrades to
"evaluation unavailable" rather than failing the request.

**Rationale**:
- wirefilter is Rust (Cloudflare, MIT, actively maintained — commits through 2026-07-30, tags to
  v0.7.0). It ships a genuine C ABI in its `ffi/` crate with a complete surface (scheme building,
  parse, compile, execution context, match) plus a C test suite.
- **No viable Go binding exists.** The two on GitHub (`hysios/wirefilter-go`, `c93614/wirefilter-go`)
  have 1–2 stars and last commits in 2021/2022, are not meaningfully indexed on pkg.go.dev, and
  would need vendoring and auditing. Cloudflare's own issue #56 requesting FFI usage examples has
  been open and unanswered since 2019.
- The C ABI is still moving (recent upstream commits change `LhsValue`, quantifiers, `WhichCaptures`),
  so a cgo binding is a standing silent-ABI-break risk on a security-critical path.
- cgo would contaminate the whole Go build: `CGO_ENABLED=1`, a Rust toolchain in every CI and Docker
  stage, and loss of trivial cross-compilation — directly at odds with the "buildable via Makefile,
  standalone binary or container" requirement.
- A Rust panic or pointer misuse in-process would take down the log processor. The spec's FR-073d
  requires evaluation to run isolated from collection; a process boundary delivers that by
  construction rather than by discipline.

**Alternatives rejected**:
- *cgo over `wirefilter-ffi`*: highest coupling, breaks portable builds, no crash isolation, and puts
  us in the business of maintaining a dead binding against a live ABI.
- *Pure-Go reimplementation of the CF Rules language*: highest long-term risk. Matching Cloudflare's
  semantics bit-for-bit across regex, CIDR sets, `any()`/`all()` quantifiers and the function library
  is a second implementation that must never drift — and drift means silent false verdicts in a
  security tool. Generic Go expression engines (`expr`, `gval`) are not CF-syntax-compatible and would
  degenerate into this same option.

**Consequence for the spec**: FR-073a's "expression-level, not full CF fidelity" framing is confirmed
correct and now has a concrete cause — **wirefilter defines no fields at all.** The scheme is entirely
embedder-defined; Cloudflare's field catalog (`http.request.uri.path`, `ip.src`, `cf.threat_score`, …)
is a product-layer construct that is *not* in the open-source repo. We must define and maintain our
own scheme from the public field reference, and say so in the UI per FR-073b.

**Verification task (Phase 1)**: Build the sidecar skeleton and confirm `cargo build` of the pinned
wirefilter version, a scheme covering our supported field subset, and a round-trip evaluation.

**Prior art**: A repository matching this pattern (`menta2k/siem`, `backend/internal/wirefilter/client.go`)
implements exactly this sidecar client shape. Given the timing and this project being `siem-v2`, it is
most likely this project's own predecessor — treated here as a design reference to read, **not** as
independent third-party validation.

---

## R2: OWASP evaluation — Coraza embedded in the Go backend

**Decision**: Embed **Coraza v3.7.0** with **coraza-coreruleset v4.25.0** (tracking CRS 4.25.0 LTS)
directly in the Go backend as a library. No sidecar, no separate engine process.

**Rationale**:
- Pure Go, so it compiles into the existing binary with no toolchain contamination — the opposite of
  the wirefilter situation. `go.mod` requires Go 1.25.0, matching the local toolchain (Go 1.25.4).
- The replay use case is directly supported without a live socket. Canonical sequence:
  `NewTransaction` → `ProcessConnection` → `ProcessURI` → `AddRequestHeader`* →
  `ProcessRequestHeaders` → `WriteRequestBody` → `ProcessRequestBody` → `ProcessLogging` → `Close`.
- **`tx.MatchedRules()` is what makes FR-030 satisfiable.** A transaction records only *one*
  interruption (the first disruptive action), which alone cannot answer "report every matching rule".
  `MatchedRules()` returns every rule that fired with ID, message, data, severity, tags and matched
  data, which is exactly the required output.
- CRS ships as an embedded `fs.FS` via `go:embed`, wired in with `WithRootFS(coreruleset.FS)`.
  Paranoia level and anomaly thresholds are set through the standard `tx.paranoia_level` /
  `tx.inbound_anomaly_score_threshold` SecAction convention.

**Configuration decisions**:
- `SecRuleEngine DetectionOnly` — keeps rules running past a would-be block so the matched-rule set
  is complete, then "would this have blocked" is computed from the interruption and anomaly score.
- Generous `SecRequestBodyLimit`, set at or above what the production edge allowed, with explicit
  flagging when a capture is truncated relative to the limit (feeds FR-035).
- `defer tx.Close()` immediately after `NewTransaction()` — Coraza pools transactions and their body
  buffers; skipping `Close()` leaks memory across a long replay batch.
- A `*coraza.WAF` is safe for concurrent use across goroutines; a `Transaction` is not. One
  transaction per goroutine.

**Determinism (FR-033 / SC-015)**: core matching is a pure function of input plus static rules, but
three things must stay off or pinned:
- `@rbl` performs live DNS lookups — must never be enabled.
- `@geoLookup` depends on a GeoIP snapshot that drifts between capture and replay — not enabled
  unless the lookup data is snapshotted with the capture.
- Persistent collections (`initcol`, `SESSION`/`IP` state) reflect *now*, not capture time — replay
  runs single-transaction with no persistence backend.
- CRS and Coraza versions are pinned and stored with every run, which FR-073c already mandates.

**V1 — RESOLVED empirically 2026-08-19** (spike: `backend/internal/owasp/anomalyscore_spike_test.go`).
There is indeed no typed `AnomalyScore()` accessor, but a clean typed path exists and the correct
variable is **not** the obvious one:

- The transaction **does** satisfy `plugintypes.TransactionState`, so the value is reachable as
  `state.Variables().TX().Get(...)` — no audit-log or message parsing required.
- The variable carrying the total is **`TX:blocking_inbound_anomaly_score`**. Measured against a CRS 4.25
  SQLi request: `TX:anomaly_score` reads `0`, `TX:inbound_anomaly_score` is **empty**, and
  `TX:blocking_inbound_anomaly_score` reads `5` — cross-checked against rule 949110's own message,
  *"Inbound Anomaly Score Exceeded (Total Score: 5)"*.
- **Severity summation is not viable**: of 65 matched rules, 64 report severity `unknown`. A
  severity-weighted total would have read near zero — a wrong answer that looks plausible.

Implemented as `crsAnomalyScoreVar` in `backend/internal/owasp/score.go`, with the spike retained as a
regression test so a Coraza or CRS upgrade that moves the variable fails loudly instead of silently
reporting zero.

**Alternatives rejected**: ModSecurity via cgo (same toolchain problems as wirefilter, worse
maintenance story); re-interpreting stored provider verdicts without an engine (rejected at spec time
as FR-073, since it cannot answer what-if questions at all).

---

## R3: DataDome is a pull-mode source **and** a Cloudflare enrichment — both paths

> **Corrected 2026-08-19.** An earlier revision of this section concluded DataDome was *only* an
> enrichment carried inside the Cloudflare record. That was wrong: it missed DataDome's log export API.
> The correction comes from the predecessor implementation at `/home/sko/projects/siem`, which has this
> working in production code (`backend/internal/vendors/datadome/adapter.go`,
> `docs/connecting-vendors.md`).

**Decision**: Collect DataDome **both** ways, through one adapter.

1. **Primary — pull.** Poll DataDome's log export API (`/v1/logs/export`) on a schedule with a
   per-source watermark, yielding full per-request decisions: `requestid`, `timestamp`, `ip`, `host`,
   `uri`, `method`, `action` (`allow`/`block`/`challenge`/`captcha`), `botscore`, `ua`, `country`, `asn`.
2. **Secondary — Cloudflare header enrichment.** Capture the Worker-injected `x-datadome-*` headers into
   the Cloudflare Logpush record.

**Why both, when pull already gives full decisions**: the enrichment is what makes the *correlation
bridge* work — see R11a. The Cloudflare record ends up carrying both `RayID` and `x-datadome-requestid`,
which links DataDome's identifier space to Cloudflare's. Without it, DataDome events know only their own
`requestid` and would fall to heuristic joining.

### The webhook is not a source

DataDome's Integrations webhook is an **attack-notification** mechanism. Its payload is an attack summary
— `THREAT_NAME`, `ENDPOINT_NAME`, `ATTACK_DURATION`, `ATTACK_REQUESTS_COUNT`, `IP_COUNT` — with **no
per-request identifier, IP, URI or action**. There is nothing in it to correlate against another
provider's record.

This is not a configuration gap that can be opened up: the dialog's Threats and Attack Severity fields
select which *attacks* raise a notification, not which requests are logged. No combination of them
produces per-request events. (Captured as FR-001b.)

### The Cloudflare custom-fields trap — three ways to silently get nothing

This is the highest-value operational detail recovered from v1, and the earlier revision of this research
would have led straight into it:

- **`request_fields` captures the header *as the client sent it*.** A header injected by a Cloudflare
  Worker — which is exactly how DataDome enriches a request — is **not** client-sent. It appears **only**
  in `transformed_request_fields`.
- **`transformed_request_fields` cannot be set from the dashboard.** The UI writes `request_fields` only;
  the transformed values are **API-only**, via the `http_log_custom_fields` phase entrypoint.
- **Header names must be lower case.** A capitalised name is accepted and logs nothing.

Each of these fails *silently and identically*: the job is accepted, traffic flows, and the DataDome
fields are simply absent — indistinguishable from DataDome not running.

### One adapter, both field shapes

v1 aliases every field so pull records and header-enriched records share a single code path:
`firstOf(fields, "requestid", "x-datadome-requestid")`, and likewise for `botname`/`botscore`/`action`.
v2 adopts this directly — it is why DataDome needs one parser rather than two.

### Operational constraints

- **Entitlement**: per-request log export is generally a Corporate/Enterprise plan feature. Confirm the
  account's API base URL *and* export entitlement before configuring the source; without export,
  DataDome cannot supply per-request events at all.
- **Export allowed traffic, not just blocks.** A blocks-only export quietly defeats the product's main
  purpose — the disagreement worth seeing is "DataDome allowed this and F5 blocked it", which is
  invisible if DataDome only ever reports blocks. v1 lists this as a leading cause when nothing
  correlates.
- **PII exposure**: `RequestHeaders` capture will carry session cookies and device identifiers into raw
  storage at full traffic rate for the whole retention period. Header selection must be deliberate and
  the captured set classified under FR-015.

**Verification tasks**: confirm the account's export entitlement and API base URL; confirm the
`transformed_request_fields` capture actually populates for Worker-injected headers in this zone.

---

## R3a: DataDome is a Cloudflare Worker SUBREQUEST — verified against real records

> **Established 2026-08-19 from the operator's real captures** (`raw/`, gitignored) and confirmed by
> the operator. This supersedes the delivery-mechanism half of R3 for this deployment.

**How it actually works**: DataDome runs as a Cloudflare Worker that calls its protection API for
every request it guards. Cloudflare logs that call as an ordinary **subrequest**, so the
`http_requests` dataset carries one extra row per protected request — a `POST` to
`api-cloudflare.datadome.co`. Read literally those rows are noise. Read correctly they are DataDome's
verdict, and the only one available: DataDome's own export identifies requests by a private id that
carries no Ray ID at all.

**The join chain, measured on a real request**:

| Record | RayID | ParentRayID | Host |
|---|---|---|---|
| Cloudflare (Worker fetch to origin) | `a2d6ea0f…ccd4` | `a2d6ea0d…c5d9` | `www.jobs.bg` |
| DataDome (Worker subrequest) | `a2d6ea0d…ccd4` | `a2d6ea0d…c5d9` | `api-cloudflare.datadome.co` |
| nginx | — (`cf_ray` = `a2d6ea0f…ccd4-DXB`) | — | — |
| F5 ASM | — (`CF-Ray` = `a2d6ea0f…ccd4`) | — | — |

nginx and F5 see the Worker fetch's **own** ray; the DataDome verdict is keyed on the **parent** ray.
So the Cloudflare record must contribute **both** identifiers — and then the existing union-find bridge
joins all four at exact tier, with no time window and no new machinery (R11a). Verified end to end:
`TestRealFourLayerFlow` reconstructs a complete four-layer flow from the real captures.

**Identification requires both conditions**: host `api-cloudflare.datadome.co` **and** a parent ray.
The hostname alone would also match a genuine visitor browsing that domain.

**`ParentRayID` is the literal string `"00"` for a top-level request**, not empty. Treating it as a
real ray would key every top-level request in the tenant onto one identifier and merge the entire
tenant's traffic into a single flow.

### The verdict mapping — where being wrong is dangerous

Adopted from the predecessor's production-verified analysis. Two inputs are required, and neither
alone suffices:

| Status | `x-datadome-traffic-rule-response` | Normalized action |
|---|---|---|
| 200 | `authorize` / absent | allowed |
| 200 | `interstitial` / `block` / `hard_block` | **logged** (detection without enforcement) |
| 403 | `hard_block` | **blocked** |
| 403 | `interstitial` / `block` | **challenged** |
| 403 | unrecognised | challenged, marked unmapped |
| other (e.g. 499) | any | unknown |

- **`block` is a CHALLENGE, not a block.** It is DataDome's name for the slider CAPTCHA — the one
  value in the vocabulary whose name means the opposite of what it does. `hard_block` is the real
  block. Conflating them overstates enforcement across a large share of traffic.
- **A 403 alone cannot answer**: Device Check, CAPTCHA and hard block all return 403.
- **`hard_block` on a 200 is not a block.** DataDome's header reports the type applied *or the type
  that would have been applied*; a served request means detection without enforcement. Reading it as
  blocked invents a block that never happened — the same error as missing one, pointed the other way.
- **The header lives in `ResponseHeaders`**, not `RequestHeaders`. The Worker sets it on the way out.
  Searching only request headers finds nothing while everything else looks correct.

---

## R4: Cloudflare Logpush ingest contract

**Decision**: Implement a dedicated Logpush receiver endpoint in the Go ingest service rather than
routing Logpush through Vector, because the destination-validation handshake and shared-secret auth
need custom logic.

**Verified contract**:
- **Body**: NDJSON, one JSON record per line. Batch caps are `max_upload_bytes` (5 MB–1 GB) and
  `max_upload_records` (1,000–1,000,000); actual batches may be smaller. No configurable minimum.
- **Destination validation at job creation**: Cloudflare POSTs a gzipped `test.txt.gz` whose content is
  `{"content":"tests"}`. The endpoint must accept it over HTTPS with a trusted cert and return success,
  or job creation fails outright. **The receiver must implement this handshake before any Logpush job
  can be created.**
- **Auth**: no native HMAC/signature scheme. The supported mechanism is `header_*` query parameters on
  the destination config injecting custom headers (e.g. `?header_Authorization=Basic%20...`).
  Cloudflare's own docs state customers must perform their own authentication of pushed logs — so a
  shared secret compared in constant time, over TLS, is the design.
- **Delivery is at-least-once**: retries on failure, and a batch that eventually succeeds is not
  retried — duplicates are expected. The receiver must be idempotent on RayID (FR-007 already requires
  this).
- **Timestamps**: format is configurable via `output_options.timestamp_format` — `unixnano` is the API
  default, `rfc3339` the dashboard default. This must be pinned explicitly in the job config and matched
  in the parser, or timestamps silently misparse.
- **Latency**: standard Logpush publishes no maximum-delay SLA. **Edge Log Delivery** (HTTP-requests
  dataset only) offers a configurable 30s–5min max batch interval — relevant to SC-006/SC-007, whose
  freshness targets are otherwise at the mercy of an unbounded push interval.

**Fields for correlation and verdict**: `RayID`, `EdgeStartTimestamp`, `EdgeEndTimestamp`, `ClientIP`,
`ClientRequestHost`, `ClientRequestURI`, `ClientRequestMethod`, `EdgeResponseStatus`, `BotScore`,
`WorkerStatus`. Security decisions come from either the current
`SecurityAction`/`SecurityRuleID`/`SecurityRuleDescription` singles and the
`SecurityActions`/`SecuritySources`/`SecurityRuleIDs` parallel arrays, **or** the legacy
`WAFAction`/`WAFRuleID`/`FirewallMatches*` family, depending on zone plan and age.

**Verification tasks**: confirm whether live batches arrive gzip-encoded (only the *validation* file's
gzip is documented); confirm the retry count/window against current docs rather than the ~5-retries-over-
5-minutes figure the research synthesized indirectly; confirm which security-field family this zone
populates before building verdict mapping on either.

---

## R5: Correlation must happen at ingest time, not at query time

**Decision**: Correlate in the Go processor and write a **materialized `request_flow` document** to
VictoriaLogs. Do **not** rely on LogsQL's `join` pipe as the primary correlation mechanism.

**Rationale**: LogsQL does have a real `join` pipe with documented LEFT/INNER JOIN semantics
(`<q1> | join by (<fields>) (<q2>) [inner]`), so query-time correlation is not impossible. But the docs
carry an explicit constraint: the joined-in query's results are **buffered in RAM** for the duration of
the join, with a direct warning to keep that result set small. At 8,000 events/sec — roughly 700M
records/day — an unscoped join across a meaningful investigation window is memory-prohibitive. There is
no primitive that streams "all records sharing field X, grouped" efficiently regardless of size;
`stats by` aggregates rather than materialising grouped record sets, and `stream_context` is
intra-stream and position-based, not a cross-source key join.

**Consequences**:
- The correlator owns in-flight flow state, keyed by correlation key, held in Valkey with the
  late-arrival window as TTL (FR-018, FR-024), persisted so a restart resumes rather than resets (FR-023).
- VictoriaLogs stores three record kinds: raw records, normalized events, and completed flows. Flow
  reads become single-document lookups, which is what makes SC-008's 5-second search target realistic.
- The `join` pipe is retained as an *investigation-time* tool for narrow, tightly time-scoped ad-hoc
  questions — not for the primary read path.

---

## R6: VictoriaLogs data model — cardinality

**Decision**: Stream fields are **low-cardinality only**: `provider`, `dataset`, `tenant`, `zone`/`host`.
The correlation key (Ray ID / trace ID), client IP, and user ID are **regular fields, never stream fields.**

**Rationale**: This is stated as a hard rule in the VictoriaLogs docs, near-verbatim: *"Never add
non-constant fields to streams... `ip`, `user_id` and `trace_id` must never be associated with log
streams."* Violating it causes ingestion and query degradation, memory/CPU growth, and disk I/O
amplification — the classic label-cardinality explosion.

This costs us nothing, because VictoriaLogs indexes *all* fields for full-text search regardless of
cardinality — explicitly its differentiator over Loki. High-cardinality lookups use exact field match
(`trace_id:="..."`), which the docs identify as the fast path.

---

## R7: VictoriaLogs retention — a genuine gap against FR-039/FR-040

**Decision**: Implement tiering and legal hold **outside** VictoriaLogs. VictoriaLogs serves the hot and
warm window only.

**What VictoriaLogs actually provides**:
- Time retention (`-retentionPeriod`, default 7d, range 1d–100y) and disk-based retention
  (`-retention.maxDiskSpaceUsageBytes` or `-retention.maxDiskUsagePercent`, mutually exclusive).
- Deletion granularity is the **whole per-day partition**, not the record.
- **No tiered storage, no S3 offload for queryable data, no downsampling.** It is local-disk-only for
  query serving. Backup is a per-partition snapshot API plus `rsync`/`rclone`; restore means copying a
  partition back to local disk and attaching it — a cold path, not a queryable tier.
- Record-level deletion exists (`-delete.enable`, `POST /delete/run_task?filter=<LogsQL>`, accepting an
  arbitrary filter so GDPR-style targeted erasure is expressible) but **rewrites all stored logs**, so it
  is a scheduled batch operation, never a per-record hot-path TTL.
- **No immutability, no legal hold, no delete-lock of any kind.**

**Resulting design**:
- **Hot/warm** = VictoriaLogs with `-retentionPeriod` sized to the warm window.
- **Cold** = per-day partition snapshots pushed to S3-compatible object storage with **Object Lock**,
  which is also what supplies the immutability the constitution's audit and legal-hold requirements
  need. Deployment target is **RustFS** — see R13, including its maturity caveat.
- **Retention classes** = separate VictoriaLogs tenants (or instances) per retention class, since
  retention is a per-instance flag and expiry is per-day-partition. Per-category retention (FR-039)
  cannot be expressed within one instance.
- **Legal hold (FR-040)** = a hold registry in PostgreSQL, plus copying held partitions to Object-Locked
  storage, plus refusing expiry while a hold is open. VictoriaLogs cannot enforce this itself; the
  enforcement lives in our retention service.
- **Audit trail** = PostgreSQL append-only with a periodic immutable export, **not** VictoriaLogs, because
  FR-055 requires operators be unable to alter it and `-delete.enable` offers no per-record protection.

This is the largest gap between the chosen stack and the spec, and is recorded in the plan's Complexity
Tracking rather than glossed over.

---

## R8: VictoriaLogs multi-tenancy — advisory, so enforcement is ours

**Decision**: `vmauth` (or the Go backend acting as the sole gateway) is **mandatory infrastructure**, and
clients never reach VictoriaLogs directly.

**Rationale**: Tenancy is an `(AccountID, ProjectID)` uint32 pair supplied via HTTP headers, and
VictoriaLogs performs **no authentication or authorization on them at all** — a client that can reach the
port can claim any tenant. The official recommendation is to front it with `vmauth` mapping authenticated
users to fixed tenant headers.

**Consequence for FR-074b** ("cross-tenant access impossible to express, not merely refused"): the backend
must **never** accept or proxy raw LogsQL from clients. The API exposes structured query parameters that
the backend compiles into LogsQL with the tenant headers injected server-side. This also closes the
LogsQL-injection hole that a passthrough query API would open.

---

## R9: Ingestion throughput and the durable buffer

**Decision**: **NATS JetStream** as the durable, replayable buffer between ingest and processing.

**Rationale**: Constitution Principle I (NON-NEGOTIABLE) requires a durable replayable buffer *before*
parsing, and FR-063 requires operator-driven replay after a parser or correlation fix. JetStream is a
single small Go-native binary with durable streams, replay from sequence, consumer groups, and
at-least-once delivery — it satisfies the requirement without the operational weight of Kafka.

**Alternatives rejected**:
- *Redpanda/Kafka*: fully capable and the right answer at much larger scale, but a substantial
  operational step up for a stack deliberately kept lean. Recorded as the documented scale-out upgrade
  path if throughput or multi-consumer needs grow.
- *Hand-rolled disk WAL*: exactly the kind of subtle, correctness-critical component that should not be
  written from scratch when durability is non-negotiable.
- *Vector disk buffers alone*: good for the Vector-fed sources, but gives no independent multi-consumer
  replay for the Logpush path, which Vector does not receive.

**Throughput confidence**: the target is ~8,000 events/sec combined. VictoriaMetrics' own 2026 collector
benchmark sustained 10,000 logs/sec with collectors capped at **1 CPU core**, and an independent
comparison had VictoriaLogs absorbing 66 MB/s on 4 vCPU / 8 GiB (3× Loki on identical hardware). The
target is comfortably inside demonstrated capability; no official per-second SLA is published, and
VictoriaMetrics' stated position is to benchmark with 1–10% of real production data — which becomes a
load-test task, not an assumption.

---

## R10: Vector → VictoriaLogs sink, and the Vector-fed sources

**Decision**: Vector `elasticsearch` sink against `http://<vl>:9428/insert/elasticsearch/` with
`api_version: v8` and gzip, per VictoriaLogs' own documented recommendation. Disk buffers plus
end-to-end acknowledgements enabled on every source.

**Rationale**: **There is no official native VictoriaLogs sink in Vector.** The documented options are the
Elasticsearch-compatible bulk endpoint (recommended by the VictoriaLogs maintainers) or the `http` sink
against `/insert/jsonline`. A Loki sink reportedly works but with field-formatting caveats and is
explicitly not the maintainers' recommendation.

Vector's disk buffers act as a write-ahead log surviving restarts, and end-to-end acknowledgements let a
source withhold its ack (file cursor, syslog client) until the sink confirms delivery — together these
are what let the Vector-fed legs meet FR-005's no-loss requirement.

- **nginx**: `file` source with checkpointing. **The log_format must be JSON, not combined text** —
  confirmed against real records. The combined format cannot carry `cf_ray` without positional parsing
  that breaks the moment a field is added.
- **`cf_ray` arrives with a datacentre suffix** (`a2d6ea0f6813ccd4-DXB`) while Cloudflare logs the bare
  id. The suffix must be stripped or every origin record silently fails to join.
- **F5 ASM**: `syslog` source. ASM remote logging offers syslog, Key-Value Pairs (for Splunk-style
  reporting servers via HSL), CSV, and CEF (ArcSight) formats.

---

## R11: Correlation key — confirming the spec's tiered strategy

**Decision**: The tiered strategy resolved at spec time (FR-072/a–e) is confirmed viable, with one weak
link.

**Verified**: Cloudflare forwards the Ray ID to origin as the **`CF-Ray`** request header. nginx can log
it directly as **`$http_cf_ray`** in a custom `log_format` — so the Cloudflare↔nginx exact join is
straightforward, and DataDome rides inside the Cloudflare record (R3) so it inherits the same key.

**Weak link — F5 BIG-IP ASM**: the official Request Logging profile documentation shows only predefined
tokens (`HTTP_METHOD`, `HTTP_URI`, `CLIENT_IP`, …), and **no explicit documented syntax for logging an
arbitrary header such as `CF-Ray` was confirmed.** The well-known field practice is an iRule
(`HTTP::header value "CF-Ray"`) writing the value into the log line or an ASM custom field. This is a
common pattern but was **not** confirmed against official syntax in this research.

**Consequence**: F5 is the provider most likely to fall back to the heuristic join (FR-072b), which is
precisely why the tiered design was the right call over assuming universal exact joins. If the iRule
approach proves out in a lab, exact-join coverage should approach the SC-024 target of 95%.

**Verification task (blocking for SC-024)**: lab-test arbitrary-header logging on the actual BIG-IP
version before committing to the exact-join path for F5.

---

## R11a: Multi-identifier bridging — how DataDome joins exactly

**Decision**: Correlation treats each record as carrying a **set** of per-request identifiers, and unions
records transitively across shared identifiers (union-find), rather than keying each record on one
chosen identifier.

**Why this is necessary**: the four sources do not share a single identifier space.

| Record | Identifiers it carries |
|---|---|
| Cloudflare | `RayID` **and** `x-datadome-requestid` (via custom-field capture, R3) |
| DataDome (pull) | `requestid` only |
| nginx | `CF-Ray` (as `$http_cf_ray`) |
| F5 ASM | `CF-Ray` (if the iRule works — V2) |

A DataDome pull event and an nginx line share **no** identifier directly. But the Cloudflare record
carries both, so unioning over identifier sets links all three into one component. DataDome joins nginx
**transitively, at exact tier** — no timestamp proximity, no clock agreement, no false-join risk.

**Deterministic identity**: the component's canonical id is its smallest member identifier, so the same
set of records always yields the same flow identity however they were discovered or ordered — which is
what FR-022 and FR-072g require.

**Consequence**: had correlation keyed each record on a single identifier, tier-2 heuristics would have
carried all DataDome joins, and SC-024's 95% exact-join target would be unreachable no matter how well
Ray ID propagation worked. Captured as FR-072f/FR-072g.

**Prior art**: implemented in the predecessor at `backend/internal/correlate/group/group.go` and
`backend/internal/correlate/keys/keys.go`, whose own header comment warns that reading "join on a shared
id" literally — as a per-event decision — makes the heuristic tier dead code. Worth reading before
implementing this.

---

## R12: Components added beyond the stated stack

Two additions are proposed that the user's brief did not name. Both are called out explicitly rather
than absorbed silently.

**PostgreSQL** — required for state that is transactional, mutable and relational, which a log store
cannot serve: users/roles/tenants, detection definitions, evaluation run records, retention policies,
legal hold registry, source configuration, and the append-only audit trail. FR-055 in particular
requires an audit trail operators cannot alter, and VictoriaLogs' `-delete.enable` provides no per-record
protection. *Alternative rejected*: storing this in VictoriaLogs — wrong tool for mutable relational
state, and it cannot satisfy the immutability requirement.

**NATS JetStream** — the durable buffer, justified under R9 by the non-negotiable Constitution I.

**Valkey** (already offered in the brief) is used for in-flight correlation state, query result caching,
and rate limiting, with persistence enabled so FR-023's restart-resume holds.

---

## R13: Object storage — RustFS behind an S3-compatible abstraction

**Decision**: **RustFS** is the deployment target for cold archive, immutable audit export and
legal-hold preservation. The backend codes strictly against the **S3 API**, never against RustFS
specifics, so any S3-compatible store (AWS S3, MinIO, Ceph RGW, Garage) is a configuration swap.

**Rationale**: RustFS is an Apache-2.0, Rust, S3-compatible distributed object store positioned as a
MinIO alternative, with a permissive licence free of the copyleft terms that made MinIO's licensing
awkward for embedded/commercial use. It fits the project's existing Rust presence (the wirefilter
sidecar) and its performance claims are credible for the cold-archive access pattern, which is
write-once, read-rarely and entirely latency-tolerant.

**⚠️ Maturity caveat — the load-bearing risk**: as of August 2026 RustFS has **not** reached a stable
1.0. It is in a `1.0.0-rc`/beta series, and the maintainers' own guidance is explicitly **not to use it
in production until 1.0 stable**. The upstream feature matrix additionally marks **Distributed Mode**
and **RustFS KMS** as "Under Testing".

**✅ Object Lock support — VERIFIED 2026-08-19 (V9 PASS)**. The documentation claim could not be
confirmed at source (the docs page 404s, and the README omits Object Lock entirely), so it was tested
directly against `rustfs/rustfs:latest` in single-node mode. Conformance test:
`backend/test/integration/objectlock_conformance_test.go`. Results:

| Step | Result |
|---|---|
| Bucket created with `ObjectLockEnabledForBucket` | ✅ |
| `PutObjectLockConfiguration` (COMPLIANCE, default retention) | ✅ |
| Versioning (per-version ids returned) | ✅ |
| `PutObjectRetention` COMPLIANCE pinned to a version | ✅ |
| **Delete of the retained version** | ✅ **REFUSED** — `AccessDenied: Object is under COMPLIANCE retention and cannot be deleted until ...` |
| `PutObjectLegalHold` | ✅ |
| Retained version survives an overwrite, byte-identical | ✅ |
| **Delete under legal hold alone, with `BypassGovernanceRetention: true`** | ✅ **REFUSED** — `AccessDenied: Object has a legal hold and cannot be deleted.` |

Two details make this a strong result rather than a superficial one. The delete was attempted with the
**root credentials** — COMPLIANCE mode held against the most privileged caller, which is exactly the
operator FR-055 protects the audit trail against. And legal hold was tested **in isolation**, after
letting a short governance retention lapse and explicitly requesting a governance bypass, so FR-040's
mechanism was proven on its own rather than inferred from the retention result.

**Why this was tested rather than assumed**: Object Lock is what makes FR-040 (legal hold) and FR-055
(an audit trail operators cannot alter) actually true. A store can accept every Object Lock API call and
still permit the delete — a failure invisible from the API surface, leaving the system looking compliant
while the guarantee silently did not exist. The test's pass condition is therefore *the delete was
refused*, never *the calls succeeded*.

**Residual risk after V9 — reduced, not eliminated**:
- Verified in **single-node** mode. Upstream marks **Distributed Mode** as "Under Testing", and the
  enforcement path in a clustered deployment was not exercised. **Re-run V9 against the actual
  production topology before relying on it there.**
- RustFS remains **pre-1.0** with maintainers advising against production use until 1.0 stable. V9
  addresses the *correctness* of Object Lock, not the project's overall maturity.
- Not tested: that retention correctly *releases* the object after `RetainUntilDate` passes. Relevant to
  FR-039 expiry, not to FR-040/FR-055, and cheap to add when the retention service is built.

**Mitigations built into the design**:
1. **S3 API only** — no RustFS-specific calls anywhere. Swapping stores is a config change, not a
   rewrite. This is what keeps the risk cheap to reverse. *(Retained: still correct, and the reason
   re-testing on a different topology or store is cheap.)*
2. ~~**V9 is a blocking verification**~~ — **done, PASS.** Retained in CI so an upstream regression or a
   store swap is caught rather than assumed.
3. **Conformance test in CI** — the same Object Lock suite runs against whichever store is configured,
   so a swap or an upstream regression is caught rather than assumed.
4. **Documented fallback**: if V9 fails, the options in order of preference are MinIO (mature Object
   Lock, licence constraints), Ceph RGW (mature, heavier), or cloud S3 for the audit/hold bucket only
   while RustFS retains the bulk cold archive — since the immutability requirement applies to a small
   fraction of the data by volume.

**Alternatives considered**: MinIO — mature and proven Object Lock, but AGPL-v3 licensing is the reason
projects increasingly avoid it. Ceph RGW — mature but disproportionate operational weight here. Cloud
S3 — no maturity risk, but the brief implies self-hosting.

**Outcome**: RustFS proceeds as directed, with the compliance gate **passed** for single-node. Keep the
audit/legal-hold bucket separable regardless — it is a small fraction of volume, and separability is what
makes the remaining pre-1.0 and distributed-mode risk cheap to act on.

---

## Consolidated verification tasks carried into Phase 1

These are the points where research reached the limit of what documentation can settle. None block the
design; all block specific acceptance claims.

| # | Item | Blocks | Where it lands |
|---|------|--------|----------------|
| ~~V1~~ | ~~Coraza anomaly-score extraction~~ **RESOLVED**: `TX:blocking_inbound_anomaly_score` via `plugintypes.TransactionState` | FR-030 score reporting | ✅ Done — see R2 |
| ~~V2~~ | ~~F5 `CF-Ray` logging~~ **RESOLVED**: the operator's real F5 records carry `CF-Ray`, so the WAF layer joins at exact tier | SC-024 | ✅ Confirmed from real data |
| V3 | Live Logpush batch gzip encoding (only the validation file's gzip is documented) | Ingest receiver | Empirical, first job |
| V4 | Logpush retry count/window | Dedup window sizing | Docs re-check |
| ~~V5~~ | ~~CF security-field family~~ **RESOLVED**: real records populate the modern `Security*` family, plus `WAFAttackScore`/`WAFSQLiAttackScore`/`WAFXSSAttackScore`/`MatchedRules` | Verdict mapping | ✅ Confirmed from real data |
| V6 | DataDome `DATADOME_LOGPUSH_CONFIGURATION` syntax + plan entitlement for advanced headers | DataDome verdict depth | Docs + account check |
| V7 | Sustained-load behaviour at 4×2,000 eps against real data shape | SC-004, SC-005 | Load test |
| V8 | wirefilter scheme coverage vs the CF field reference | FR-031 | Sidecar spike |
| V10 | DataDome export entitlement + account API base URL | FR-001a, DataDome source viability | Account check |
| ~~V11~~ | ~~`transformed_request_fields` population~~ **SUPERSEDED by R3a**: the verdict arrives on the DataDome subrequest's `ResponseHeaders`, not via request-header capture on the main record | R3a | ✅ Resolved |
| ~~V9~~ | ~~RustFS Object Lock enforcement~~ **PASS** — delete refused under both COMPLIANCE retention and isolated legal hold, single-node | FR-040, FR-055 | ✅ Done — see R13. Re-run on the production topology |
