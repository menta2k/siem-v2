# 003 — Traffic Profiler

An independent service that watches completed request flows and learns, per URL, what
that URL normally looks like: which parameters it accepts, what type each parameter
carries, and the structural ceilings of the requests that reach it (request length,
header count, cookie count).

The output is a **behavioural baseline**, not a detection. It answers "what is normal
for `POST /api/orders/{id}`" so an analyst, a WAF rule author, or a later detection can
ask "and is this request normal?".

---

## 1. Scope

**In scope (v1)**

- Per-`(tenant, host, method, path template)` endpoint profile.
- Query-string parameters: name, inferred type, presence rate, length bounds,
  cardinality, enum candidates.
- Path parameters, discovered by templating `/orders/8813` → `/orders/{int}`.
- Structural ceilings per endpoint: max/p95 request length, header count, cookie count,
  parameter count, individual value length.
- Per-tenant GUI configuration of **which hosts are profiled**, mirroring the existing
  ingest-filters pattern.
- A profile browser + visualisation page in the Nuxt frontend.

**Out of scope (v1), stated so the boundary is deliberate**

- Request **body** parameters. No parser populates `schema.Request.BodyRef` today —
  bodies are never captured, so body params cannot be profiled without a separate
  ingest-side change with its own data-governance decision. See §3.
- Drift alerting ("a new parameter appeared", "a value exceeded the learned maximum").
  The profile is the prerequisite; the detection is a natural follow-on and belongs in
  `internal/alerting` under Constitution III, with its own fixtures.
- Response-side profiling.

---

## 2. Why a separate service

`profilerd`, a fourth binary alongside `logproc`, `apiserver`, `retentiond`.

Profiling is an unbounded-cost aggregation over every request the platform sees. Sharing
`logproc`'s process would put a CPU-heavy, memory-resident aggregation on the same
goroutine budget as the latency-sensitive ingest path, which Constitution I forbids in
substance: a profiler backlog must degrade profiles, never collection. A separate
process also means the profiler can be stopped, resized, or redeployed during an
incident without touching ingest — the same argument that already separates `retentiond`.

---

## 3. Where the data comes from — and what is missing

### 3.1 Transport: publish closed flows to JetStream

`flow.Pipeline` already exposes an `OnFlow func(*Flow)` hook (`internal/biz/flow/pipeline.go:51`)
that is **declared but never wired**. This is the extension point.

- New stream `SIEM_FLOWS`, subject `siem.flows`, created by the same
  `jetstream.Connect` helper the raw buffer uses.
- `logproc` wires `pipeline.OnFlow` to a **non-blocking** publisher: a bounded channel
  (default 8192) drained by a small pool of publisher goroutines. When the channel is
  full the flow is **dropped and counted** — Constitution I requires an explicit drop
  policy, and profiling must never apply backpressure to flow storage. The drop counter
  is exported and alertable.
- `MaxAge` on `SIEM_FLOWS` is short (default 24h) and `MaxBytes` bounded: this is a
  hand-off buffer, not a store of record. VictoriaLogs remains the flow's home.
- `profilerd` consumes with its own durable consumer (`profiler`), acking only after the
  profile delta is committed. A profiler outage accumulates and replays; it does not
  lose flows within `MaxAge`.

**Rejected alternative:** polling VictoriaLogs on a watermark. It needs zero `logproc`
changes, but it re-reads the hot store at profiling cadence, needs its own watermark
durability, and gives no natural backpressure boundary. The JetStream path costs one
small, already-anticipated wiring change and is strictly better.

### 3.2 Capture gap — the part that needs a decision

Three of the four things asked for are **not derivable from what is stored today**.
Verified against the parsers, not assumed:

| Wanted | Available today | Why |
|---|---|---|
| Parameters + types | ✅ Yes | `Request.Query` is populated by all four parsers (`cloudflare/parser.go:134`, `nginx:103`, `datadome:97`, `f5asm:99`). |
| Max header count | ⚠️ Cloudflare only | Only the Cloudflare parser sets `Request.Headers` (`cloudflare/parser.go:153`), and only when the Logpush job selects `RequestHeaders`. nginx, F5 ASM and DataDome never populate it. |
| Max cookie count | ❌ No | `cookie` is classified `Secret` and the whole value is replaced with `[redacted]` **before storage** (`normalize/masking.go:35,101`). Cookie names and count are destroyed by design and cannot be recovered downstream. |
| Max request length | ❌ No | No parser records a request byte count. `Response.Bytes` is the response. Cloudflare's `ClientRequestBytes` exists in Logpush but is not in the parser struct. |

The masking is correct and must not be relaxed. The fix is to compute the **structural
facts** at normalisation time — before the masker runs — and stamp them on the event as
non-sensitive integers. Counting cookies is not the same as storing them.

Additive schema change (Constitution II permits additive; bump `schema.Version` to `1.1`):

```go
// Shape carries structural facts about a request that are derived BEFORE masking
// and are safe to keep afterwards. Counting a cookie is not storing a cookie:
// these are integers and names, never values.
type Shape struct {
    RequestBytes    int64    `json:"request_bytes,omitempty"`
    HeaderCount     int      `json:"header_count,omitempty"`
    HeaderBytes     int      `json:"header_bytes,omitempty"`
    CookieCount     int      `json:"cookie_count,omitempty"`
    CookieNames     []string `json:"cookie_names,omitempty"` // names only; see below
    QueryParamCount int      `json:"query_param_count,omitempty"`
    Complete        bool     `json:"shape_complete"`         // false when the provider
                                                             // did not ship headers
}
```

`CookieNames` is a judgement call worth naming: a cookie *name* is normally structural
(`session`, `_ga`, `cf_clearance`) but can itself be an identifier. Recommendation:
capture names, hold them behind `view_sensitive` in the API, and allow a per-tenant
"count only" mode in the profiler config. `Complete: false` is what stops the UI from
reporting "max 0 headers" for an nginx-only endpoint as though it were a finding — an
absent measurement and a measured zero are different claims (FR-070's principle).

Work required, per provider:
- **Cloudflare** — add `ClientRequestBytes`; derive header/cookie counts from
  `RequestHeaders` where the Logpush job ships it.
- **nginx** — the Vector source can emit `$request_length`, `$http_cookie` and a header
  map; needs a `deploy/vector/` config change plus parser fields.
- **F5 ASM / DataDome** — likely `Complete: false` for headers; F5 ASM may expose a
  request length field, to be confirmed against a fixture.

> **This is the one genuinely blocking question in the plan.** If extending capture is
> not acceptable, v1 ships parameter profiling only and the "max headers / cookies /
> request length" panels are honestly marked "not captured" rather than showing zeros.
>
> **As built (phase 3 delivered):** `schema.Shape` uses per-field nil pointers instead of
> the sketched `Complete` flag — nil already says "not measured" per fact, which is
> stronger than one boolean for the whole struct. Two refusals were added on top of the
> sketch: Cloudflare does NOT claim header counts (Logpush `RequestHeaders` is a
> configured subset, and counting a subset as "the headers" understates a ceiling while
> claiming to measure it), and F5 ASM does NOT claim request bytes (captures truncate
> bodies; a lying floor is worse than an absent number). nginx cookie capture is opt-in
> via `$http_cookie` because the raw log line would carry the values.

---

## 4. The profiling algorithm

### 4.1 Path templating (this is what makes the feature viable)

Without templating, `/orders/8813` and `/orders/8814` are two profiles and the table
grows with traffic. Templating is not a nicety; it is the cost control (Constitution VII).

Per `(tenant, host, method, segment-count)`, maintain per-position value statistics.
A position becomes a variable when, over at least `MinSamples` (default 64) observations:

- distinct values exceed `MaxDistinctPerSegment` (default 32), **or**
- ≥90% of observed values share a single non-freetext inferred type (`{uuid}`, `{int}`,
  `{hex}`, `{date}`).

Otherwise the position stays literal. Output: `/api/v2/users/{uuid}/orders/{int}`.

Templating is **monotonic**: a position that becomes a variable never reverts, and when
it does, the profiles under the previously-literal siblings are merged into the template.
This keeps the result deterministic under replay (Constitution VI): the same flows in
any order converge to the same template set.

### 4.2 Parameter type inference

A join-semilattice; the recorded type is the least upper bound of everything observed:

```
empty
  ├─ bool ─┐
  ├─ int ──┴─ float ─┐
  ├─ uuid ───────────┤
  ├─ ipv4 / ipv6 ────┤
  ├─ email ──────────┼─ alnum ─ freetext (top)
  ├─ iso8601 ────────┤
  ├─ hex / base64 ───┤
  └─ json ───────────┘
```

Recording the LUB rather than a histogram means "this parameter is an int" degrades
honestly to "this parameter is freetext" the first time something else shows up, and the
transition itself is the interesting signal for a later drift detection. Per parameter we
also keep: `observations`, `present_count` (→ presence rate, so "required vs optional"
is measured not guessed), `min_len`, `max_len`, `distinct_estimate`, and up to
`MaxEnumValues` (default 64) observed values **only while cardinality stays below that
cap** — an enum candidate. Above the cap, values are discarded and only the type and
bounds remain.

Parameter *values* are never stored beyond the enum candidate set, and the enum set is
run through the existing `normalize` value patterns so a token that slipped into a
query string is not resurrected in a profile.

### 4.3 Aggregation and idempotency

Delivery is at-least-once and flows can be **amended** after close (FR-018 merge-on-close),
so the same `flow_id` can arrive twice. Every profile field is either a monotonic merge
(`max`, type LUB, name union) — inherently idempotent — or a counter, which is not.

Counters are deduplicated against a set of recently-seen `flow_id`s with a TTL
covering the merge horizon. **As built:** the set is in-memory in `profilerd` rather
than Valkey — the consumer is a single process that acks only after flush, so the only
window an external store would add is replay-across-restart, which merely inflates
counters slightly. Not worth a dependency; revisit if profilerd is ever scaled out.

`profilerd` accumulates in memory and flushes to Postgres on a ticker (default 30s) or
at a dirty-endpoint threshold, upserting deltas. Ack happens after the flush that
covers the message, so a crash replays at most one flush window.

---

## 5. Storage — Postgres

Profiles are mutable, relational, low-volume aggregates. That is exactly the split
`001_core.sql` already documents: VictoriaLogs holds the append-only stream, Postgres
holds mutable state.

`backend/internal/data/postgres/migrations/009_traffic_profiles.sql`:

```sql
CREATE TABLE IF NOT EXISTS profile_endpoint (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL REFERENCES tenant(id),
    host              TEXT NOT NULL,
    method            TEXT NOT NULL,
    path_template     TEXT NOT NULL,
    observations      BIGINT NOT NULL DEFAULT 0,
    first_seen        TIMESTAMPTZ NOT NULL,
    last_seen         TIMESTAMPTZ NOT NULL,
    -- Structural ceilings. NULL means NOT MEASURED, which is not the same as 0.
    max_request_bytes BIGINT,
    max_header_count  INTEGER,
    max_header_bytes  INTEGER,
    max_cookie_count  INTEGER,
    max_param_count   INTEGER,
    max_value_len     INTEGER,
    max_path_len      INTEGER,
    -- Percentiles kept as a compact sketch so p95 survives restart without raw samples.
    request_bytes_sketch JSONB,
    cookie_names      TEXT[] NOT NULL DEFAULT '{}',
    status_mix        JSONB NOT NULL DEFAULT '{}',
    -- True when a cap was hit and the profile is therefore incomplete.
    truncated         BOOLEAN NOT NULL DEFAULT FALSE,
    -- Providers that contributed, so the UI can explain a missing measurement.
    providers         TEXT[] NOT NULL DEFAULT '{}',
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, host, method, path_template)
);

CREATE INDEX IF NOT EXISTS profile_endpoint_tenant_host_idx
    ON profile_endpoint (tenant_id, host, observations DESC);

-- As built: parameters live in a `params JSONB` column on profile_endpoint
-- instead of this child table — the profiler always reads/writes whole
-- endpoints (memory is authoritative, flush replaces the row), and no reader
-- needs a parameter outside its endpoint. The logical schema below is what
-- the JSONB carries.
CREATE TABLE IF NOT EXISTS profile_parameter (
    endpoint_id       TEXT NOT NULL REFERENCES profile_endpoint(id) ON DELETE CASCADE,
    location          TEXT NOT NULL CHECK (location IN ('query','path')),
    name              TEXT NOT NULL,
    inferred_type     TEXT NOT NULL,
    observations      BIGINT NOT NULL DEFAULT 0,
    present_count     BIGINT NOT NULL DEFAULT 0,
    min_len           INTEGER,
    max_len           INTEGER,
    distinct_estimate BIGINT NOT NULL DEFAULT 0,
    enum_values       TEXT[] NOT NULL DEFAULT '{}',
    enum_overflowed   BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen        TIMESTAMPTZ NOT NULL,
    last_seen         TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (endpoint_id, location, name)
);

-- Per-tenant profiler configuration, on the tenant row like ingest_filters:
-- deciding what is profiled is a tenant-level policy, not a feed setting.
ALTER TABLE tenant ADD COLUMN IF NOT EXISTS profiler_config JSONB NOT NULL
    DEFAULT '{"enabled":false,"hosts":[],"cookie_names":false}';
```

### Cost and cardinality controls (Constitution VII)

Hard caps, each with a counter and a `truncated` flag rather than silent loss:

| Cap | Default |
|---|---|
| endpoints per tenant | 20 000 |
| endpoints per host | 5 000 |
| parameters per endpoint | 200 |
| enum values per parameter | 64 |
| distinct values per path segment before templating | 32 |

Reaching a cap stops *growth*, not *updating*: existing profiles keep learning. Hitting
a tenant or host cap is a logged, alertable event — it usually means templating failed
on a URL shape nobody anticipated, and that is worth seeing.

---

## 6. Configuration API and GUI

Mirrors `FilterService` (`internal/service/filtersvc.go`) exactly, because that is the
established pattern for tenant-scoped, GUI-edited, audited policy in this codebase.

**New service** `internal/service/profilesvc.go`, mounted on `apiserver`:

| Route | Permission | Purpose |
|---|---|---|
| `GET /api/v1/profiler/config` | `manage_sources` | current config + limits |
| `POST /api/v1/profiler/config` | `manage_sources` | replace config; audited as `profiler_config.replaced` |
| `GET /api/v1/profiles` | `view_flows` | endpoint list, filter by host/method/search, sorted |
| `GET /api/v1/profiles/{endpointID}` | `view_flows` | one endpoint + its parameters |
| `GET /api/v1/profiles/hosts` | `view_flows` | observed hosts + counts, for the config picker |
| `DELETE /api/v1/profiles/{endpointID}` | `manage_sources` | forget a profile; audited |

Reusing `manage_sources` and `view_flows` rather than inventing a permission keeps the
role matrix in `003_auth.sql` untouched. Cookie names, when captured, are additionally
gated on `view_sensitive` in the response serialiser.

**Config shape**

```json
{
  "enabled": true,
  "hosts": ["api.example.com", "*.shop.example.com"],
  "exclude_paths": ["/health", "/metrics"],
  "cookie_names": false,
  "min_observations_to_publish": 20
}
```

Host matching supports an exact name and a single leading `*.` wildcard. `hosts: []`
with `enabled: true` means **profile nothing** — an explicit allow-list, never an
implicit "everything", so enabling the feature cannot accidentally profile the entire
estate. `min_observations_to_publish` keeps one-off URLs (scanner noise) out of the UI
until they prove recurrent; they are still counted.

`profilerd` holds a refreshed in-memory snapshot of every tenant's config on the same
`filterCache` pattern in `cmd/logproc/main.go` — a Postgres blip keeps the last snapshot
rather than stalling the consumer. Unlike the ingest filter, this cache **fails closed**:
if a tenant's config has never loaded, that tenant is not profiled. Profiling is
additive, so not-profiling is the safe default; dropping data was the reason the ingest
filter had to fail open.

---

## 7. Frontend

New page `frontend/app/pages/profiles.vue`, nav entry in `layouts/default.vue`:

```
{ title: 'Traffic profiles', icon: 'mdi-sitemap-outline', to: '/profiles', visible: true }
```

The project ships no charting library (Vuetify + `@mdi/font` only) and `dashboards.vue`
is card/table based. Adding a chart dependency for one page is not worth the bundle;
the visuals below are small inline SVG components, styled from the Vuetify theme, in
`app/components/profile/`.

**Layout**

1. **Host summary strip** — one card per configured host: endpoints learned, requests
   observed, parameters learned, coverage warning when providers for that host never
   ship headers.
2. **Endpoint table** (`v-data-table-server`) — method chip, path template with `{param}`
   segments visually distinct, observation count, parameter count, a compact
   `RequestSizeBar` (p50/p95/max as a stacked horizontal bar), last seen. Sortable,
   host-filterable, searchable. Rows with `truncated` carry a warning chip — an
   incomplete profile must never read as a complete one.
3. **Endpoint drawer** (reusing the `FlowDetailDrawer` pattern) —
   - **Parameters table**: name, location chip (query/path), type chip colour-coded by
     the lattice level, a presence bar (`present/observations` as a percentage — this is
     the "required vs optional" read), length range, cardinality, and enum values as
     chips when the parameter is an enum candidate.
   - **Shape panel**: max request length, header count, cookie count, parameter count,
     longest value — each rendering "not captured" with a tooltip explaining which
     provider is missing, when `Complete` is false.
   - **Type composition bar**: one stacked bar showing how the endpoint's parameters
     distribute across types — the fastest way to spot an endpoint that is all-freetext.
4. **Configuration panel**, gated to admin/engineer, matching `filters.vue`: host
   allow-list with add/remove chips fed by `GET /api/v1/profiles/hosts` so an operator
   picks from hosts actually seen rather than typing them, path exclusions, the
   cookie-names toggle with its privacy note, and the publish threshold. Save is a
   single replace-the-config POST, consistent with the ingest-filter editor.

Everything is server-filtered and server-paginated; the frontend never receives another
tenant's profiles (Constitution V — tenancy enforced at the query layer).

---

## 8. Deployment

- `backend/cmd/profilerd/` + `backend/configs/profilerd.yaml` (`http_addr: ":8300"` for
  `/health` and metrics; needs `postgres`, `jetstream`, `valkey`).
- `conf.Config` gains a `Profiler` section: flush interval, caps, channel size, consumer
  name.
- `Makefile`: add `profilerd` to `SERVICES` — build, package and Docker targets are
  already parameterised over that list.
- `deploy/compose/docker-compose.yml`: new `profilerd` service under the `app` profile,
  `restart: unless-stopped`, depending on `postgres` (healthy), `nats`, `valkey`.
- `deploy/systemd/` + `nfpm.yaml`: one more unit and one more binary, following
  `retentiond`.

**Self-monitoring** (Constitution IV) — exported and alertable: flows consumed, flows
dropped at the publish channel, consumer lag, endpoints learned, profiles flushed, flush
failures, cap-hit counters, and **zero-output-while-input-continues**, which is the
failure this platform treats as loudly as an attack.

---

## 9. Testing

- **Unit, table-driven**: type lattice (every pair's LUB), path templating convergence,
  parameter merge idempotency.
- **Property**: replaying the same flow set in shuffled order yields byte-identical
  profiles (Constitution VI). This is the test that keeps templating honest.
- **Fixtures**: reuse `backend/test/fixtures/{cloudflare,nginx,f5asm,datadome}` — the
  parser shape changes in §3.2 need fixture updates anyway, so profiler assertions ride
  along on real sanitised records.
- **Masking regression**: a fixture whose query string carries a JWT must not surface
  that value in an enum candidate set. This is the test that stops the profiler becoming
  a secret-exfiltration path.
- **Integration** (`test/integration`, `-tags=integration`): publish flows to JetStream,
  assert profiles land in Postgres and that a restart mid-stream neither duplicates
  counters nor loses endpoints.
- **Load**: profiler backlog must not raise `logproc` flow-store latency — the drop
  policy is only credible if it is measured.

---

## 10. Delivery order

Each phase is independently shippable and independently useful.

| Phase | Work | Result |
|---|---|---|
| **1 — Transport** | `SIEM_FLOWS` stream, `OnFlow` publisher with bounded channel + drop counter, `profilerd` skeleton consuming and counting. | Flows reach a new service; ingest demonstrably unaffected. |
| **2 — Profiling core** | Templating, type lattice, aggregation, caps, Postgres migration + repo, flush loop, dedupe. | Profiles exist and are queryable by SQL. |
| **3 — Capture gap** | `schema.Shape` (v1.1), per-parser shape extraction before masking, Vector config for nginx, fixture updates. | Max request length / header count / cookie count become real numbers where the provider supports them. |
| **4 — API + config** | `profilesvc.go`, six routes, tenant config column, audited writes, snapshot cache in `profilerd`. | Feature is controllable and readable over HTTP. |
| **5 — Frontend** | `profiles.vue`, drawer, SVG components, config panel, nav entry, Vitest coverage. | The feature is usable. |
| **6 — Docs** | `docs/runbooks/` entry, OpenAPI regen (`make api`), quickstart. | Operable by someone who did not build it. |

Phase 3 can run in parallel with 4 and 5; phases 1–2 gate everything.

---

## 11. Open decisions

1. **Extend capture (§3.2)?** Without it, "max request length", "max headers" and "max
   cookies" cannot be delivered for any provider — the data does not exist in storage.
   Recommendation: yes, via `schema.Shape` computed pre-masking, since counting is not
   storing. If declined, phase 3 is dropped and the UI marks those panels "not captured".
2. **Cookie names, or counts only?** Recommendation: capture names, gate on
   `view_sensitive`, default the per-tenant toggle to counts-only.
3. **Retention of profiles.** A profile for a host that stopped serving traffic six
   months ago is stale, not wrong. Recommendation: `retentiond` prunes endpoints whose
   `last_seen` exceeds a configurable window (default 90d), audited.
4. **Request bodies.** Genuinely valuable for profiling `POST` parameters, but no body
   is captured anywhere today and doing so is a significant data-governance change.
   Recommendation: leave out of v1 and treat as its own spec.
