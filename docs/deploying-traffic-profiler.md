# Deploying the traffic profiler (`profilerd`)

The profiler consumes completed flows and learns, per endpoint, what normal looks like: which
parameters each URL accepts, their inferred types, and the structural ceilings of the requests that
reach it. `/job/8584286` and `/job/8584287` appear as one route, `/job/{int}`.

It is deliberately a separate binary. A profiler backlog degrades profile freshness and **nothing
else** — stopping, resizing or redeploying it never touches collection (Constitution I).

## Data path

```
logproc ──(completed flows)──► NATS JetStream SIEM_FLOWS ──► profilerd ──► PostgreSQL
   │            bounded queue,        24 h / 2 GiB,              │        profile_endpoint
   │            drop-and-count        Discard=old                │
   └── never blocks on any of this                               └── read by apiserver
                                                                     GET /api/v1/profiles*
```

Two properties worth knowing before operating it:

- **`logproc` publishes best-effort.** The hand-off is a bounded in-process queue; when it is full
  (profiler far behind, NATS down) flows are **dropped from profiling only** — they are still
  stored and searchable. Drops are counted and logged once a minute.
- **`profilerd` acks after flush.** Consumed messages are acknowledged only after the covering
  PostgreSQL commit, so a crash replays at most one flush interval (default 30 s). Replayed flow
  IDs are deduplicated; counters stay honest.

## Prerequisites

| Dependency | Why | Notes |
|---|---|---|
| NATS JetStream | The `SIEM_FLOWS` stream | The same server as the ingest buffer; the stream is created automatically by whichever side starts first. |
| PostgreSQL | Profile storage + per-tenant policy | Migration `009_traffic_profiles.sql` is applied automatically at start. |
| `logproc` at this version or later | Publishes flows | Older `logproc` runs fine but publishes nothing; the profiler waits on an empty stream. |

## Build and artifacts

```bash
make build-profilerd        # bin/profilerd (static, CGO_ENABLED=0)
make build                  # or all four Go services
```

Delivered like the other Go services: a container image (`deploy/docker/Dockerfile.backend` with
`SERVICE=profilerd`), the OS package (`nfpm.yaml` → `/usr/bin/siem-profilerd` +
`siem-profilerd.service`), and a compose service under the `app` profile.

## Configuration

`backend/configs/profilerd.yaml` (host-run) / `deploy/compose/configs/profilerd.yaml` (compose):

```yaml
server:
  http_addr: ":8300"        # health/metrics only; data is served by the apiserver

storage:
  jetstream:
    url: "nats://localhost:4222"
  postgres:
    dsn_ref: "env:SIEM_PG_DSN"

profiler:
  flush_interval: 30s       # commit cadence; also the crash-replay bound
  consumer_name: "profiler" # durable consumer identity — do not run two instances with one name
  max_pending_flows: 5000   # force an early flush past this many unacknowledged flows
```

Environment: **`SIEM_PG_DSN`** only. Secrets are references in the file, never values.

Raising `flush_interval` batches more per commit; it also widens the replay window after a crash
and the acknowledgement latency. 30 s is right unless PostgreSQL write load says otherwise.

## Deploy

**Compose** (the `app` profile already includes it):

```bash
docker compose -f deploy/compose/docker-compose.yml --profile app up -d --build profilerd
```

**systemd / package install:**

```bash
systemctl enable --now siem-profilerd
journalctl -u siem-profilerd -f     # expect: "connected to flow conveyor", "restored endpoint profiles"
```

**Host-run development:**

```bash
SIEM_PG_DSN=postgres://siem:siem_dev_only@localhost:55432/siem?sslmode=disable \
  bin/profilerd --conf backend/configs/profilerd.yaml
```

Restart `logproc` at the same version once, so it starts publishing — look for
`publishing completed flows for profiling` in its log.

## Enable profiling — nothing is analyzed by default

Deployment alone profiles **nothing**. Which domains are analyzed is per-tenant policy, an explicit
allow-list edited in the GUI: **Traffic profiles → Configure** (requires `manage_sources`, i.e.
admin or engineer). Pick hosts from the observed list or add patterns
(`api.example.com`, `*.shop.example.com`), optionally exclude path prefixes (`/health`), save.
Every change is audited as `profiler_config.replaced`.

The same over the API:

```bash
curl -s -X POST http://<api>/api/v1/profiler/config \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"config":{"enabled":true,"hosts":["api.example.com"],"exclude_paths":["/health"],
       "cookie_names":false,"min_observations_to_publish":20}}'
```

`enabled: true` with an empty host list profiles nothing — enabling the feature must never
implicitly profile the whole estate. The profiler picks up config changes within 30 s.

## Verify

1. **Health** (unauthenticated, like every service):

   ```bash
   curl -s http://localhost:8300/health | jq
   ```

   ```json
   {
     "status": "healthy",
     "consumed": 4182,
     "skipped": 3970,
     "last_flush_at": "2026-08-21T11:40:12Z",
     "flush_error": "",
     "aggregator": {
       "observed": 212, "deduplicated": 3, "cap_hits": 0,
       "endpoints": 47, "dirty_pending": 12,
       "collapses": 5, "secrets_withheld": 0,
       "invalid_query_strings": 1, "retired_merged": 9
     }
   }
   ```

   `consumed` is flows read from the stream; `skipped` is flows outside every tenant's allow-list.
   A `503` means the last flush failed and is being retried; nothing is lost while that holds.

2. **Profiles appear**: the Traffic profiles page fills as traffic arrives. Path templates need
   evidence — a position collapses to `{int}`/`{uuid}`/… after ~64 observations, so on a fresh
   deploy individual URLs appear first and merge into templates as volume accumulates. That is
   learning, not a fault.

## Operating signals

Constitution IV applies: the failure mode to watch is **consuming without producing**.

| Signal | Where | Meaning / action |
|---|---|---|
| `consumed` rising, `endpoints` flat at 0 | `/health` | Everything is being skipped — almost always an allow-list that matches no real host. Check `skipped`, then the tenant config. |
| `flows dropped before profiling` | `logproc` log | The conveyor hand-off is saturated or NATS is down. Collection is unaffected; profiling has gaps for that minute. |
| `flush_error` non-empty / `503` | `/health` | PostgreSQL trouble. The worker stops fetching past `2×max_pending_flows` and retries; backlog rides in JetStream. |
| `cap_hits` rising | `/health` | A tenant or host hit its endpoint cap (20 000 / 5 000). Usually templating failed on an unanticipated URL shape — look at the newest endpoints for that host. |
| `secrets_withheld` rising | `/health` | Query values matching secret patterns were counted but never stored. Expected on auth callbacks; a spike elsewhere is worth a look. |
| `truncated` flag on an endpoint | UI / API | A per-endpoint cap (200 params, 64 enum values, 32 statuses) stopped growth. The profile keeps updating what it already tracks. |

Sizing note: state is in memory — roughly endpoints × parameters. The default caps bound a
worst-case tenant at ~20 000 endpoints; typical estates sit far below. Watch RSS alongside
`endpoints` on first rollout.

## Outage and replay semantics

| Scenario | Effect |
|---|---|
| `profilerd` down < 24 h | Flows accumulate in `SIEM_FLOWS`; on restart it consumes the backlog. Profiles are complete, just late. |
| `profilerd` down > 24 h (or stream past 2 GiB) | Oldest flows age out of the conveyor. Profiles have a gap; nothing else is affected — VictoriaLogs remains the store of record. |
| Crash (kill -9) | At most one flush interval replays; flow-ID dedupe absorbs the counter effect. Learned templates reload from PostgreSQL — collapse decisions are never re-derived or reversed. |
| PostgreSQL down | Flushes fail and retry; fetching pauses past the pending bound; `/health` reports degraded. No acks are lost. |
| NATS down | `logproc` counts drops; `profilerd` waits and reconnects. |

## Rollback / decommission

Stopping `profilerd` is the rollback — no other service notices. To decommission fully:

```bash
systemctl disable --now siem-profilerd
nats stream rm SIEM_FLOWS                 # optional: drop the conveyor and its consumer
```

Learned profiles stay readable in the UI until deleted (per-endpoint **Forget** in the drawer, or
`DELETE FROM profile_endpoint` for a tenant — the former is audited, the latter is a DBA act).
Disabling a tenant's config (`enabled: false`) stops analysis but keeps existing profiles readable.

Migration `009` is additive (two schema objects, one tenant column); running an older binary
against the migrated schema is safe.

## Troubleshooting: "no profiles are appearing"

In order:

1. Tenant config **enabled** with a **non-empty host list**? (`GET /api/v1/profiler/config`)
2. Do the listed hosts match real traffic hosts exactly (or by `*.` wildcard)? Compare `skipped`
   vs `observed` in `/health` — high `skipped` with zero `observed` is a list/traffic mismatch.
3. Is `logproc` publishing? Its log should show `publishing completed flows for profiling`; if it
   shows `flow conveyor unavailable`, fix NATS connectivity and restart `logproc`.
4. Is the endpoint hidden by the publish threshold? Toggle **Show rare** in the UI
   (`min_observations_to_publish` hides sub-threshold endpoints; they are still counted).
5. `consumed` at 0 with the stream non-empty → check the durable consumer name was not changed
   mid-flight (a new name starts a new consumer at the stream tail).
