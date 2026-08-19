# Contract: Vector → Ingest Receiver (nginx, F5 ASM)

**Endpoint**: `POST /ingest/v1/vector/{provider}` where `provider` ∈ `nginx` | `f5asm`

## Vector-side requirements (R10)

Every pipeline MUST enable:
- **Disk buffers** — acts as a write-ahead log, surviving restarts (FR-005).
- **End-to-end acknowledgements** — the source withholds its ack (file cursor, syslog client) until the
  sink confirms delivery. Without this, a crash silently loses in-flight events.

### nginx
`file` source with checkpointing; `remap`/VRL parses the custom log format.

Required `log_format` — `$http_cf_ray` is what makes the exact join to Cloudflare possible (R11):

```nginx
log_format siem '$remote_addr - [$time_iso8601] "$request" $status '
                '$body_bytes_sent "$http_referer" "$http_user_agent" '
                '$http_cf_ray $request_time $upstream_response_time';
```

### F5 ASM
`syslog` source. ASM remote logging supports syslog, Key-Value Pairs (HSL, Splunk-style), CSV, and CEF.
Key-Value Pairs is preferred — least parsing ambiguity.

> **V2 — UNVERIFIED, and the highest-risk item in the ingest design.** Logging an arbitrary header
> (`CF-Ray`) is not confirmed in the official Request Logging profile docs, which show only predefined
> tokens. The field-standard approach is an iRule (`HTTP::header value "CF-Ray"`). **Must be lab-tested
> on the target BIG-IP version.** If it fails, F5 falls back to the heuristic join (FR-072b) and SC-024's
> 95% exact-join target is unreachable for the F5 layer.

## Body

NDJSON, gzip or identity. Each line is one structured event post-VRL.

**Required per record**: `timestamp` (RFC 3339 UTC), `provider`, `source_id`, and the raw original line
preserved in `_raw` — Constitution II requires the unmodified original be retained (FR-010).

## Semantics

- At-least-once; `raw_id` derived deterministically from `source_id` + file offset / syslog sequence.
- Durably buffered to JetStream before `2xx`.
- Auth: shared secret header over TLS, from the secret manager. Rate limited.
- `503` when the buffer is unavailable so Vector retains and retries — never a false `200`.
