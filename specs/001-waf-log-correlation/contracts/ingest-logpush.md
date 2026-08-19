# Contract: Cloudflare Logpush → Ingest Receiver

**Endpoint**: `POST /ingest/v1/cloudflare/logpush`
**Source of truth**: Cloudflare. This contract is conformance, not design (R4).

## 1. Destination validation handshake (blocking)

At **job creation**, Cloudflare POSTs a gzipped file `test.txt.gz` whose decompressed content is:

```json
{"content":"tests"}
```

The endpoint MUST accept it over HTTPS with a publicly trusted certificate and return `2xx`, or job
creation fails with `error validating destination: error writing object: error uploading`.

**Requirement**: the receiver must handle this *before* any Logpush job can be created. The validation
payload MUST NOT be ingested as log data — detect it and discard, but return success.

## 2. Authentication

Cloudflare offers **no HMAC or signature scheme**. The supported mechanism is `header_*` query
parameters on the destination config injecting arbitrary headers:

```
https://siem.example.com/ingest/v1/cloudflare/logpush?header_Authorization=Bearer%20<SECRET>&tags=...
```

**Requirements**
- Secret compared in **constant time**; sourced from the secret manager, never config files (FR-057).
- TLS required; reject plaintext.
- Rate limited (FR-059).
- Failed auth → `401`, no internal detail, recorded in the audit trail (FR-058).

## 3. Request body

| Property | Value |
|---|---|
| Format | NDJSON — one JSON record per line |
| Batch size caps | `max_upload_bytes` 5 MB–1 GB; `max_upload_records` 1,000–1,000,000 |
| Content-Encoding | **V3 — UNVERIFIED.** Only the *validation* file's gzip is documented. Receiver MUST handle both gzip and identity, dispatching on the actual header. |
| Minimum batch | None. Batches may be smaller than the caps. |

## 4. Delivery semantics

**At-least-once.** Cloudflare retries on failure; a batch that eventually succeeds is not retried.
Duplicates are expected and normal.

**Requirements**
- Idempotent on `RayID` (FR-007). Deterministic `raw_id` from `batch_id` + line offset.
- Durably persisted to JetStream **before** parsing, and before responding `2xx` (Constitution I).
- Respond `2xx` only once durability is achieved — a premature ack loses data on crash.
- `5xx` on internal failure so Cloudflare retries rather than dropping.
- **V4 — retry count/window unverified** (~5 retries over ~5 min from indirect synthesis). Dedup window
  must be sized from verified behaviour.

## 5. Required job configuration

```
timestamp_format = "rfc3339"      # pin explicitly — API default is unixnano (R4)
```

Custom fields MUST be configured to capture the DataDome headers. **This is the single easiest thing to
get wrong in the whole integration** — three distinct mistakes each produce an empty result that is
indistinguishable from DataDome not running (R3):

- **`request_fields` captures the header *as the client sent it*.** A header injected by a Cloudflare
  Worker — which is exactly how DataDome enriches a request — is **not** client-sent and appears **only**
  in `transformed_request_fields`.
- **`transformed_request_fields` is API-only.** The dashboard writes `request_fields` only. It must be set
  through the `http_log_custom_fields` phase entrypoint.
- **Header names must be lower case.** A capitalised name is accepted and logs nothing.

```bash
curl -sS -X PUT \
  "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/rulesets/phases/http_log_custom_fields/entrypoint" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "rules": [{
      "action": "log_custom_field",
      "expression": "true",
      "action_parameters": {
        "request_fields": [{"name": "cf-ray"}],
        "transformed_request_fields": [
          {"name": "x-datadome-requestid"},
          {"name": "x-datadome-isbot"},
          {"name": "x-datadome-botname"},
          {"name": "x-datadome-ruletype"}
        ]
      }
    }]
  }'
```

> **`x-datadome-requestid` is the load-bearing one.** It is what bridges DataDome's identifier space to
> Cloudflare's `RayID`, letting DataDome pull events join nginx and F5 at exact tier (R11a). The other
> headers are useful enrichment; this one is structural.

**Select headers deliberately.** `RequestHeaders` capture will carry session cookies and device
identifiers into raw storage at full traffic rate for the entire retention period. Everything captured
must be classified and masked under FR-015.

> DataDome's **full per-request decisions come from its own pull feed**, not from these headers — see
> [`ingest-datadome-pull.md`](./ingest-datadome-pull.md). If custom fields are missing, the DataDome
> *bridge* is lost (joins degrade to heuristic), which the system MUST report as a source-configuration
> fault rather than as a clean flow.

## 6. Fields consumed

**Correlation**: `RayID` (primary key), `EdgeStartTimestamp`, `EdgeEndTimestamp`
**Request**: `ClientIP`, `ClientRequestHost`, `ClientRequestURI`, `ClientRequestMethod`, `EdgeResponseStatus`
**Verdict**: `SecurityAction`, `SecurityRuleID`, `SecurityRuleDescription`, `SecurityActions[]`,
`SecuritySources[]`, `SecurityRuleIDs[]` — **or** legacy `WAFAction`, `WAFRuleID`,
`FirewallMatchesActions[]`, `FirewallMatchesSources[]`, `FirewallMatchesRuleIDs[]`
**Bot**: `BotScore`, `WorkerStatus`

> **V5 — UNVERIFIED**: which security-field family this zone populates depends on plan and zone age.
> The parser MUST handle both and record which was seen. Building on one family alone is a known risk.

## 7. Latency

Standard Logpush publishes **no maximum-delay SLA**. **Edge Log Delivery** (HTTP-requests dataset only)
allows a configurable 30s–5min max batch interval and is **recommended** — SC-006 (95% searchable in 30s)
and SC-007 are otherwise hostage to an unbounded push interval.

## 8. Responses

| Code | Meaning |
|---|---|
| `200` | Batch durably buffered (or validation handshake accepted) |
| `400` | Malformed body — recorded, not retried |
| `401` | Auth failure |
| `429` | Rate limited — Cloudflare retries |
| `503` | Buffer unavailable — Cloudflare retries. **Never drop to return 200.** |
