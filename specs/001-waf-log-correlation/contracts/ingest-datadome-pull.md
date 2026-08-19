# Contract: DataDome Log Export → Puller (pull mode)

**Direction**: backend polls DataDome. The only **pull**-mode source in the system.
**Source of truth**: DataDome. Corrected per R3; see also R11a for how these records join.

## Why pull, and not the webhook

DataDome's Integrations **webhook is an attack-notification mechanism and cannot feed this platform.**
Its payload is an attack summary — `THREAT_NAME`, `ENDPOINT_NAME`, `ATTACK_DURATION`,
`ATTACK_REQUESTS_COUNT`, `IP_COUNT` — carrying **no per-request identifier, IP, URI or action**. There is
nothing in it to correlate against another provider's record.

This cannot be configured away: the dialog's Threats and Attack Severity fields choose which *attacks*
notify, not which requests are logged. No combination produces per-request events. (FR-001b forbids
presenting such a feed as a source.)

## Polling

```jsonc
{
  "delivery_mode": "pull",
  "pull_config": {
    "endpoint": "https://api.datadome.co",   // CONFIRM per account — V10
    "path": "/v1/logs/export",
    "interval_seconds": 60
  }
}
```

Credential: a DataDome API key, from the secret manager (FR-057).

**Watermark (FR-001a)**: the puller walks the export in time windows and persists a per-source watermark,
so a restart resumes where it stopped — never re-reading a window (duplicate work) nor skipping one
(silent loss). The watermark advances only after records are durably buffered, so a crash mid-window
re-reads rather than skips; duplicates are then absorbed by the idempotency rule below.

## Fields consumed

| Field | Use |
|---|---|
| `requestid` | **Correlation identifier** — DataDome's per-request id (R11a) |
| `timestamp` | `event_time` |
| `ip`, `host`, `uri`, `method` | Request attributes; heuristic-join inputs if bridging fails |
| `action` | `allow` \| `block` \| `challenge` \| `captcha` → normalized action (FR-025) |
| `botscore` | Verdict score |
| `ua`, `country`, `asn` | Client attributes |

**Bot score is not a threat score.** A high bot score on an *allowed* request is a score conflict worth
surfacing; a WAF threat rating on an allowed request is only a severity hint. They must not be merged
into one "score" concept.

## Semantics

- **At-least-once**; `raw_id` derived deterministically from `requestid` + window, so a re-read window
  produces no duplicate layer, count, or alert evidence (FR-007).
- Records durably buffered before parsing (Constitution I).
- Poll failures are retried with backoff and count toward source health; sustained failure raises the
  source-silence alert (FR-044) — a puller that cannot reach the API is indistinguishable from a silent
  source and must alert either way.

## Preconditions to verify before configuring (V10)

1. **Export entitlement** — per-request log export is generally a **Corporate/Enterprise** plan feature.
   Without it DataDome cannot supply per-request events at all. Discover this before creating the source.
2. **Account API base URL** — confirm per account rather than assuming the default.
3. **Allowed traffic is included in the export, not blocks only.** A blocks-only export defeats the
   system's main purpose: the disagreement worth seeing is *"DataDome allowed this and F5 blocked it"*,
   which is invisible if DataDome reports only blocks. This is a leading cause of "nothing correlates".
