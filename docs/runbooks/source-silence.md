# Runbook: Log source has gone silent

**Detection**: `pipeline.source_silence` · **Severity**: high

## What fired

A source that had been delivering has now been quiet for longer than its declared cadence.

**This is not the same as "awaiting first record."** A source that never delivered is a
configuration task; a source that stopped is an incident. The alert deliberately does not fire on
the former.

## Why it matters more than it looks

A silent feed is indistinguishable from clean traffic on every dashboard in the system. Searches
return fewer results and nothing appears wrong. This alert exists because that failure is otherwise
invisible.

While the source is silent, **flows for that layer close as partial**. They are still correct —
the missing layer is named explicitly — but any conclusion drawn about that layer is unavailable
rather than negative.

## First check

Whether the credential is the real problem. A rejected credential *causes* silence, and reading the
symptom sends you to the provider's dashboard instead of to the token.

```bash
curl -s -H "Authorization: Bearer <identity>" http://<api>/api/v1/sources \
  | jq '.sources[] | {id, health_state, last_record_at, credential_valid}'
```

## Then, by source

**Cloudflare** — check the Logpush job still exists and is enabled; Cloudflare disables jobs whose
destination fails repeatedly. Confirm the destination URL and that the shared secret still matches.

**DataDome** — there is no separate DataDome feed. Silence here means the *Cloudflare* records
stopped carrying the Worker subrequest: either the Worker is not running, or the
`x-datadome-traffic-rule-response` response-field capture was removed.

**nginx / F5** — check Vector is running and its disk buffer is draining:

```bash
journalctl -u vector -n 50
```

A Vector that cannot reach the ingest endpoint holds events rather than dropping them, so recovery
usually drains a backlog rather than losing data. Expect a burst on recovery — and note that the
burst is **not** a traffic spike; security detections should not be read as if it were.

## Resolving

The alert clears when records resume. If the source is intentionally decommissioned, disable it on
the Sources page rather than leaving it to alert — a muted alert is worse than a deleted one.
