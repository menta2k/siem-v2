# Security Review — 2026-08-19

Scope: the four externally-reachable surfaces (ingest, query, evaluation, export) plus the
authentication stack added in feature `002-authn-authz`. Method: manual path review against the
constitution's checklist, `gosec` over all non-test packages, and adversarial tests already in the
suite (each claim below names its enforcement).

## Findings and dispositions

`gosec` reported 4 issues; all dispositioned, 0 remaining:

| Finding | Disposition |
|---|---|
| G115 int→uint32 in password verification | **Fixed**: `decodeHash` now rejects keys/salts over 1 KiB, bounding the conversion and capping the cost a corrupt record can impose |
| G124 ×2 cookie attributes (conditional `Secure`) | **Asserted, then annotated**: `TestTheCookieCarriesItsSecurityAttributes` checks HttpOnly, Secure, SameSite=Strict and the `__Host-` prefix on the *rendered* production header — the thing the browser actually sees |
| G304 file read from variable | Intended behaviour: the operator's own `--conf` flag |

## Load testing found what review could not

Two production-grade defects surfaced only under the 3× burst (24,000 events/sec):

1. **NATS max-payload refusals** — a 6,000-record Logpush batch marshals past the 1 MiB default,
   so every large delivery came back 503. Real Logpush batches reach 1 GB. Fixed by chunking in
   the buffer (each chunk under 512 KiB, deterministic per-chunk MsgIds so retried publishes
   deduplicate chunk-by-chunk); the guarantee no longer depends on server tuning.
2. **Fatal data race** — `concurrent map read and map write` crashed the processor: the consumer
   goroutine and the flush ticker shared the pipeline's maps unlocked. Never manifested below
   ~24k/s. Fixed with a mutex; reproduced by a `-race` test so it cannot return.

After both fixes: **2,880,000 events at 23,981/sec aggregate, zero refused** (SC-005).

## Path review

**Ingest** — durability before acknowledgement (503, never a false 200); constant-time shared-secret
comparison; unset secret fails closed; batch/record size bounds with explicit truncation; gzip
dispatch + sniffing; the validation probe is never stored. Enforced in `internal/ingest/*_test.go`.

**Query** — no client string ever reaches LogsQL: typed parameters, whitelist-validated, tenant
injected server-side from the resolved principal only. Seven injection shapes rejected in tests and
live. Forbidden and not-found are indistinguishable (enumeration).

**Evaluation** — Coraza runs `DetectionOnly` with `@rbl`/`@geoLookup`/persistent collections off;
the wirefilter sidecar is process-isolated, batch-bounded, and "unavailable" is never rendered as
"no match". Incomplete captures warn rather than silently evaluating.

**Export** — requires its own permission; unattributed exports refused; redactions named, never
silent; unmasked content requires `view_sensitive` and every such view is individually audited —
and refused outright if the audit write fails.

**Authentication** — argon2id (OWASP params), dummy-hash for unknown users, TOTP with sealed
secrets, purpose-signed JWTs, rotation-with-revocation failing closed, invites that render
REDACTED under every fmt verb. Deny-by-default enforced by a build-failing route assertion.

## Accepted residual risks

- RustFS is pre-1.0; Object Lock enforcement is verified single-node (V9) and re-verification on
  the production topology remains on the checklist.
- Dev conveniences (`SIEM_DEV_IDENTITIES`, `SIEM_DEV_INSECURE_COOKIES`, `SIEM_DEV_SKIP_MFA`, seeded passwords) are
  env-gated and log a startup warning; a production hardening pass should assert they are unset.
- The 24-hour sustained soak (SC-004 in full) has not been run; a 3-minute sample at target rate
  and the 2-minute 3× burst stand in for it. The number to watch on the real soak is the
  exact-join ratio, not throughput.

