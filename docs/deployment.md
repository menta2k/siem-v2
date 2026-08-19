# Deployment

Four services, each independently deployable. That separation is a requirement, not a preference:
**collection must survive maintenance of everything else** (FR-065, SC-022).

| Service | Role | Can it be down? |
|---|---|---|
| `logproc` | Receives, buffers, parses, correlates, stores | **No.** Records are lost only if this cannot buffer. |
| `apiserver` | Search, evaluation, alerts, admin | Yes — collection continues. |
| `retentiond` | Tiering, expiry, legal hold, archive | Yes — expiry is delayed, nothing is lost. |
| `wirefilter-svc` | Cloudflare expression evaluation | Yes — CF rule testing reports unavailable; everything else works. |

## Build

```bash
make build            # static binaries, CGO_ENABLED=0
make build-wirefilter # the Rust sidecar
make build-frontend
make docker           # container images for all services
```

Coraza is pure Go, so the backend binaries stay static and portable. The only non-Go component is
the wirefilter sidecar, deliberately isolated in its own process (research.md R1).

## Order of operations

1. **`retentiond --migrate-only`** — applies the PostgreSQL schema. Idempotent; safe to run on every
   deploy.
2. **`retentiond`** — creates the object-store buckets. **Object Lock can only be enabled at bucket
   creation and cannot be retrofitted**; getting this wrong means recreating the bucket and
   re-copying the archive.
3. **`logproc`** — start before pointing any provider at it, so the first delivery is not refused.
4. **`apiserver`**, **`wirefilter-svc`** — any time.

### First start

When **no active account can sign in** — a fresh database, or a recovery where every admin was
deactivated — the apiserver seeds a bootstrap administrator and logs a one-time setup link:

```
WARN BOOTSTRAP: no account can sign in yet — open this one-time setup link on the
     console to create the administrator's password  path=/invite?token=...
```

Open that path on the console: it previews the account, takes a password (12 characters
minimum), and the first sign-in walks through MFA enrolment — the bootstrap account gets no
weaker path than any invited account. The link expires after 7 days, dies on redemption, and is
**re-issued fresh on every restart** until someone completes setup, so a lost log line is fixed
by restarting, not by touching the database. Once any account has a password, bootstrap never
runs again.

`SIEM_ADMIN_EMAIL` sets the administrator's address (default `admin@siem.local`);
`SIEM_ADMIN_TENANT` the tenant (default `default`).

## Configuration

Secrets are **references**, never values: `env:SIEM_PG_DSN`, resolved at startup. A configuration
file can therefore be committed. A literal value in a secret field is rejected rather than used.

Required environment:

| Variable | Used by |
|---|---|
| `SIEM_PG_DSN` | apiserver, retentiond |
| `SIEM_INGEST_SECRET` | logproc |
| `SIEM_S3_ACCESS_KEY` / `SIEM_S3_SECRET_KEY` | retentiond |
| `SIEM_CORS_ORIGINS` | apiserver — explicit origins only, never a wildcard |

## Rollback

**Services** — replace the binary or image and restart. Correlation state is persisted in Valkey, so
`logproc` resumes in-progress flows rather than discarding them. Buffered records are replayed from
JetStream automatically.

**Database migrations** — each runs in its own transaction, so a failure leaves the schema at the
last complete migration rather than half-applied. Migrations are additive by policy; a change that
would drop or retype a column requires a migration plan and a re-parse or dual-write strategy, and
is not rolled back by redeploying an older binary.

**Parsers** — a parser rollback is safe and does not lose data: records that fail against the older
parser are dead-lettered with their original bytes and can be reprocessed once the newer parser
returns.

```bash
siem-logproc replay-deadletters --provider <provider> --dry-run
```

**What cannot be rolled back**: data deleted by a retention pass, and data whose Object Lock
retention has been applied. This is by design — see the legal-hold guarantees — and is why
`retentiond` refuses to expire anything when it cannot read the hold registry.

## Scaling

The documented target is 2,000 records/sec per provider, ~8,000 combined.

- **`logproc`** scales horizontally; JetStream consumer groups distribute batches. Correlation state
  is in Valkey rather than in-process, so any instance can close any flow.
- **VictoriaLogs** scales vertically first — the maintainers' own guidance — and only then to the
  cluster build.
- **The exact-join ratio is the metric that matters under load.** Throughput can look healthy while
  correlation quality falls, and the second failure is the one that makes the data untrustworthy.

## Health

`/health` on each service is unauthenticated (it exposes nothing and is needed before credentials
exist). It asserts **meaningful output**, not liveness: a `logproc` that is running but producing no
flows reports unhealthy, which is the entire point of Constitution Principle IV.
