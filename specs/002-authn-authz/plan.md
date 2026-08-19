# Plan: Authentication & Authorization

**Feature**: `002-authn-authz` | **Date**: 2026-08-19 | **Reference implementation**: `/home/sko/projects/siem` (v1)

## Where v2 stands today

v2 already has the *authorization* half working and verified live:

- `tenancy.Principal` — roles (`analyst`/`engineer`/`admin`), permission bundles, property scope,
  with the structural guarantee that **tenant comes only from the resolved principal** (FR-074b).
- `server.Authenticator` + `RequirePermission` — permissions declared at the routing table, refusals
  audited, forbidden rendered as not-found.
- Append-only audit trail, per-principal rate limiter, `errors` package that never leaks detail.

What it does **not** have is authentication: `resolvePrincipal` treats the bearer string as the
identity itself — explicitly commented as "the seam where a real identity provider belongs". This
plan fills that seam. **Everything downstream of the seam keeps working unchanged**, which is the
payoff of having built it as a seam.

## What v1 provides, and the lessons encoded in it

v1's auth is ~2,700 lines of production-hardened code whose comments record *why*. These are the
decisions worth carrying over wholesale — several encode bugs already paid for once:

| Decision | The lesson behind it |
|---|---|
| argon2id, OWASP interactive params (19 MiB, t=2, p=1), PHC encoding | Memory hardness is what makes an offline attack on a stolen hash expensive; PHC lets params upgrade without invalidating stored hashes |
| One `ErrInvalidCredentials` for unknown-user AND wrong-password, plus **dummy-hash verification for unknown users** | Distinct replies or timing turn login into a user-enumeration oracle |
| Token **purpose signed into claims** (`access` / `refresh` / `mfa_pending`) | A refresh token presented as an access token must fail by construction, not by where it turned up |
| `mfa_pending` token grants *nothing* except the right to present a TOTP code | Without it a caller skips the password step and brute-forces codes |
| `TokenPair` carries `ExpiresAt` AND `RefreshExpiresAt` separately | v1 bug: dating the refresh cookie with the access expiry evicted it within minutes — logout on every reload |
| Refresh token in a `__Host-` prefixed, httpOnly, Secure, SameSite=Strict cookie; access token in memory only | The browser *enforces* the `__Host-` guarantees; localStorage puts the longer-lived credential where any XSS reads it |
| Public operations as an **explicit set of generated constants**, never prefixes or string literals | v1 bug: a hand-written name matched no RPC, so `Refresh` demanded the very access token it exists to reissue |
| Tenant **re-read on every request**, not trusted from the token | A suspended tenant's tokens stay cryptographically valid; re-reading makes suspension take effect immediately |
| Invites instead of self-registration: 256-bit secret, SHA-256 stored, 7-day TTL, one-time, redeem sets a password and **stops** — no session | 256 bits of entropy is what justifies a non-memory-hard hash; redeem-grants-no-session keeps possession of a link below possession of an account |
| Min password length 12, **length is the only rule** | Composition rules push people to `Passw0rd!` and away from passphrases that resist offline attack |
| TOTP skew = 1, secret encrypted at rest, never logged after enrolment | Each extra skew period is another valid code an attacker may guess |
| Frontend signed-out marker in storage | Logout must not be undone by an auto-refresh racing the revocation |

## Design decisions for v2

### D1: Adopt v1's authentication stack as-is (argon2id + TOTP + JWT pair + revocation)

Port `internal/auth/{credentials,mfa,tokens,invite,revocation,context}.go` with v2 package paths.
The code is tested, the comments are the documentation, and the parameters are current OWASP.
Valkey (already running, persistence on) replaces Redis as the revocation store — same interface.

### D2: Keep v2's typed permission model; do NOT adopt Casbin

The one deliberate divergence, and it needs justifying since v1 uses Casbin route policy:

- v2's permissions are **semantic** (`view_sensitive`, `export`) rather than route-shaped, which is
  what lets one permission govern an endpoint *and* the behaviour inside it (e.g. export includes
  unmasked content only with `view_sensitive`). A route table cannot express that.
- They are compile-time checked and declared at the routing table, already audited per decision.
- Casbin's real contribution in v1 is **deny-by-default** — an endpoint without a policy line is
  unreachable. v2 gets the same property structurally: a startup/test assertion that **every route
  under `/api/v1/` is wrapped in `RequirePermission`**, failing the build otherwise. That is the
  fail-closed direction without a second policy language to keep in sync.
- Casbin's tenant-as-domain guarantee is already stronger in v2: the tenant is not even a parameter
  a call site could pass wrongly — `TenantOf(ctx)` is the only source.

### D3: Sessions — short access token in memory, refresh in the `__Host-` cookie

- Access TTL 10 minutes, refresh TTL 7 days (v1's shape). Signing key ≥32 bytes from the secret
  resolver (`env:SIEM_JWT_KEY`), never config files.
- Logout revokes the refresh token's JTI in Valkey with TTL = remaining lifetime, and clears the
  cookie. Refresh rotates: each use revokes the presented token and issues a new pair, so a stolen
  refresh token dies the first time the legitimate client refreshes after the theft.

### D4: MFA is mandatory for admin, enrolled-on-first-login for all

Login returns either a `TokenPair` (MFA verified) or an `mfa_pending` challenge. Enrolment renders
the `otpauth://` URI as a QR (v1's `MfaEnrolment.vue` is the reference). The TOTP secret is
encrypted with a key from the secret resolver before storage.

### D5: Invites replace the dev seed

`POST /api/v1/invites` (admin, audited) → one-time link. Preview and redeem are the only public
endpoints beyond login/refresh/verify-mfa — listed in an explicit set with v1's comment about why
an explicit set. The dev seed remains behind a `--dev-seed` flag for local work only.

### D6: Rate limiting and lockout on the auth endpoints

Per-IP and per-identity windows on `login` and `verify-mfa` using the existing `RateLimiter`.
No hard account lockout (a lockout is a denial-of-service primitive against a known email);
instead escalating delay + audit + the existing alerting path (`auth.failed` entries are already
in the trail — add a detection over them, with a positive and a near-miss fixture like every other).

## Data model (PostgreSQL migration `003_auth.sql`)

```
principal      + password_hash TEXT            -- PHC-encoded argon2id
               + mfa_secret_enc BYTEA          -- encrypted TOTP secret, NULL until enrolled
               + mfa_enrolled_at TIMESTAMPTZ
               + last_login_at TIMESTAMPTZ
               + password_set_at TIMESTAMPTZ

invite         id, tenant_id, email, role, secret_hash (SHA-256), created_by,
               created_at, expires_at, redeemed_at    -- one-time: redeemed_at set exactly once
```

Revocation lives in Valkey (`revoked:{jti}` with TTL), not PostgreSQL — it is hot-path,
self-expiring state.

## API surface

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /api/v1/auth/login` | public | constant-time; returns pair or `mfa_pending` |
| `POST /api/v1/auth/mfa` | `mfa_pending` token | returns pair; sets refresh cookie |
| `POST /api/v1/auth/refresh` | refresh cookie | rotates; public in the operation set (v1's lesson) |
| `POST /api/v1/auth/logout` | access | revokes refresh, clears cookie |
| `GET  /api/v1/auth/me` | access | profile + permission map for the frontend `can` |
| `POST /api/v1/invites` | `manage_users` (new perm, admin) | audited |
| `GET  /api/v1/invites/preview` | public (possession of secret) | coarse errors only |
| `POST /api/v1/invites/redeem` | public (possession of secret) | sets password, grants **no** session |
| `POST /api/v1/auth/mfa/enroll` | access | QR provisioning |

`resolvePrincipal` changes from identity-string lookup to: parse access token → check purpose →
load principal by claims subject → **re-read tenant active flag** → attach to context. Nothing
after the context attach changes.

## Frontend

Mirror v1's `stores/auth` shape as a Nuxt composable: access token in memory, `awaitingMfa` state,
`can` map derived from `/auth/me`, signed-out marker, silent refresh on 401-once-then-redirect.
Pages: `login.vue`, MFA step, enrolment QR (port `MfaEnrolment.vue`), invite redemption. The
sidebar identity switcher becomes the real profile block (v1's append slot). Dev identities remain
behind a build flag.

## Phases

1. **Port the auth core** (credentials, mfa, tokens, invite, revocation) with its tests — pure
   code, no wiring. Valkey revocation adapter + integration test against the live container.
2. **Migration + repos** — `003_auth.sql`, principal/invite repo methods, encrypted-secret helper.
3. **Auth endpoints + middleware swap** — the explicit public-operation set, cookie handling,
   `resolvePrincipal` replacement, deny-by-default route assertion, rate limits.
4. **Frontend** — login/MFA/invite pages, auth composable, remove dev switcher from prod builds.
5. **Verification** — the checklist below, in Chrome against the live stack, plus the
   `auth.failed`-spike detection with fixtures.

## Verification checklist — status at 2026-08-19

- [x] Unknown email and wrong password: same error, verified live (identical `{"code":"unauthorized"}` responses); dummy hash exercised
- [x] Refresh token rejected as access token; `mfa_pending` rejected as either — unit tests + live (challenge-as-access → 401)
- [x] Refresh rotates and the replaced token is dead (verified live: old cookie → 401, new → 200); logout kills refresh immediately
- [x] Cookie carries httpOnly + SameSite=Strict + the refresh TTL expiry, verified on the live Set-Cookie header. `__Host-` + Secure are production-mode; dev-over-HTTP uses the unprefixed name behind `SIEM_DEV_INSECURE_COOKIES` with a startup warning
- [x] `SIEM_DEV_SKIP_MFA=true` completes login on the password alone (no TOTP step) for local development — env-gated, loud startup warning, happy-path only: wrong passwords, rate limiting and audit are untouched. Covered by `TestDevSkipMFALogsInWithoutASecondStep`
- [x] Refresh cookie expiry = refresh TTL (7 days out on the live header), plus `TestRefreshExpiryIsItsOwn` as the regression test
- [x] Deactivated principal: `ResolveAccess` re-reads the record per request; refresh re-reads before rotating
- [x] Every `/api/v1/` route carries a `RequirePermission` wrapper — `TestEveryProtectedRouteRequiresAPermission` fails the build otherwise; public operations asserted to be an explicit set
- [x] Invite: garbage/expired/redeemed all return `ErrInvalidInviteToken`; secret renders REDACTED under every fmt verb; redeem grants no session
- [x] User management UI (`/users`, admin-gated) + endpoints: `GET /api/v1/users` (tenant listing with status/MFA/invite-pending), `POST /api/v1/users/{id}` (activate/deactivate, role change, MFA reset) — tenant-scoped in the SQL, self-lockout guards (no self-deactivation/demotion), cross-tenant target renders as not-found. Covered by `TestUserAdministration`; verified live in the browser
- [x] Invite redemption UI (`/invite?token=…`, public): preview → password (min 12) → redeem → sign-in; one-time property verified live (reused link refuses); the setup link is shown exactly once with copy button and expiry
- [x] Feed management (ported from v1): per-feed ingest endpoints `/ingest/v1/{provider}/{feed_id}` with per-feed tokens — minted server-side (`auth.NewFeedToken`, id half for O(1) lookup + 256-bit secret half), stored as SHA-256 only (v2 upgrade over v1's reversible sealed store). Token re-roll keeps v1's immediate-kill semantics with the "providers retry, nothing is lost" confirm dialog; the token appears exactly once, with ready-to-paste Logpush `destination_conf` (`?header_Authorization=Bearer%20…`) or Vector sink URL. Ingest serves credentials from a 30s-refresh in-memory snapshot: DB outage degrades to stale cache, a never-loaded store answers 503 (senders retry), never 401. PUT accepted on logpush routes (destination validation). Endpoints behind manage_sources: GET/POST `/api/v1/feeds`, POST `/api/v1/feeds/{id}`, POST `/api/v1/feeds/{id}/rotate`. Covered by `TestFeedManagement`, `feedauth` unit tests; create→deliver→rotate→old-token-401 verified live
- [x] Auth events in the trail (login, logout, mfa_enrolled, failed) — verified live; credential never recorded
- [x] MFA enrolment confirmed ONLY by a verified code (`analyst` remains unenrolled after seeding; `engineer` enrolled via the browser flow)
- [x] Full browser flow verified in Chrome: password → QR enrolment → TOTP → session; reload restores via the cookie; sign-out sticks (signed-out marker)

- [x] Production TLS run: the `__Host-`/Secure cookie path exercised end to end on https://siem.server-lab.eu (Cloudflare Tunnel) — bootstrap invite redeemed, admin signed in, refresh cookie observed as `__Host-siem_refresh` with Secure+HttpOnly+SameSite=Strict in the live browser session (2026-08-19). Nothing outstanding.
