# Contracts

**Feature**: `001-waf-log-correlation` | **Phase**: 1

Four interface surfaces, each with a different stability obligation.

| Contract | Direction | Stability |
|---|---|---|
| [`proto/`](./proto/) → `backend/api/openapi.yaml` | Frontend & external clients → backend | Public. Versioned; breaking changes need a major bump. **The generated spec at `backend/api/openapi.yaml` is authoritative** — the copy in this directory is the design-time sketch that preceded it. |
| [`ingest-logpush.md`](./ingest-logpush.md) | Cloudflare → backend | **Dictated by Cloudflare.** We conform; we do not choose. |
| [`ingest-vector.md`](./ingest-vector.md) | Vector → backend | Internal, but a deployed-config coupling. |
| [`ingest-datadome-pull.md`](./ingest-datadome-pull.md) | Backend → DataDome export API | **Dictated by DataDome.** The only pull-mode source. |
| [`wirefilter-sidecar.md`](./wirefilter-sidecar.md) | Backend → Rust sidecar | Internal, versioned together. |
| [`normalized-event.schema.json`](./normalized-event.schema.json) | The common schema | **The most important contract in the project** (Constitution II). Additive changes only; removals/type changes are breaking and need migration + re-parse (FR-009 governance). |

**OpenAPI generation**: proto is the source of truth. `openapi.yaml` is generated via
`protoc-gen-openapi` and **committed**, so the diff is reviewable and the spec is servable without a
build step. `make api` regenerates; CI fails if the committed file is stale.

**Query API design constraint (R8, FR-074b)**: no endpoint accepts LogsQL, or any query fragment, from a
client. Endpoints take structured, typed parameters that the backend compiles into LogsQL with tenant
headers injected server-side. This is what makes cross-tenant access inexpressible rather than merely
refused, and it closes off query injection.
