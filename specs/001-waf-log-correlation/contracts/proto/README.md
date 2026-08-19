# Protobuf Service Definitions

**Source of truth** for the API. `contracts/openapi.yaml` is generated from these via
`protoc-gen-openapi` and committed so the diff stays reviewable (`make api`; CI fails on staleness).

## Planned packages

| Package | Service | Covers |
|---|---|---|
| `flow.v1` | `FlowService` | `SearchFlows`, `GetFlow`, `GetFlowRecords`, `ExportFlow` |
| `evaluation.v1` | `EvaluationService` | `CreateEvaluation`, `GetEvaluation`, `ListEvaluations` |
| `alert.v1` | `AlertService` | `ListAlerts`, `AcknowledgeAlert`, `GetCollectionHealth` |
| `admin.v1` | `AdminService` | sources, detections, retention policies, legal holds, principals |

## Conventions

- Kratos v2 layout: `api/<pkg>/<version>/*.proto`, HTTP mapping via `google.api.http` annotations.
- Errors via `kratos/errors` with proto-defined reasons; messages disclose no internal detail (FR-058).
- Timestamps are `google.protobuf.Timestamp`, always UTC.
- **No field anywhere accepts a query string, filter expression, or LogsQL fragment** (R8, FR-074b).
  Search inputs are enumerated, typed fields. This is a review gate, not a guideline.
- Tenant is never a request field — it is derived server-side from the authenticated principal.
  A client-supplied tenant would make cross-tenant access expressible, which FR-074b forbids.
