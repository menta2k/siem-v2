# Contract: Backend → wirefilter Sidecar

**Service**: `wirefilter-svc` (Rust) | **Transport**: HTTP/JSON over the internal network
**Why a separate process**: R1 — no viable Go binding, moving C ABI, and FR-073d requires evaluation
isolated from collection.

## `POST /evaluate`

```jsonc
{
  "expression": "http.request.uri.path contains \"/admin\" and ip.src in {203.0.113.0/24}",
  "requests": [
    {
      "ref": "evt_01HX...",
      "fields": {
        "http.request.uri.path":   "/admin/login",
        "http.request.method":     "POST",
        "http.host":               "example.com",
        "ip.src":                  "203.0.113.9",
        "http.user_agent":         "curl/8.0",
        "http.request.uri.query":  "next=/dashboard"
      }
    }
  ]
}
```

**Response**

```jsonc
{
  "expression_valid": true,
  "parse_error": null,
  "scheme_version": "cf-scheme-v1",
  "engine_version": "wirefilter-0.7.0",
  "results": [
    {
      "ref": "evt_01HX...",
      "matched": true,
      "caveats": ["field http.request.body.raw not captured; predicates on it evaluated as unset"]
    }
  ]
}
```

## `GET /health` → `{"status":"ok","engine_version":"...","scheme_version":"..."}`

## Semantics

- **Stateless.** No storage, no cross-call state. Determinism is a function of expression + fields only
  (FR-033).
- **The scheme is ours.** wirefilter defines *no* fields — the scheme is entirely embedder-defined (R1).
  `wirefilter-svc` declares a scheme mirroring the documented Cloudflare field catalogue.
  `scheme_version` is recorded on every Evaluation Run so results stay interpretable after the scheme
  grows. **V8 — scheme coverage vs the CF field reference is unverified.**
- **Unset fields are caveats, not errors.** A predicate over a field the capture lacks yields a caveat,
  never a silent false — this is what feeds FR-035's "result may differ from production" warning.
- **Fidelity limit, surfaced not hidden (FR-073b).** This evaluates a rule *expression*; it does not
  reproduce Cloudflare's full product evaluation (managed rulesets, execution order, skip rules). The API
  response and the UI must say so.
- **Failure is degraded, not fatal.** The Go client treats the sidecar as optional: if unconfigured or
  unreachable, CF evaluation reports unavailable while OWASP evaluation and everything else continues.
- **Bounded**: request timeout and a max `requests[]` batch size; resource-limited container.
- **Not client-reachable**: internal network only, reached solely by `apiserver`.
