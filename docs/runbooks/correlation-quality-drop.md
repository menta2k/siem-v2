# Runbook: Exact-join rate has fallen

**Detection**: `pipeline.correlation_quality_drop` · **Severity**: high

## What fired

Fewer than 80% of flows are joining on a shared identifier; the rest fell back to attribute-and-time
heuristics.

## Why this is easy to miss

**Nothing looks broken.** Flows still form, searches still return results, dashboards still populate.
What changed is confidence: heuristic joins can put the wrong records together, and a flow that
looks complete may be assembled from two different requests.

## First check

Which identifier stopped arriving:

```bash
curl -s -H "Authorization: Bearer <identity>" http://<api>/api/v1/stats/verdicts \
  | jq '{exact_join_ratio, bridged_flows, total_flows}'
```

Then open any recent flow and look at the per-event `correlation_key_source`.

## Causes, in order of likelihood

1. **`ParentRayID` no longer captured** on the Logpush job. This breaks the DataDome layer
   specifically: its verdict is keyed on the parent ray and has nothing else to attach to.
2. **nginx stopped logging `$http_cf_ray`** — often a `log_format` change, or a pre-processor that
   strips or rewrites the header.
3. **F5 iRule removed or not applied** to the virtual server after a config change.
4. **A new Worker route** whose subrequests were not anticipated — check whether the affected flows
   share a hostname.

## Confirming a fix

The ratio should recover within one correlation window. It will not backfill: flows already written
keep the tier they were joined at, which is correct — rewriting history to look better would be the
wrong repair.
