# Runbook: Processing stage produces no output

**Detection**: `pipeline.stage_zero_output` · **Severity**: critical

## What fired

A stage is receiving input and producing nothing. **Every process is still running and every
liveness probe still passes.** This is the condition liveness checks cannot see, and the reason the
constitution requires health checks to assert meaningful output rather than mere aliveness.

Zero input *and* zero output is an idle pipeline, not this. The alert does not fire on idle.

## Impact

Records are still arriving and still durably buffered — **nothing is being lost**. They are simply
not becoming flows. Recovery replays them; the damage is latency, not data.

## First check

Compare input and output rates over the last five minutes:

```bash
curl -s -H "Authorization: Bearer <identity>" http://<api>/api/v1/health/collection \
  | jq '.stages[] | {stage, state, input_rate, output_rate, backlog_depth}'
```

## By stage

**correlate** — the most common. Look for an unbounded in-flight count: flows opening and never
closing means the late-arrival window is not elapsing, or correlation state was lost and every flow
is waiting for records that already arrived.

```bash
journalctl -u siem-logproc -n 100 | grep -E "flows stored|in_flight"
```

**normalize** — usually a parser panicking on a shape it has never seen. Check the dead-letter rate;
if it spiked at the same moment, this is really a parse-failure incident.

**store** — VictoriaLogs unreachable or out of disk. Ingest continues buffering; check disk first.

## Recovery

1. Restart the affected service. Correlation state is persisted, so in-progress flows resume rather
   than resetting.
2. If the backlog is large, let it drain before concluding anything — throughput recovers before
   latency does.
3. If restarting does not clear it, replay from the buffer once the cause is fixed:

```bash
# Dry run first: it reports what WOULD be reprocessed without writing.
siem-logproc replay --provider cloudflare --from <ts> --to <ts> --dry-run
```
