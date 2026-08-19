# Runbooks

One per alert condition. Every built-in detection carries a `recommended_first_check`, and these
expand on it.

The ordering principle throughout: **establish what the system can still see before diagnosing what
it is telling you.** A silent source and clean traffic look identical on a dashboard.

| Alert | Runbook |
|---|---|
| `pipeline.source_silence` | [source-silence.md](./source-silence.md) |
| `pipeline.stage_zero_output` | [stage-zero-output.md](./stage-zero-output.md) |
| `pipeline.parse_failure_spike` | [parse-failure-spike.md](./parse-failure-spike.md) |
| `pipeline.correlation_quality_drop` | [correlation-quality-drop.md](./correlation-quality-drop.md) |
