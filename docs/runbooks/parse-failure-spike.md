# Runbook: Parse failure rate elevated

**Detection**: `pipeline.parse_failure_spike` · **Severity**: high

## What fired

More than 1% of a source's records failed to parse. The target is under 0.1%.

## What it usually means

A provider changed its log format without notice. This is the ordinary cause and it is recoverable:
**the original bytes are preserved**. Nothing is lost while this is unresolved — the records are in
the dead-letter store waiting for a corrected parser.

## First check

Read a sample and compare it to what the parser expects:

```bash
curl -s -H "Authorization: Bearer <identity>" \
  "http://<api>/api/v1/deadletters?provider=<provider>&limit=5" | jq '.records[].failure_reason'
```

The failure reason names the parser and version, so it is actionable without reproducing the error.

## Fixing

1. Add the real (sanitized) sample to `backend/test/fixtures/<provider>/`.
2. Write a failing test against it — the constitution requires the test first.
3. Correct the parser and bump its version.
4. Deploy, then reprocess:

```bash
siem-logproc replay-deadletters --provider <provider> --dry-run
siem-logproc replay-deadletters --provider <provider>
```

Records that still fail stay dead-lettered rather than being marked recovered, so a partial fix is
visible rather than silently leaving a gap.

> **Do not sanitize by deleting fields.** A fixture that omits the field which broke the parser
> cannot prove the parser is fixed. Replace values, keep the shape.
