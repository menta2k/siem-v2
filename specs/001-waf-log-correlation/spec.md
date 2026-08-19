# Feature Specification: Multi-Provider WAF Log Correlation & Request Flow Analysis

**Feature Branch**: `001-waf-log-correlation`

**Created**: 2026-08-18

**Status**: Ready for Planning

**Input**: User description: "I am building SIEM like log collection and analyze system. The idea is to collect logs from Cloudflare Datadome F5 ASM nginx and to reconstruct the request flow. Logs may come in different order from the providers but the end timeline and order should be reconstructed. In addition to that to analyze the verdict and the reason for the action. The system should be able to test the request vs CF rule or OWASP engine. The system must have strong security and Log retention and alerting. The system must be able to handle about 1500-2000 requests per second from each provider. The system must have backend service (log processor) and a frontend service."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Reconstruct a single request's journey across all providers (Priority: P1)

A security analyst investigating a customer complaint or a suspected attack needs to see what happened to one specific HTTP request as it passed through the edge and application stack. Today the analyst must open four separate consoles (Cloudflare, DataDome, F5 ASM, nginx), search each one with a different query language and a different timestamp format, and mentally stitch the results together — a process that takes 15–30 minutes per request and often fails because one provider's record cannot be matched to the others.

The system collects records from all four providers, joins the records that belong to the same request, and presents a single ordered timeline: which layer saw the request first, what each layer decided, and where the request stopped or completed. The timeline is correct even though the four providers deliver their records at different times, in different orders, with different clocks, and with different delays.

**Why this priority**: This is the core value of the system and the foundation every other story builds on. Without a correct correlated timeline, verdict analysis, rule testing, and alerting have nothing to operate on. Delivered alone it already replaces the manual four-console stitching workflow.

**Independent Test**: Feed a recorded set of provider records for a known set of requests, delivered deliberately out of order and with delays, into the collection interface. Verify the system produces one timeline per request with the layers in the correct causal order, and that the reconstructed order matches the known ground truth for 100% of the recorded requests.

**Acceptance Scenarios**:

1. **Given** a request that traversed Cloudflare, DataDome, F5 ASM, and nginx, **When** all four provider records have been received, **Then** the analyst sees a single request flow showing all four layers in causal order with each layer's timestamp, decision, and latency contribution.
2. **Given** the nginx record for a request arrives before the Cloudflare record for the same request, **When** the analyst views the request flow, **Then** the layers are still ordered by their true position in the request path, not by arrival order.
3. **Given** a provider's record arrives 10 minutes after the other three, **When** it is received, **Then** the existing request flow is updated in place to include it and the analyst is not shown two separate flows for the same request.
4. **Given** two providers report timestamps that differ by several seconds because of clock skew, **When** the flow is reconstructed, **Then** the ordering reflects the known request path rather than the raw timestamps, and the skew is visible to the analyst as a data-quality note.
5. **Given** one provider never produces a record for a request that the other providers saw, **When** the analyst views the flow, **Then** the flow is shown as partial, with the missing layer explicitly marked as "no record" rather than silently omitted.
6. **Given** a provider redelivers a record the system already has, **When** it is processed, **Then** the request flow is unchanged and no duplicate layer appears.

---

### User Story 2 - Understand the verdict and why the action was taken (Priority: P2)

An analyst looking at a blocked or challenged request needs to know which layer took the action, what the action was (allowed, challenged, rate-limited, blocked, logged-only), and the specific reason — which rule, which signal, which score, which threshold. Each provider expresses this differently: Cloudflare names a rule and an action, DataDome returns a bot score and a reason code, F5 ASM lists violations and attack types, nginx records the resulting status code. The analyst needs these expressed in one common vocabulary so blocked traffic can be reasoned about and false positives can be identified quickly.

**Why this priority**: This is what turns a timeline into an explanation. It is the first thing an analyst asks after "what happened" and it drives the false-positive triage that consumes most WAF operations time. It depends on Story 1 but delivers standalone value once flows exist.

**Independent Test**: Load correlated flows containing known verdicts from each provider and verify that each provider-specific decision is mapped to the correct normalized action and carries the originating rule, signal, or score, with the provider's raw reason still available for inspection.

**Acceptance Scenarios**:

1. **Given** a request blocked by an F5 ASM signature, **When** the analyst opens the flow, **Then** the verdict shows the blocking layer, the normalized action, the violated signature, the attack type, and the matched portion of the request.
2. **Given** a request challenged by Cloudflare and subsequently allowed, **When** the analyst opens the flow, **Then** both decisions appear in order with the challenge outcome, and the final effective outcome of the request is stated unambiguously.
3. **Given** a request scored by DataDome below the blocking threshold, **When** the analyst opens the flow, **Then** the score, the threshold in force, and the contributing signals are shown even though no blocking action was taken.
4. **Given** two layers each took an action on the same request, **When** the analyst views the verdict summary, **Then** the system identifies which layer terminated the request and which actions were advisory or superseded.
5. **Given** a provider emits a reason code the system does not recognize, **When** the flow is displayed, **Then** the code is surfaced verbatim and flagged as unmapped rather than being dropped or misclassified.

---

### User Story 3 - Test a request against rule logic to confirm or refute a verdict (Priority: P3)

A security engineer handling a suspected false positive, or validating a proposed rule change, needs to re-evaluate a captured request against rule logic without waiting for the traffic to happen again in production. They select a captured request from a flow and evaluate it against Cloudflare rule expressions or against an OWASP Core Rule Set evaluation, and see which rules match, at what paranoia or sensitivity level, and what action would result. They can then adjust the rule or the request and re-run to compare outcomes.

**Why this priority**: It converts the system from a diagnostic tool into a decision tool — engineers can validate rule changes against real traffic before deploying them. It is high value but depends on captured request detail from Stories 1 and 2, and the system remains useful without it.

**Independent Test**: Take a captured request known to trigger a specific rule, run the evaluation, and verify the system reports that rule as matched with the expected action; then take a benign request and verify no match is reported. Both cases must be reproducible on repeat runs.

**Acceptance Scenarios**:

1. **Given** a captured request that was blocked in production, **When** the engineer evaluates it against the OWASP Core Rule Set, **Then** the system reports every matching rule, the anomaly score, the effective threshold, and whether that score would block at the configured paranoia level.
2. **Given** a captured request and a Cloudflare rule expression, **When** the engineer evaluates the request against that expression, **Then** the system reports whether the expression matches and which fields caused the result.
3. **Given** an engineer modifies the rule and re-runs the evaluation on the same request, **When** the run completes, **Then** the system shows a side-by-side comparison of the previous and new outcome.
4. **Given** the same request and the same rule version, **When** the evaluation is run repeatedly, **Then** the result is identical every time.
5. **Given** an evaluation run, **When** it completes, **Then** the run is recorded with the request identifier, the rule set and version used, the parameters, the operator, and the outcome, and is retrievable later.
6. **Given** a request whose body or headers were truncated or redacted at capture, **When** an evaluation is attempted, **Then** the system states which fields are unavailable and that the result may differ from the production verdict, rather than silently evaluating incomplete input.

---

### User Story 4 - Be alerted when something is wrong, in the traffic or in the pipeline (Priority: P4)

A security operations engineer must be told, without watching a screen, when attack conditions appear in the traffic (a spike in blocks, a single source triggering many rules, a rule that suddenly starts blocking legitimate traffic) and equally when the observability itself has failed (a provider has stopped sending logs, the parse failure rate has jumped, the correlation stage has stopped producing flows, the backlog is growing). Alerts must be routed to the operator's existing channels and must be actionable — stating what fired, what evidence caused it, and what to check first.

**Why this priority**: Alerting is what makes the system operate unattended, and pipeline self-alerting is a non-negotiable constitutional requirement. It is placed after the analysis stories because it needs something meaningful to alert on, but it is required before production use.

**Independent Test**: Drive synthetic conditions — stop one provider feed, inject malformed records, inject a burst of blocks from one source — and verify that each condition raises the expected alert within its stated detection window, and that a healthy baseline raises no alerts.

**Acceptance Scenarios**:

1. **Given** a provider that normally delivers continuously, **When** it delivers nothing for longer than its configured expected cadence, **Then** a source-silence alert fires identifying the provider and the time of its last record.
2. **Given** normal traffic, **When** blocked-request volume from a single source address exceeds its configured threshold, **Then** an alert fires containing the source, the rules involved, and links to representative request flows.
3. **Given** records still arriving, **When** the correlation stage produces zero flows for longer than its configured window, **Then** an operational alert fires even though every service process is still running.
4. **Given** a rule that normally blocks rarely, **When** its block rate rises sharply against its own baseline, **Then** a possible-false-positive alert fires with sample flows attached.
5. **Given** an alert has fired, **When** the operator opens it, **Then** it names the detection that fired, its version, the contributing evidence, and the recommended first check.
6. **Given** the same underlying condition persists, **When** it continues, **Then** the operator receives a grouped or suppressed notification rather than one notification per matching event.

---

### User Story 5 - Search, retain, and produce evidence over the retention window (Priority: P5)

An analyst or auditor needs to search across all collected traffic by attributes such as source address, host, path, verdict, rule, country, user agent, or time range; to open any matching request's full flow; and to export a defensible evidence package for an incident report or an audit request. Data must remain available for the full retention period, must be removed reliably when the period expires, and must be preservable beyond it when a legal hold applies.

**Why this priority**: Search and retention are what make the collected data usable beyond the current shift and are required for compliance, but the system delivers analytical value before the full retention and export capability is complete.

**Independent Test**: Load a known corpus spanning the retention window, run searches with known expected result sets, verify completeness and result timing; then advance past an expiry boundary and verify expired data is gone while held data is retained.

**Acceptance Scenarios**:

1. **Given** a populated retention window, **When** the analyst searches by source address and time range, **Then** matching request flows are returned completely and within the stated search time target.
2. **Given** a request flow, **When** the analyst exports it as evidence, **Then** the export contains the normalized flow, every contributing provider record in its original form, and a record of who exported it and when.
3. **Given** data older than the configured retention period, **When** the retention process runs, **Then** that data is removed from all tiers and the removal is recorded in the audit trail.
4. **Given** a legal hold is placed on a set of data, **When** its retention period expires, **Then** the held data is preserved and the attempted expiry is recorded.
5. **Given** the analyst searches a period that has aged into cold storage, **When** the search runs, **Then** results are still returned, with the longer expected retrieval time communicated before the search begins.

---

### User Story 6 - Control who can see and do what (Priority: P6)

An administrator must be able to grant analysts access only to the data and actions appropriate to their role — for example, allowing an analyst to view flows but not to export raw payloads, or restricting a team to the properties it owns. Every access to log data, every export, and every configuration change must be recorded in a trail the operators themselves cannot alter.

**Why this priority**: Required before any real production data is loaded, but the analytical capability can be developed and validated against sanitized data first.

**Independent Test**: Define roles with differing permissions, then attempt each permitted and each forbidden action as each role and verify the outcomes, confirming that forbidden data never appears in any response and that every attempt is present in the audit trail.

**Acceptance Scenarios**:

1. **Given** a user restricted to a subset of monitored properties, **When** they run a search that would otherwise match other properties, **Then** only their permitted results are returned and the restriction is enforced before results are produced, not by hiding them afterwards.
2. **Given** a user without export permission, **When** they attempt an export, **Then** the attempt is refused with a clear message and is recorded in the audit trail.
3. **Given** any user views a request flow containing classified sensitive fields, **When** the flow is displayed, **Then** those fields appear masked unless the user holds the specific permission to view them.
4. **Given** an administrator changes a retention policy or a detection rule, **When** the change is saved, **Then** the previous value, the new value, the actor, and the time are recorded immutably.

---

### Edge Cases

- **No shared identifier**: A provider record carries no identifier that can be joined to the others. The system must still store, normalize, and make the record searchable as an uncorrelated observation rather than discarding it or attaching it to the wrong flow.
- **Ambiguous match**: Two candidate flows match a record equally well. The system must not guess silently; it must record the ambiguity and expose it as a data-quality signal.
- **Very late arrival**: A record arrives after its flow has been finalized and aged into a colder tier. The flow must be amendable, and the amendment must be visible as such.
- **Never-completed flow**: Some provider records for a request never arrive. The flow must be closed as partial after a bounded wait rather than held open indefinitely consuming state.
- **Clock skew and wrong clocks**: A provider's clock is minutes off, or a record carries a timestamp in the future or far past. Ordering must not be corrupted, and the anomaly must be flagged rather than silently corrected.
- **Sustained overload**: A provider sends far above its expected 1500–2000 records per second, or all four burst simultaneously. Collection must continue without loss; latency may degrade and must be visible.
- **Provider outage then flood**: A provider is silent for an hour then delivers the entire backlog at once. The system must absorb it, order it correctly, and not mistake the backlog for a traffic spike in security alerting.
- **Malformed or changed format**: A provider changes its log format without notice. Affected records must be captured for later reprocessing rather than dropped, and the change must raise an alert.
- **Duplicate delivery**: The same record is delivered more than once. It must not appear twice in a flow, in counts, or in alert evidence.
- **Oversized records**: A record contains a very large body or header set. It must be handled with a stated size limit, with truncation recorded explicitly so downstream evaluation knows the input was incomplete.
- **Sensitive data in payloads**: Captured requests contain credentials, tokens, or personal data. These must be classified and masked or tokenized before storage, and their presence must not block correlation.
- **Retention expiry during an investigation**: Data referenced by an open investigation reaches its expiry. The system must apply the hold mechanism rather than silently deleting evidence.
- **Downstream unavailability**: Storage or search is unavailable. Collection must continue into the durable buffer and drain on recovery, with no loss.
- **Restart mid-correlation**: The processor restarts while flows are in progress. Correlation must resume from persisted state, not restart empty and lose partial flows.
- **Evaluation against unavailable data**: A rule evaluation is requested for a request whose payload was masked, truncated, or already expired. The system must state this rather than produce a misleading result.

## Requirements *(mandatory)*

### Functional Requirements

#### Collection & Ingestion

- **FR-001**: System MUST collect log records from Cloudflare, DataDome, F5 ASM, and nginx, supporting each provider's available delivery mechanism — **push** (the provider POSTs to the system) and **pull** (the system polls the provider's export API) — without requiring changes to the providers' own configuration beyond enabling log delivery.
- **FR-001a**: System MUST support pull-mode collection by polling a provider's log export API on a schedule, tracking a per-source watermark so that a restart resumes where it stopped rather than re-reading or skipping a window.
- **FR-001b**: System MUST reject as unusable any provider feed that carries no per-request identifier and no per-request attributes, and MUST NOT present attack-summary or aggregate notifications as a collection source.
- **FR-002**: System MUST accept a sustained rate of 1,500–2,000 records per second from each provider independently, and a combined sustained rate of at least 8,000 records per second across all four.
- **FR-003**: System MUST absorb short bursts of at least three times the sustained rate for at least five minutes without loss of records.
- **FR-004**: System MUST write every received record to durable, replayable storage before any parsing, correlation, or indexing takes place.
- **FR-005**: System MUST NOT lose records when any downstream stage is unavailable; such conditions may increase latency but MUST NOT reduce durability.
- **FR-006**: System MUST count, record, and alert on every discarded record; silent loss is prohibited.
- **FR-007**: System MUST process redelivered records idempotently so that at-least-once delivery from providers produces exactly one occurrence in flows, counts, and search results.
- **FR-008**: System MUST support adding a new log source without code changes to existing sources, and MUST treat a source as onboarded only once it has a parser with test fixtures, a declared expected delivery cadence, a retention and data-classification decision, and a stated detection posture.

#### Normalization & Data Quality

- **FR-009**: System MUST normalize every record into a single documented common schema covering, at minimum, request identity, timing, client attributes, request attributes, the acting layer, the decision, and the reason for the decision.
- **FR-010**: System MUST retain each record's original unmodified content alongside its normalized form for the full retention period applicable to that record.
- **FR-011**: System MUST record both the time the event occurred at the provider and the time the system received it, as distinct values, in a single timezone-explicit format.
- **FR-012**: System MUST route records it cannot parse to a dead-letter store containing the original content and the parse failure reason, and MUST make dead-lettered records reprocessable after a parser is corrected.
- **FR-013**: System MUST detect and flag implausible timestamps and inter-provider clock skew, and MUST NOT silently alter reported times.
- **FR-014**: System MUST surface provider values it does not recognize (unmapped verdicts, reason codes, rule identifiers) verbatim and marked as unmapped, rather than discarding them or mapping them to an approximate value.
- **FR-015**: System MUST classify fields that may carry credentials, tokens, personal data, or otherwise regulated data, and MUST mask or tokenize them according to policy before storage.

#### Correlation & Flow Reconstruction

- **FR-016**: System MUST join records originating from the same HTTP request across all providers into a single request flow.
- **FR-017**: System MUST reconstruct the causal order of layers within a flow correctly regardless of the order or timing in which the provider records arrive.
- **FR-018**: System MUST update an existing flow in place when a late record for that flow arrives within the configured late-arrival window, rather than creating a second flow.
- **FR-019**: System MUST close a flow as partial after a bounded wait when expected records never arrive, and MUST mark each absent layer explicitly as having produced no record.
- **FR-020**: System MUST retain records that cannot be joined to any flow as searchable uncorrelated observations, and MUST report the proportion of records that remain uncorrelated as a data-quality metric.
- **FR-021**: System MUST NOT attach a record to a flow when the match is ambiguous; it MUST record the ambiguity and expose it as a data-quality signal.
- **FR-022**: System MUST produce identical flows when the same records are processed again, regardless of the order of reprocessing.
- **FR-023**: System MUST persist correlation state so that a restart resumes in-progress flows rather than discarding them.
- **FR-024**: System MUST apply a stated policy for out-of-order and late-arriving records, and MUST make the effective window and policy visible to operators.

#### Verdict & Reason Analysis

- **FR-025**: System MUST express each layer's decision in a common set of normalized actions covering at least: allowed, logged only, rate limited, challenged, challenge passed, challenge failed, and blocked.
- **FR-026**: System MUST record, for each decision, the reason as reported by that provider — including rule or signature identity, attack or violation category, score, and threshold where the provider supplies them.
- **FR-027**: System MUST determine and present the single effective outcome of each request flow, identifying which layer terminated the request and which decisions were advisory or superseded.
- **FR-028**: System MUST allow an analyst to see the provider's raw decision content alongside the normalized interpretation.
- **FR-029**: System MUST compute per-flow timing attribution showing the time contributed at each layer where the underlying records permit it.

#### Rule Evaluation & Testing

- **FR-030**: System MUST allow an operator to evaluate a captured request against OWASP Core Rule Set logic and report every matching rule, the resulting anomaly score, the threshold applied, and the action that score would produce.
- **FR-031**: System MUST allow an operator to evaluate a captured request against a Cloudflare rule expression and report whether it matches and which request fields determined the result.
- **FR-032**: System MUST allow an operator to modify the request or the rule and re-run an evaluation, presenting the outcomes side by side.
- **FR-033**: System MUST produce identical evaluation results for identical inputs and identical rule versions.
- **FR-034**: System MUST record every evaluation run with the request identifier, the rule set and version, the parameters used, the operator, the time, and the outcome, and MUST make past runs retrievable.
- **FR-035**: System MUST state explicitly when a captured request is incomplete — truncated, masked, or partially expired — and MUST warn that the evaluation result may differ from the production verdict.
- **FR-036**: System MUST run evaluations in isolation such that an evaluation cannot affect production traffic, collection, or the stored record of the original request.

#### Search, Retention & Evidence

- **FR-037**: Users MUST be able to search flows and records by time range, source address, host, path, method, status, normalized action, acting layer, rule or signature identity, country, user agent, and provider.
- **FR-038**: System MUST make newly collected records searchable within a stated freshness target.
- **FR-039**: System MUST support configurable retention per data category and per storage tier, with defined defaults, and MUST enforce expiry across every tier including backups and archives.
- **FR-040**: System MUST support legal hold that preserves specified data beyond its normal expiry, and MUST record every hold, release, and prevented expiry.
- **FR-041**: Users MUST be able to export a request flow as an evidence package containing the normalized flow, every contributing original record, and the export's own provenance.
- **FR-042**: System MUST record every export in the audit trail with the actor, the scope of the data, and the time.

#### Alerting & Detection

- **FR-043**: System MUST evaluate configurable detection rules against collected traffic and raise alerts when they match.
- **FR-044**: System MUST raise an alert when any source delivers no records for longer than its declared expected cadence.
- **FR-045**: System MUST raise an alert when any processing stage produces no output while continuing to receive input.
- **FR-046**: System MUST raise an alert when the parse failure rate, the uncorrelated record rate, the processing backlog, or the end-to-end latency exceeds configured thresholds.
- **FR-047**: System MUST raise an alert when a rule's block rate deviates sharply from its own established baseline, as a candidate false positive.
- **FR-048**: System MUST include in every alert the detection that fired, its version, the contributing evidence, and a link to the relevant request flows.
- **FR-049**: System MUST group or suppress repeated notifications for a persisting condition rather than notifying per matching event.
- **FR-050**: System MUST deliver alerts to configurable destinations and MUST alert operators when a delivery destination itself is failing.
- **FR-051**: System MUST store detection rules under version control with test fixtures, and MUST require that a rule pass a positive and a negative fixture before it can be activated.

#### Security, Access & Auditing

- **FR-052**: System MUST authenticate every user and service before granting access to any log data or administrative function.
- **FR-053**: System MUST authorize every data access against the requester's role and permitted scope, enforced before results are produced rather than by filtering results afterwards.
- **FR-054**: System MUST encrypt all data in transit between collectors, processing, storage, and the frontend, and MUST encrypt all stored data at rest.
- **FR-055**: System MUST record every access to log data, every export, every evaluation run, and every configuration change in an append-only audit trail that operators cannot alter or delete.
- **FR-056**: System MUST mask classified sensitive fields in all views and exports unless the requester holds the specific permission to see them, and MUST record each such privileged view.
- **FR-057**: System MUST obtain all credentials and provider API keys from a secret store or the environment, never from source or repository configuration files.
- **FR-058**: System MUST validate every externally supplied input — provider payloads, user queries, rule definitions, configuration — at the system boundary and reject invalid input with a clear message that discloses no internal detail.
- **FR-059**: System MUST rate limit all externally reachable interfaces.

#### Operations & Observability

- **FR-060**: System MUST expose, per source and per processing stage, the records received and emitted, the parse failure rate, the processing latency, the buffer depth, the flows completed, and the alerts produced.
- **FR-061**: System MUST verify its own correctness through health checks that assert meaningful output — flows produced, alerts delivered — rather than only that processes are running.
- **FR-062**: System MUST attempt bounded automatic recovery for stages in a known-recoverable degraded condition, and MUST record every recovery attempt with its cause and outcome.
- **FR-063**: System MUST allow an operator to replay records from the durable buffer or the archive to rebuild flows after a parser or correlation fix.
- **FR-064**: System MUST track ingest volume and storage growth per source and alert on deviation from the established baseline.
- **FR-065**: System MUST continue collection while analysis, search, or frontend components are unavailable or under maintenance.

#### Frontend

- **FR-066**: Users MUST be able to view a request flow as an ordered visual timeline showing each layer, its decision, its reason, and its timing contribution.
- **FR-067**: Users MUST be able to move from a search result to the full flow, and from a flow to any contributing original record, without leaving the interface.
- **FR-068**: Users MUST be able to view aggregate traffic and verdict trends over a selected period, broken down by provider, action, rule, and source.
- **FR-069**: Users MUST be able to initiate a rule evaluation from a request flow and view its result in context.
- **FR-070**: Frontend MUST clearly indicate data-quality conditions — partial flows, unmapped values, clock skew, truncated payloads, masked fields — wherever they affect what is displayed.
- **FR-071**: Frontend MUST indicate current collection health, including any source currently silent or degraded, so a user never reads an incomplete view as a complete one.

#### Correlation Strategy (resolved)

- **FR-072**: System MUST correlate provider records using a tiered strategy: an exact join on a shared request identifier wherever one is present, falling back to a deterministic attribute-and-time heuristic for providers that do not carry it.
- **FR-072a**: System MUST treat a propagated edge request identifier (Cloudflare Ray ID, or an equivalent trace identifier injected at the outermost layer and forwarded downstream) as the primary correlation key, and MUST use it whenever the record carries it.
- **FR-072b**: System MUST support a heuristic fallback join for records lacking the primary key, matching on the combination of client address, host, request method, request path, and event time within a bounded proximity window, plus any provider-specific identifier that can be cross-referenced.
- **FR-072c**: System MUST assign every flow a correlation confidence reflecting which method joined it, MUST record the method used per contributing record, and MUST expose both to the analyst.
- **FR-072d**: System MUST NOT complete a heuristic join when more than one candidate matches within the window; such records MUST be recorded as ambiguous per FR-021 rather than attached to a best guess.
- **FR-072e**: System MUST report correlation quality — exact joins, heuristic joins, ambiguous, and uncorrelated — as ongoing metrics per source, so degradation in identifier propagation is detected as an operational condition.
- **FR-072f**: System MUST treat a record as carrying potentially **several** per-request identifiers, and MUST join records transitively through them: when one record carries two identifiers, records that each know only one of those identifiers belong to the same flow. This bridging MUST be exact-tier — it MUST NOT depend on timestamp proximity or clock agreement.
- **FR-072g**: System MUST derive a flow's correlation identity deterministically from its identifier set, so the same set of records always produces the same flow identity regardless of the order in which records arrived or were discovered.

#### Rule Evaluation Model (resolved)

- **FR-073**: System MUST evaluate OWASP Core Rule Set logic by executing the captured request against a real rule engine, producing an authoritative set of matched rules, anomaly score, and resulting action rather than an approximation inferred from stored verdicts.
- **FR-073a**: System MUST evaluate Cloudflare rules by interpreting the rule expression against the captured request's fields, reporting match or no-match and the fields that determined the result, without claiming to reproduce Cloudflare's full internal evaluation.
- **FR-073b**: System MUST state, for every evaluation result, which evaluation model produced it and what its known limits are, so an operator does not read an expression match as a guaranteed production outcome.
- **FR-073c**: System MUST pin and record the rule set version, paranoia or sensitivity level, and engine version used in every run, so that FR-033's repeatability holds across time.
- **FR-073d**: System MUST run engine evaluation in an isolated environment with bounded execution time and resources, such that a malformed or hostile captured request cannot affect collection, storage, or other evaluations.
- **FR-073e**: Simulation of F5 ASM and DataDome rule logic is out of scope; their verdicts are normalized and analyzed but not re-executed.

#### Tenancy & Access Scope (resolved)

- **FR-074**: System MUST carry an explicit tenant identity on every stored record, flow, evaluation run, alert, and audit entry, and MUST enforce tenant scope server-side at the query layer, while operating initially with a single configured tenant.
- **FR-074a**: System MUST authorize access as the combination of tenant scope, role, and permitted property scope, evaluated before results are produced.
- **FR-074b**: System MUST NOT allow a query, alert, export, or evaluation to return or reference data outside the requesting principal's tenant, and MUST make cross-tenant access impossible to express rather than merely refused after the fact.
- **FR-074c**: Adding a second tenant MUST NOT require changes to the storage schema, the query authorization model, or the alerting pipeline.

### Key Entities

- **Log Source**: A configured provider feed (Cloudflare, DataDome, F5 ASM, nginx, or a future addition). Carries its delivery mechanism, expected cadence, data classification, retention policy, parser version, and current health.
- **Raw Record**: One log entry exactly as delivered by a provider, with its receipt time, source, and delivery batch identity. Immutable and retained for the record's full retention period.
- **Normalized Event**: The common-schema interpretation of one raw record — request identity, event time and receipt time, client attributes, request attributes, acting layer, decision, reason, and data-quality flags. Linked to its raw record and its parser version.
- **Request Flow**: The correlated set of normalized events belonging to one HTTP request, ordered causally, with its completeness state (complete, partial, ambiguous), effective outcome, per-layer timing, and correlation confidence.
- **Verdict**: A single layer's decision within a flow — normalized action, terminating or advisory, provider reason, rule or signature identity, category, score and threshold where present, and the unmodified provider decision content.
- **Rule Reference**: The identity and version of a provider rule, signature, or OWASP rule as observed in verdicts and used in evaluations, along with its observed block-rate baseline.
- **Evaluation Run**: A recorded test of a captured request against a rule set — the request, the rule set and version, parameters such as paranoia or sensitivity level, the operator, the time, matched rules, resulting score and action, and any comparison to a prior run.
- **Detection**: A versioned rule evaluated against collected traffic or pipeline health, with its condition, severity, expected response, and test fixtures.
- **Alert**: An instance of a detection firing — the detection and version, time, severity, contributing evidence, linked flows, delivery state, and acknowledgement state.
- **Retention Policy**: The rule governing how long a data category is kept in each storage tier, its expiry behaviour, and its interaction with legal hold.
- **Legal Hold**: A preservation instruction over a defined set of data, with its scope, reason, actor, and lifecycle.
- **Access Principal**: A user or service with an identity, role, permitted data scope, and permitted actions.
- **Audit Record**: An immutable entry describing an access, export, evaluation, or configuration change — actor, action, scope, time, and outcome.
- **Dead-Letter Record**: A record that could not be parsed or normalized — original content, source, failure reason, parser version, and reprocessing state.
- **Pipeline Health Signal**: The per-source and per-stage measurements of throughput, failure rate, latency, backlog, and output, against which silence and zero-output conditions are judged.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An analyst can determine what happened to a specific request — every layer it passed, every decision, and the reason for the final outcome — in under 2 minutes, replacing a manual process that currently takes 15–30 minutes across four consoles.
- **SC-002**: At least 99% of requests that were seen by more than one provider are reconstructed into a single correlated flow.
- **SC-003**: Reconstructed layer ordering matches known ground truth for 100% of requests in the validation corpus, including cases delivered out of order and with clock skew.
- **SC-004**: The system sustains 2,000 records per second from each of the four providers concurrently, for at least 24 hours, with zero record loss.
- **SC-005**: The system absorbs a burst of three times the sustained rate for 5 minutes with zero record loss.
- **SC-006**: 95% of records are searchable within 30 seconds of the provider delivering them, under sustained load.
- **SC-007**: 95% of correlated flows are complete and viewable within 60 seconds of the last contributing record being delivered.
- **SC-008**: 95% of searches over the hot retention window return complete results in under 5 seconds.
- **SC-009**: A provider that stops delivering is detected and alerted within 5 minutes of its expected cadence lapsing.
- **SC-010**: A processing stage that stops producing output while still receiving input is detected and alerted within 5 minutes.
- **SC-011**: Fewer than 0.1% of received records fail to parse, and 100% of those that fail are recoverable from the dead-letter store and can be reprocessed successfully after a parser fix.
- **SC-012**: No records are lost across a full restart of every processing component under sustained load.
- **SC-013**: 100% of collected records remain retrievable for their full configured retention period, and 100% of data past expiry is verifiably removed from every tier.
- **SC-014**: A security engineer can determine whether a rule change would have blocked or allowed a specific past request in under 5 minutes, without deploying anything to production.
- **SC-015**: Repeated evaluation of the same request against the same rule version produces an identical result in 100% of runs.
- **SC-016**: 100% of alerts include the evidence and the linked request flows needed to begin investigation without a separate query.
- **SC-017**: 100% of accesses to log data, exports, evaluation runs, and configuration changes appear in the audit trail, and no operator role can alter or remove an audit entry.
- **SC-018**: 100% of attempts to access data outside a principal's permitted scope are refused, and no out-of-scope data appears in any response.
- **SC-019**: Classified sensitive fields are masked in 100% of views and exports for principals lacking the specific permission to see them.
- **SC-020**: A new log source can be onboarded — parser, fixtures, cadence, classification, retention — in under one working day, with no change to existing sources.
- **SC-021**: An analyst can produce an evidence export for an incident in under 5 minutes, containing the normalized flow, all original records, and its own provenance.
- **SC-022**: Collection continues with zero loss during planned maintenance of the analysis, search, and frontend components.
- **SC-024**: At least 95% of correlated flows are joined by exact request identifier rather than heuristic fallback once identifier propagation is fully enabled, and the exact-join proportion is visible to operators at all times.
- **SC-025**: Fewer than 0.5% of join attempts resolve as ambiguous, and 100% of ambiguous cases are surfaced rather than resolved by guessing.
- **SC-026**: An OWASP evaluation of a captured request completes in under 10 seconds and reports the same matched rules and score as the production engine for 100% of validation cases where the captured request is complete.
- **SC-027**: No query, export, alert, or evaluation returns data outside the requesting principal's tenant in 100% of tested attempts, including deliberately malformed and injected queries.
- **SC-023**: Every displayed view that is incomplete — partial flow, silent source, masked or truncated content — is labelled as such, so no user can mistake a partial view for a complete one.

## Assumptions

- **Providers in scope**: Cloudflare, DataDome, F5 ASM, and nginx are the initial sources. The architecture must accommodate further sources, but no others are in scope for this feature.
- **Mixed delivery modes**: Cloudflare pushes (Logpush); nginx and F5 ASM are delivered by a collection agent; DataDome is **pulled** from its log export API. DataDome's webhook is an attack-notification mechanism carrying no per-request identifier and is therefore not a viable source.
- **DataDome entitlement**: DataDome per-request log export is generally a Corporate/Enterprise plan feature. Without it DataDome cannot supply per-request events at all — this must be confirmed before the source is configured, not after.
- **DataDome export scope**: the DataDome export is assumed to include allowed traffic, not only blocked requests. A blocks-only export makes the cross-provider disagreement case ("DataDome allowed this, F5 blocked it") impossible to see, which is a primary purpose of the system.
- **Provider access**: The operator controls the four provider accounts sufficiently to enable and configure log delivery, and provider-side log delivery is already available or can be enabled.
- **Traffic profile**: 1,500–2,000 records per second per provider is the sustained expectation; approximately 8,000 records per second combined is the design target, with headroom for 3× bursts.
- **Common request path**: Requests generally traverse the layers in a consistent order (edge → bot management → application firewall → origin server), which is the basis for causal ordering; deviations are treated as data-quality conditions rather than the norm.
- **Retention defaults**: In the absence of a stated compliance mandate, the default is 30 days hot and searchable, 90 days warm, and 12 months in cold archive, configurable per data category. Raw records follow the same schedule as their normalized events.
- **Late-arrival window**: Records arriving up to 15 minutes after their flow's first record are correlated in place; flows are closed as partial after that, and later arrivals amend the closed flow.
- **Alert delivery**: Alerts are delivered to the operator's existing notification channels rather than requiring a new incident-management product.
- **Deployment**: The system is operated by the same organization whose traffic it observes, and runs in an environment that organization controls.
- **Backend and frontend separation**: The log processor and the frontend are separately deployable and separately scalable services, so that frontend maintenance never interrupts collection.
- **Sanitized data in development**: No production traffic is used in development or test environments unless sanitized; all committed test fixtures are sanitized and free of real credentials or personal data.
- **Rule sets**: OWASP Core Rule Set and Cloudflare rule expressions are the rule languages in scope for evaluation. F5 ASM and DataDome rule simulation are out of scope for this feature; their verdicts are analyzed but not re-executed.
- **Correlation identifier**: An edge-injected request identifier is assumed to be propagated to downstream layers where each provider permits it; the heuristic fallback exists because full propagation across all four providers cannot be assumed from day one. Enabling propagation is expected to raise exact-join coverage over time and is treated as an operational improvement, not a precondition for the system to function.
- **Evaluation fidelity**: OWASP evaluation is authoritative because a compatible engine can be executed locally; Cloudflare evaluation is expression-level because no equivalent engine is externally available. This asymmetry is deliberate and surfaced to users rather than hidden.
- **Tenancy**: The system serves one organization at launch, but tenant identity is modelled and enforced from the first release so that isolating additional organizations later is a configuration change rather than a rewrite.
- **Out of scope**: Blocking or otherwise acting on live traffic, pushing rule changes back to any provider, long-term behavioural user profiling, and automated incident response are all outside this feature. The system observes and explains; it does not enforce.
