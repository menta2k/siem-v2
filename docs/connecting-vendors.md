# Connecting Cloudflare, DataDome, F5 ASM and nginx

What each provider must be configured to send, and the specific mistakes that produce
a system which looks healthy while collecting nothing useful.

Every item here was established against **real records**, not documentation.

---

## The correlation model, first

Understanding this makes the rest obvious. When a Cloudflare Worker is in play, **one visitor
request produces several Cloudflare rows**:

```
visitor request                    ray = PARENT
├─ Worker fetch to origin          ray = A, ParentRayID = PARENT   → seen by nginx and F5 as A
└─ Worker call to DataDome         ray = B, ParentRayID = PARENT   → DataDome's verdict
```

- nginx and F5 see the **fetch's own ray (A)**.
- DataDome's verdict is keyed on the **parent ray**.
- The Cloudflare record carries **both A and PARENT**, which is what joins the two groups.

Correlation therefore needs nothing more than the ray ids — no time windows, no heuristics.
Everything below exists to make sure those ids actually arrive.

---

## Feeds and ingest tokens

Every provider delivers to a **feed**: one endpoint with one credential, created on the
**Feeds** page (requires source-management permission). The feed id is the last path
segment of the ingest URL and the token authenticates deliveries to exactly that path:

```
https://<ingest-host>/ingest/v1/<provider>/<feed-id>
```

### Token rules

- **The token is shown exactly once** — at creation or rotation. Only its SHA-256 is
  stored, so it cannot be recovered later, only rotated again. The dialog that shows it
  also shows the ready-to-paste provider configuration; copy both before dismissing.
- Its form is `<feed-id>.<secret>`. The id half must match the URL path, so a token
  leaked from one feed's configuration cannot be replayed against another feed.
- Send it as `Authorization: Bearer <token>`. The `?token=<token>` query parameter is
  the documented fallback for senders with no custom-header field — it works, but URLs
  are logged more readily than headers, so prefer the header wherever possible.

### Rotation

**Rotation takes effect immediately** — there is no grace period, deliberately: two live
credentials would leave no way to see which one a sender still uses. Deliveries with the
old token are rejected with 401 until the provider is reconfigured; providers retry
failed deliveries, so the switch loses nothing. Rotate from the Feeds page; reconfigure
the provider with the new token from the one-time dialog.

### Reading refusals

| Response | Means | Whose problem |
|---|---|---|
| `401` | wrong or rotated token, disabled feed, or provider/path mismatch | the sender's configuration |
| `503` | the credential store has not loaded (ingest just started, or its database was never reachable) | ours — senders back off and retry, nothing is lost |

The distinction matters: a 401 during our own outage would make well-behaved senders
drop batches or disable jobs.

### Propagation delay

Ingest serves credentials from a snapshot refreshed every **30 seconds**. A newly
created or rotated token, and an enable/disable, takes up to that long to apply. A
database outage keeps the last snapshot serving — ingest never blocks on the database.

> The pre-feed shared-secret routes (`/ingest/v1/cloudflare/logpush`,
> `/ingest/v1/vector/<provider>` with `SIEM_INGEST_SECRET`) still work for
> single-tenant and lab deployments, but new configurations should use feeds: per-feed
> tokens can be rotated individually, and a leaked credential exposes one feed, not all
> of them.

---

## Cloudflare

### Logpush job

Create a **cloudflare** feed on the Feeds page. Dataset `http_requests`, delivering to
the feed's URL with the feed token in a header. Cloudflare cannot set arbitrary headers
on a Logpush destination, so the header travels as a `header_`-prefixed, URL-encoded
query parameter — the one-time token dialog renders this exact string for copy-paste:

```
https://<ingest-host>/ingest/v1/cloudflare/<feed-id>?header_Authorization=Bearer%20<TOKEN>
```

Cloudflare validates a new destination with a `PUT` carrying `{"content":"..."}` before
it creates the job; the ingest endpoint answers it without storing anything. If job
creation fails immediately, the usual cause is a stale token after a rotation — the
validation probe is the first thing the new configuration sends.

**Pin the timestamp format explicitly:**

```json
"output_options": { "timestamp_format": "rfc3339" }
```

The API default is `unixnano` and the dashboard default is `rfc3339`. The parser accepts both,
but pinning it means a job recreated later cannot silently change the meaning of every timestamp.

### Fields that must be enabled

**Correlation** — without these nothing joins:
`RayID`, `ParentRayID`, `EdgeStartTimestamp`, `EdgeEndTimestamp`

**Request and client**:
`ClientIP`, `ClientRequestHost`, `ClientRequestURI`, `ClientRequestMethod`,
`ClientRequestUserAgent`, `ClientCountry`, `ClientASN`, `EdgeResponseStatus`

**Verdict**:
`SecurityAction`, `SecurityRuleID`, `SecurityRuleDescription`,
`SecurityActions`, `SecuritySources`, `SecurityRuleIDs`, `MatchedRules`

**Scores** — note these run the OPPOSITE way to a bot score: **1 means attack, 99 means clean**:
`WAFAttackScore`, `WAFSQLiAttackScore`, `WAFXSSAttackScore`, `WAFRCEAttackScore`,
`BotScore`, `BotScoreSrc`

**Required for the DataDome verdict**: `ResponseHeaders`

### The DataDome custom field

DataDome's decision arrives on the Worker's subrequest as a **response** header. Capture it:

```bash
curl -sS -X PUT \
  "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/rulesets/phases/http_log_custom_fields/entrypoint" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"rules":[{"action":"log_custom_field","expression":"true","action_parameters":{
        "response_fields":[{"name":"x-datadome-traffic-rule-response"}]}}]}'
```

**Three ways to get this wrong, all of which fail silently:**

| Mistake | Result |
|---|---|
| Capturing it as a **request** header | Nothing. The Worker sets it on the way *out*. |
| Using a **capitalised** header name | Accepted, logs nothing. |
| Setting it from the **dashboard** | The UI writes `request_fields` only. |

---

## DataDome

**There is nothing to configure on the DataDome side, and no separate feed.**

DataDome runs as a Cloudflare Worker that calls its protection API for every guarded request.
Cloudflare logs that call as an ordinary subrequest — a `POST` to `api-cloudflare.datadome.co` —
and that row **is** DataDome's verdict. Its `ParentRayID` attaches it to the request it judged.

DataDome's own log export is not used: it identifies requests by a private id carrying no Ray ID,
so its records cannot be joined to anything.

### Reading the verdict

The status says whether DataDome **enforced**; the header says **what it decided**. Neither alone
is enough:

| Status | `x-datadome-traffic-rule-response` | Means |
|---|---|---|
| 200 | `authorize` / absent | allowed |
| 200 | `interstitial` / `block` / `hard_block` | **detected, not enforced** — the request was served |
| 403 | `hard_block` | **blocked** |
| 403 | `interstitial` / `block` | **challenged** |
| 499 | anything | unknown — the client left before the answer arrived |

> **`block` is the slider CAPTCHA, not a block.** It is the one value in DataDome's vocabulary
> whose name means the opposite of what it does. `hard_block` is the real block. Conflating them
> overstates enforcement across a large share of traffic — and understates real hard blocks when
> both appear.

---

## nginx

Deliver via Vector to an **nginx** feed: the sink's `uri` is
`https://<ingest-host>/ingest/v1/nginx/<feed-id>` with `Authorization: Bearer <token>`
(in `deploy/vector/nginx.toml`).

**The log format must be JSON.** The combined text format cannot carry `cf_ray` without positional
parsing that breaks the moment a field is added.

```nginx
log_format siem_json escape=json '{'
  '"time_iso8601":"$time_iso8601",'
  '"cf_ray":"$http_cf_ray",'
  '"cf_connecting_ip":"$http_cf_connecting_ip",'
  '"x_forwarded_for":"$http_x_forwarded_for",'
  '"remote_addr":"$remote_addr",'
  '"host":"$host","server_name":"$server_name",'
  '"request_method":"$request_method","request_uri":"$request_uri",'
  '"server_protocol":"$server_protocol","scheme":"$scheme",'
  '"status":$status,"body_bytes_sent":$body_bytes_sent,'
  '"request_length":$request_length,"request_time":$request_time,'
  '"upstream_addr":"$upstream_addr","upstream_status":"$upstream_status",'
  '"upstream_response_time":"$upstream_response_time",'
  '"user_agent":"$http_user_agent","referer":"$http_referer"'
'}';

access_log /var/log/nginx/access.json siem_json;
```

**`$http_cf_ray` arrives with a datacentre suffix** — `a2d6ea0f6813ccd4-DXB` — while Cloudflare
logs only the bare id. The parser strips it. If you pre-process these logs anywhere else, strip it
there too, or every origin record will silently fail to join.

**`cf_connecting_ip` matters**: behind Cloudflare, `remote_addr` is an edge address. Without it,
every request is attributed to the CDN.

---

## F5 BIG-IP ASM

Remote logging in **Key-Value Pairs** format (least parsing ambiguity), delivered via
Vector's syslog source to an **f5asm** feed: point the Vector HTTP sink at
`https://<ingest-host>/ingest/v1/f5asm/<feed-id>` with
`Authorization: Bearer <token>` (in `deploy/vector/f5asm.toml`, the sink's `uri` and
the bearer token).

**`CF-Ray` must reach the log.** Confirmed working in production via the captured request text —
the parser reads it from a dedicated `cf_ray` field if the logging profile provides one, and
otherwise scrapes `CF-Ray:` out of the captured raw request, which an iRule can populate:

```tcl
when HTTP_REQUEST {
    set cf_ray [HTTP::header value "CF-Ray"]
}
```

Without it the WAF layer joins only heuristically, and the exact-join ratio on the Dashboards page
will show the degradation.

---

## Confirming it works

1. **Sources page** — every source should leave `Awaiting first record`.
2. **Dashboards → Correlation quality** — the exact-join ratio should sit near 100%. A fall means
   identifier propagation broke somewhere above.
3. **Search → open any flow** — a healthy deployment shows four layers. A layer marked
   *"No record received"* is a collection problem, not an allow.

### When nothing arrives

- **401 on every delivery** — the token was rotated and the provider still sends the old
  one, or the URL's feed id belongs to a different feed than the token.
- **503 on every delivery** — ingest cannot reach its credential store; deliveries are
  being retried by the sender, not lost. Check the logproc log for
  "feed store refresh failed".
- **Silence with no errors** — the feed was disabled, and the sender treats 401 by
  backing off quietly. The Feeds page shows the disabled chip.

### When nothing correlates

In order of likelihood:

1. **`ParentRayID` not enabled** on the Logpush job — the DataDome layer can never attach.
2. **nginx not logging `$http_cf_ray`**, or the suffix not stripped by a pre-processor.
3. **F5 not logging `CF-Ray`** — the WAF layer falls to heuristic joining.
4. **Clock skew** beyond the correlation window, visible as `clock_skew` on affected flows.
5. **Different traffic** — the feeds genuinely cover different hostnames or zones.
