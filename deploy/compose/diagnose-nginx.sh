#!/usr/bin/env bash
# nginx feed diagnostic — READ-ONLY. Two ends of the same pipe:
#
#     cd deploy/compose && ./diagnose-nginx.sh            # on the SIEM compose host
#     ./diagnose-nginx.sh --nginx-host                    # on each nginx/Vector box
#
# Explains "no nginx logs are arriving": is nginx writing the JSON log, is
# Vector shipping it and to WHICH route, does logproc accept or refuse it, and
# where (which tenant) the records land. No secrets are printed and nothing is
# modified.
set -uo pipefail

section() { printf '\n===== %s =====\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

if [ "${1:-}" = "--nginx-host" ]; then
  # Read the paths Vector actually tails from its include = [...] globs; sites
  # often log per vhost (/srv/logs/<site>/siem.log), not the default path.
  globs=$(grep -hE '^\s*include\s*=' /etc/vector/*.toml 2>/dev/null | grep -oE '"[^"]+"' | tr -d '"')
  [ -n "$globs" ] || globs=/var/log/nginx/access.json

  section "1. nginx JSON access logs (from Vector include: $(echo $globs))"
  found=0
  for g in $globs; do
    for LOG in $g; do # unquoted on purpose: expands the glob
      [ -f "$LOG" ] || continue
      found=1
      echo "-- $(ls -l --time-style=+%FT%T%z "$LOG" | awk '{print $5" bytes, modified "$6}')  $LOG"
      tail -n 1 "$LOG" | cut -c1-200
      # The parser needs cf_ray; an empty one means no correlation key.
      tail -n 200 "$LOG" | grep -c '"cf_ray":""' | sed 's/^/   lines with EMPTY cf_ray (of last 200): /'
    done
  done
  if [ "$found" = 0 ]; then
    echo "NO FILES match — nginx is not writing the siem_json log (docs/connecting-vendors.md#nginx)"
    grep -rhs "access_log\|log_format siem_json" /etc/nginx/ | sed 's/^/  nginx conf: /' | head
  fi

  section "2. Vector service"
  if have systemctl; then
    systemctl is-active vector 2>&1 | sed 's/^/vector: /'
    journalctl -u vector --since "6 hours ago" --no-pager 2>/dev/null \
      | grep -Ei 'error|warn|401|403|404|502|503|retry|unauthorized' | tail -n 15
    # Vector suppresses repeats, so the tail above can hide an ongoing outage:
    # count retry/failure lines per hour to see whether it is still happening.
    echo "sink retry/error lines per hour (last 6h):"
    journalctl -u vector --since "6 hours ago" --no-pager -o short-iso 2>/dev/null \
      | grep -Ei 'sink.*(retry|error)' | cut -c1-13 | sort | uniq -c
  fi

  section "2b. can this box reach logproc right now? (no token, no data sent)"
  # A live logproc answers 401 to an unauthenticated POST; 502/503/timeout means
  # the proxy in front of it cannot reach logproc.
  for u in $(grep -hE '^\s*uri\s*=' /etc/vector/*.toml 2>/dev/null | grep -oE '"[^"]+"' | tr -d '"' | sort -u); do
    code=$(curl -s -o /dev/null -m 10 -w '%{http_code}' -X POST "$u")
    echo "$code  $u"
  done

  section "3. Vector sink target (secret redacted)"
  for f in /etc/vector/*.toml /etc/vector/*.yaml; do
    [ -f "$f" ] || continue
    echo "-- $f"
    grep -nE '^\s*(uri|include|type|auth\.token|token)\s*[:=]' "$f" \
      | sed -E 's/(token\s*[:=]\s*).*/\1<redacted>/'
  done
  echo "Expected uri: https://<ingest-host>/ingest/v1/nginx/<feed-id>  (per-feed token)"
  echo "Legacy  uri: .../ingest/v1/vector/nginx  (shared SIEM_INGEST_SECRET, tenant hardcoded to 'acme')"

  section "4. Vector disk buffer (a growing backlog = sink is failing)"
  du -sh /var/lib/vector/* 2>/dev/null || echo "no /var/lib/vector data dir"

  section "done"
  echo "Paste everything above back for analysis."
  exit 0
fi

cd "$(dirname "$0")"
COMPOSE="docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile app"
vl() { # vl <port> <logsql>
  curl -s -m 15 "http://localhost:$1/select/logsql/query" --data-urlencode "query=$2" | head -n 25
  echo
}

section "1. logproc container + image"
id=$($COMPOSE ps -q logproc 2>/dev/null)
if [ -n "${id:-}" ]; then
  docker inspect --format 'logproc: image={{.Config.Image}} started={{.State.StartedAt}} status={{.State.Status}}' "$id"
  docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$id" \
    | grep -q '^SIEM_INGEST_SECRET=.\+' \
    && echo "SIEM_INGEST_SECRET: set (legacy /ingest/v1/vector/nginx route usable)" \
    || echo "SIEM_INGEST_SECRET: EMPTY — legacy /ingest/v1/vector/nginx refuses everything"
else
  echo "logproc: NO CONTAINER"
fi

section "2. logproc /health"
curl -s -m 5 http://localhost:8100/health; echo

section "3. refused deliveries (bad/missing credential), last 24h"
$COMPOSE logs --since 24h logproc 2>/dev/null | grep -i 'REFUSED' | tail -n 10

section "4. nginx batches processed vs errors, last 6h"
logs=$($COMPOSE logs --since 6h logproc 2>/dev/null)
printf 'nginx batches processed: %s\n' "$(grep 'batch processed' <<<"$logs" | grep -c nginx)"
grep 'batch processed' <<<"$logs" | grep nginx | tail -n 3
grep -iE '"level":"error"|level=ERROR' <<<"$logs" | grep -i nginx | tail -n 5

section "5. nginx feeds (postgres)"
$COMPOSE exec -T postgres sh -c \
  'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -P pager=off -c \
   "SELECT id, tenant_id, name, enabled, updated_at, token_rotated_at FROM feed WHERE provider = '"'"'nginx'"'"' ORDER BY tenant_id;"' 2>/dev/null \
  || echo "postgres query failed"

section "6. raw nginx records by tenant (victorialogs-raw, last 24h)"
vl 9430 'provider:nginx record_kind:raw _time:24h | stats by (tenant) count() records, max(_time) newest'

section "7. nginx dead letters (unparseable lines), last 24h"
vl 9430 'provider:nginx record_kind:dead_letter _time:24h | stats by (tenant) count() dead, max(_time) newest'
vl 9428 'provider:nginx record_kind:dead_letter _time:24h | stats by (tenant) count() dead, max(_time) newest'

section "8. flows with an nginx layer, by tenant (victorialogs-hot, last 24h)"
vl 9428 'provider:correlated providers:nginx _time:24h | stats by (tenant) count() flows, max(_time) newest'

section "9. other providers for comparison (raw, last 1h)"
vl 9430 'record_kind:raw _time:1h | stats by (provider, tenant) count() records, max(_time) newest'

section "done"
echo "Paste everything above back for analysis."
