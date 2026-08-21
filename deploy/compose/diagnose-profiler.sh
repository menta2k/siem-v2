#!/usr/bin/env bash
# Traffic profiler diagnostic — READ-ONLY. Run on the compose host:
#
#     cd deploy/compose && ./diagnose-profiler.sh
#
# Prints everything needed to explain "no profiles are appearing": container
# and image state, profilerd health counters, the publish/consume path, the
# NATS stream, per-tenant profiler policy, and what tenants/hosts the stored
# flows actually carry. No secrets are printed and nothing is modified.
set -uo pipefail
cd "$(dirname "$0")"

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile app"

section() { printf '\n===== %s =====\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
pretty() { if have jq; then jq .; elif have python3; then python3 -m json.tool; else cat; fi; }

section "1. containers (profiler path)"
$COMPOSE ps --format 'table {{.Service}}\t{{.Status}}\t{{.Image}}' 2>/dev/null \
  | grep -Ei 'service|profilerd|logproc|apiserver|nats|postgres' \
  || echo "compose ps failed — wrong directory or compose files missing?"

section "2. running image identity (is the code actually new?)"
for s in profilerd logproc apiserver; do
  id=$($COMPOSE ps -q "$s" 2>/dev/null)
  if [ -n "${id:-}" ]; then
    docker inspect --format "$s: image={{.Config.Image}} started={{.State.StartedAt}}" "$id"
    img=$(docker inspect --format '{{.Image}}' "$id")
    docker image inspect --format "$s: image built {{.Created}}" "$img"
  else
    echo "$s: NO CONTAINER"
  fi
done

section "3. profilerd /health"
curl -s -m 5 http://localhost:8300/health | pretty || echo "profilerd health unreachable on :8300"

section "4. logproc → conveyor (is anything being published?)"
$COMPOSE logs --since 6h logproc 2>/dev/null \
  | grep -E "publishing completed flows|flow conveyor|dropped before profiling" | tail -n 5
$COMPOSE logs --since 1h logproc 2>/dev/null | grep -iE '"level":"error"|ERROR' | tail -n 3

section "5. profilerd log tail"
$COMPOSE logs --since 6h profilerd 2>/dev/null | tail -n 15

section "6. NATS SIEM_FLOWS stream + consumer"
curl -s -m 5 "http://localhost:8222/jsz?streams=true&consumers=true" | {
  if have jq; then
    jq '[.account_details[]?.stream_detail[]? | select(.name=="SIEM_FLOWS")
         | {messages:.state.messages, first_seq:.state.first_seq, last_seq:.state.last_seq,
            consumers:[.consumer_detail[]? | {name:.name,
              ack_floor:.ack_floor.stream_seq, num_pending:.num_pending,
              num_ack_pending:.num_ack_pending}]}]'
  else
    grep -o 'SIEM_FLOWS' | head -1 || echo "stream SIEM_FLOWS not found (or jq missing for detail)"
  fi
} || echo "NATS monitoring unreachable on :8222"

section "7. per-tenant profiler policy (postgres)"
$COMPOSE exec -T postgres sh -c \
  'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -P pager=off -c \
   "SELECT id AS tenant, profiler_config FROM tenant;"' 2>/dev/null \
  || echo "postgres query failed"

section "8. stored profiles (postgres)"
$COMPOSE exec -T postgres sh -c \
  'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -P pager=off \
   -c "SELECT tenant_id, count(*) AS endpoints, coalesce(sum(observations),0) AS observations FROM profile_endpoint GROUP BY 1;" \
   -c "SELECT tenant_id, host, method, path_template, observations, last_seen FROM profile_endpoint ORDER BY observations DESC LIMIT 10;"' 2>/dev/null \
  || echo "postgres query failed"

section "9. what tenants/hosts the FLOWS actually carry (victorialogs, last 30m)"
curl -s -m 10 'http://localhost:9428/select/logsql/query' \
  --data-urlencode 'query=provider:correlated _time:30m | fields tenant, host, method, path | limit 10' \
  | head -n 10
echo
curl -s -m 10 'http://localhost:9428/select/logsql/query' \
  --data-urlencode 'query=provider:correlated _time:30m | stats by (tenant, host) count() flows' \
  | head -n 20

section "done"
echo "Paste everything above back for analysis."
