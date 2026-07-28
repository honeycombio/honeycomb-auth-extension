#!/usr/bin/env bash
# Automated end-to-end suite: builds the example distro with OCB, runs it
# against the mock /1/auth, sends real OTLP/HTTP requests for every auth
# scenario, and asserts HTTP status codes, the outcome counter values on
# :8888/metrics, and the sampled warn logs.
set -euo pipefail
cd "$(dirname "$0")"

MOCK_URL=http://localhost:8088
OTLP_URL=http://localhost:4318/v1/traces
METRICS_URL=http://localhost:8888/metrics

WORKDIR=$(mktemp -d)
COLLECTOR_LOG="$WORKDIR/collector.log"
FAILURES=0

../example/build.sh

SPAN='{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"e2e"}}]},"scopeSpans":[{"spans":[{"traceId":"5b8efff798038103d269b633813fc60c","spanId":"eee19b7ec3c1b174","name":"e2e-span","kind":1,"startTimeUnixNano":"1700000000000000000","endTimeUnixNano":"1700000001000000000"}]}]}]}'

echo "starting mock /1/auth ..."
python3 ../example/mock_auth.py &
MOCK_PID=$!

echo "starting collector (log: $COLLECTOR_LOG) ..."
../example/_build/otelcol-honeycomb-auth-example --config config.yaml > "$COLLECTOR_LOG" 2>&1 &
COLLECTOR_PID=$!

cleanup() {
  kill "$COLLECTOR_PID" "$MOCK_PID" 2>/dev/null || true
  wait "$COLLECTOR_PID" "$MOCK_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "waiting for collector readiness ..."
for i in $(seq 1 30); do
  curl -sf -o /dev/null "$METRICS_URL" && break
  [ "$i" -eq 30 ] && { echo "FATAL: collector never became ready"; cat "$COLLECTOR_LOG"; exit 1; }
  sleep 1
done

fail() {
  echo "FAIL: $1"
  FAILURES=$((FAILURES + 1))
}

# send <expected-status> <description> [curl args...]
send() {
  local want=$1 desc=$2
  shift 2
  local got
  got=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$OTLP_URL" \
    -H "content-type: application/json" "$@" -d "$SPAN")
  if [ "$got" = "$want" ]; then
    echo "ok: $desc -> $got"
  else
    fail "$desc: want HTTP $want, got $got"
  fi
}

# expect_metric <outcome> <want-count>
expect_metric() {
  local outcome=$1 want=$2 got
  got=$(curl -s "$METRICS_URL" \
    | sed -n "s/^otelcol_honeycomb_auth_authentications{outcome=\"$outcome\"} \(.*\)$/\1/p")
  got=${got:-0}
  if [ "$got" = "$want" ]; then
    echo "ok: metric outcome=$outcome -> $got"
  else
    fail "metric outcome=$outcome: want $want, got $got"
  fi
}

# expect_log <description> <grep-pattern>
expect_log() {
  if grep -q "$2" "$COLLECTOR_LOG"; then
    echo "ok: log contains $1"
  else
    fail "log missing $1 (pattern: $2)"
  fi
}

echo "--- scenarios: backend healthy"
send 200 "allowed team accepted"        -H "x-honeycomb-team: goodkey"
send 401 "other team rejected"          -H "x-honeycomb-team: otherteamkey"
send 401 "other environment rejected"   -H "x-honeycomb-team: otherenvkey"
send 200 "classic key accepted (default allow_classic)" -H "x-honeycomb-team: classickey"
send 401 "invalid key rejected"         -H "x-honeycomb-team: badkey"
send 401 "missing ingest scope rejected" -H "x-honeycomb-team: noscope"
send 401 "missing header rejected"

echo "--- scenarios: backend outage (stale serving)"
curl -sf -X POST -o /dev/null "$MOCK_URL/down"
sleep 3  # let the positive cache entry (ttl 2s) expire
send 200 "known key served stale during outage" -H "x-honeycomb-team: goodkey"
send 401 "unknown key rejected during outage"   -H "x-honeycomb-team: neverseenkey"
curl -sf -X POST -o /dev/null "$MOCK_URL/up"

echo "--- metrics"
expect_metric valid 2
expect_metric team_not_allowed 1
expect_metric environment_not_allowed 1
expect_metric invalid_key 1
expect_metric no_ingest_scope 1
expect_metric missing_header 1
expect_metric valid_stale 1
expect_metric backend_error 1

echo "--- logs"
expect_log "team-mismatch warn" "team is not in allowed_teams"
expect_log "stale-serving warn" "serving stale auth result"

if [ "$FAILURES" -gt 0 ]; then
  echo ""
  echo "$FAILURES failure(s); collector log:"
  cat "$COLLECTOR_LOG"
  exit 1
fi
echo ""
echo "e2e suite passed"
