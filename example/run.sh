#!/usr/bin/env bash
# Build the example distro (OTLP receiver + honeycomb_auth + debug exporter) and
# run it against a local mock /1/auth. Send OTLP with x-honeycomb-team: goodkey
# (accepted) or badkey (401).
set -euo pipefail
cd "$(dirname "$0")"
export GOTOOLCHAIN=auto GOWORK=off

OCB_VERSION=v0.155.0
BUILDER=./.bin/builder
if [ ! -x "$BUILDER" ]; then
  echo "installing ocb ${OCB_VERSION} -> .bin/ ..."
  GOBIN="$(pwd)/.bin" go install "go.opentelemetry.io/collector/cmd/builder@${OCB_VERSION}"
fi

echo "building distro ..."
"$BUILDER" --config builder-config.yaml

echo "starting mock /1/auth on :8088 (goodkey -> valid, badkey -> 401) ..."
python3 mock_auth.py &
MOCK=$!
trap 'kill "$MOCK" 2>/dev/null || true' EXIT

echo "running collector (Ctrl-C to stop) ..."
./_build/otelcol-honeycomb-auth-example --config config.yaml
