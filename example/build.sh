#!/usr/bin/env bash
# Install OCB (pinned) if needed and build the example distro into ./_build.
# Shared by run.sh (interactive example) and e2e/run.sh (automated tests).
set -euo pipefail
cd "$(dirname "$0")"
export GOTOOLCHAIN=auto GOWORK=off

OCB_VERSION=v0.157.0
# Version-suffixed so a version bump reinstalls instead of reusing a stale binary.
BUILDER=./.bin/builder-${OCB_VERSION}
if [ ! -x "$BUILDER" ]; then
  echo "installing ocb ${OCB_VERSION} -> .bin/ ..."
  GOBIN="$(pwd)/.bin" go install "go.opentelemetry.io/collector/cmd/builder@${OCB_VERSION}"
  mv .bin/builder "$BUILDER"
fi

echo "building distro ..."
"$BUILDER" --config builder-config.yaml
