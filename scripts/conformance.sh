#!/usr/bin/env bash
# Run the vpcsim conformance suite against the local Floci.
# Extra arguments go to `go test`, e.g. -run TestSecurityGroups.
set -euo pipefail
export PATH=/usr/local/go/bin:$PATH
cd "$(dirname "$0")/.."

# The tests reconcile with vpcsim apply. A second reconciler races with it.
if docker ps --no-trunc --format '{{.Command}}' | grep -q 'vpcsim run'; then
  echo "scripts/vpcsim.sh run is active; stop it (Ctrl+C in its terminal) before the conformance tests" >&2
  exit 1
fi
docker compose -f deploy/compose.yaml up -d --wait >/dev/null
go test -tags conformance -count=1 -v ./test/conformance/ "$@"
