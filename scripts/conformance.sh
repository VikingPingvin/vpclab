#!/usr/bin/env bash
# Run the vpcsim conformance suite. Extra arguments go to `go test`, e.g.
# -run TestSecurityGroups.
#
# The tests use their own, throwaway Floci on port 4567, so they never see the
# lab's resources and leave nothing behind in it. The data plane is shared:
# the background reconciler (vpclab up) is paused during the run and resumed
# afterwards; it then rebuilds the lab's containers. Files inside the lab's
# instances are lost.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/lib.sh

TEST_FLOCI=vpclab-test-floci
TEST_PORT=4567

# A foreground `scripts/vpcsim.sh run` would race with the tests' applies.
if docker ps --no-trunc --format '{{.Names}} {{.Command}}' | grep -v "^$RECONCILER " | grep -q 'vpcsim run'; then
  echo "scripts/vpcsim.sh run is active; stop it (Ctrl+C in its terminal) before the conformance tests" >&2
  exit 1
fi

resume=false
cleanup() {
  docker rm -f "$TEST_FLOCI" >/dev/null 2>&1 || true
  if $resume; then
    echo "==> resuming the lab reconciler"
    docker start "$RECONCILER" >/dev/null
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

if [[ "$(docker inspect -f '{{.State.Running}}' "$RECONCILER" 2>/dev/null)" == true ]]; then
  echo "==> pausing the lab reconciler"
  docker stop "$RECONCILER" >/dev/null
  resume=true
fi

echo "==> starting a throwaway Floci on port $TEST_PORT"
image=$(sed -n 's/^ *image: *\(floci\/floci:.*\)$/\1/p' deploy/compose.yaml | head -1)
docker rm -f "$TEST_FLOCI" >/dev/null 2>&1 || true
docker run -d --name "$TEST_FLOCI" -p "$TEST_PORT:4566" \
  -e FLOCI_SERVICES_EC2_MOCK=true "$image" >/dev/null
for i in $(seq 1 60); do
  [[ "$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$TEST_PORT/" || true)" == 200 ]] && break
  [[ $i == 60 ]] && { echo "the test Floci did not start" >&2; exit 1; }
  sleep 1
done

export FLOCI_ENDPOINT="http://localhost:$TEST_PORT"
go test -tags conformance -count=1 -v ./test/conformance/ "$@"
