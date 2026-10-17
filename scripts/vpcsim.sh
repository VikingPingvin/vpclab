#!/usr/bin/env bash
# Build vpcsim and run it in a privileged container.
#   scripts/vpcsim.sh apply        reconcile once
#   scripts/vpcsim.sh run          reconcile continuously (foreground)
#   scripts/vpcsim.sh plan         print the desired data plane
#
# --pid=host lets vpcsim open the network namespaces of the router and
# instance containers through /proc/<pid>/ns/net. --network=host lets it reach
# Floci on localhost:4566.
set -euo pipefail
export PATH=/usr/local/go/bin:$PATH
cd "$(dirname "$0")/.."

CGO_ENABLED=0 go build -o bin/vpcsim ./cmd/vpcsim
docker build -q -t vpcsim-runtime:dev - <deploy/runtime.Dockerfile >/dev/null
docker build -q -f deploy/vpcsim.Dockerfile -t vpcsim:dev . >/dev/null
# Each new binary untags the previous vpcsim:dev. No container uses it.
docker image prune -f --filter label=vpcsim.image=vpcsim >/dev/null

exec docker run --rm --init --privileged --pid=host --network=host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e FLOCI_ENDPOINT -e VPCSIM_INSTANCE_IMAGE -e VPCSIM_RUNTIME_IMAGE -e VPCSIM_DNS \
  vpcsim:dev "$@"
