#!/usr/bin/env bash
# Build vpcsim and run it in a privileged container.
#   scripts/vpcsim.sh apply        reconcile once
#   scripts/vpcsim.sh run          reconcile continuously (foreground)
#   scripts/vpcsim.sh plan         print the desired data plane
#
# For everyday use, scripts/vpclab.sh up runs the reconciler in the
# background instead.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/lib.sh

build_vpcsim
exec docker run --rm "${VPCSIM_RUN_ARGS[@]}" vpcsim:dev "$@"
