#!/usr/bin/env bash
# Build and run the exercise runner. Run scripts/vpcsim.sh run in another
# terminal first.
#   scripts/cap.sh list | start <name> | status | verify | hint | reset | stop
set -euo pipefail
export PATH=/usr/local/go/bin:$PATH
cd "$(dirname "$0")/.."

go build -o bin/cap ./cmd/cap
exec bin/cap "$@"
