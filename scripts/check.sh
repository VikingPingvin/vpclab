#!/usr/bin/env bash
# Format check, vet and unit tests. Extra arguments go to `go test`.
set -uo pipefail
export PATH=/usr/local/go/bin:$PATH
cd "$(dirname "$0")/.."

go mod tidy
unformatted=$(gofmt -l .)
if [[ -n "$unformatted" ]]; then
  echo "unformatted files:" $unformatted
  gofmt -d $unformatted
  exit 1
fi
go vet ./... && go test ./... "$@"
