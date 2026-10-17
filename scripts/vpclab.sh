#!/usr/bin/env bash
# vpclab: start, stop and inspect the local lab (Floci + vpcsim) in WSL.
#
#   vpclab up              start Floci and the background reconciler, wait for the first reconcile
#   vpclab status          show Floci, the reconciler and the instances
#   vpclab down            stop the reconciler, the lab containers and Floci (files are kept)
#   vpclab reset [--yes]   down, delete all Floci state (an empty AWS account), up
#   vpclab sh <name|id>    open a shell on an instance (Name tag or instance ID)
#   vpclab logs            follow the reconciler log
#   vpclab plan            print the desired data plane
#   vpclab dashboard [stop]  start (or stop) the read-only AWS-console-style UI on http://localhost:4577
#
# From PowerShell, use .\vpclab.ps1 in the repo root; it forwards here.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
. scripts/lib.sh

COMPOSE=(docker compose -f deploy/compose.yaml)
# The dashboard is an optional compose profile. Commands that must also see
# it (down, its own start and stop) use this form.
COMPOSE_ALL=("${COMPOSE[@]}" --profile dashboard)
COMPOSE_PROGRESS='^ *(Container|Network|Image) |^Going to remove ' # compose progress lines, hidden
DASHBOARD_URL=http://localhost:4577

usage() {
  sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

say() { printf '%s\n' "$*"; }
die() {
  printf 'vpclab: %s\n' "$*" >&2
  exit 1
}

floci_state() {
  local id
  id=$("${COMPOSE[@]}" ps -q floci 2>/dev/null || true)
  [[ -n "$id" ]] || { echo "stopped"; return; }
  docker inspect -f '{{.State.Status}}{{if .State.Health}} ({{.State.Health.Status}}){{end}}' "$id"
}

dashboard_state() {
  local id
  id=$("${COMPOSE_ALL[@]}" ps -q dashboard 2>/dev/null || true)
  [[ -n "$id" ]] || { echo "stopped"; return; }
  docker inspect -f '{{.State.Status}}' "$id"
}

cmd_dashboard() {
  case "${1:-}" in
    "")
      # depends_on starts Floci too, if it is not running.
      "${COMPOSE_ALL[@]}" up -d --wait --quiet-pull dashboard 2>&1 | grep -v -E "$COMPOSE_PROGRESS" || true
      [[ "$(dashboard_state)" == running ]] || die "the dashboard did not start; see: docker compose -f deploy/compose.yaml --profile dashboard logs dashboard"
      say "Dashboard   running   $DASHBOARD_URL"
      ;;
    stop)
      "${COMPOSE_ALL[@]}" rm -sf dashboard 2>&1 | grep -v -E "$COMPOSE_PROGRESS" || true
      say "Dashboard   stopped"
      ;;
    *) die "usage: vpclab dashboard [stop]" ;;
  esac
}

reconciler_state() {
  docker inspect -f '{{.State.Status}}' "$RECONCILER" 2>/dev/null || echo "not created"
}

# last_reconcile prints the reconciler's last "reconcile ok" or
# "reconcile failed" line, optionally only lines after a Unix time.
last_reconcile() {
  local since=${1:-}
  docker logs ${since:+--since "$since"} "$RECONCILER" 2>&1 | grep -E 'INFO reconcile ok|ERROR reconcile failed' | tail -1 || true
}

# A foreground `scripts/vpcsim.sh run` races with the background reconciler.
check_no_foreground_run() {
  if docker ps --no-trunc --format '{{.Names}} {{.Command}}' | grep -v "^$RECONCILER " | grep -q 'vpcsim run'; then
    die "a foreground 'scripts/vpcsim.sh run' is active; stop it (Ctrl+C in its terminal) first"
  fi
}

cmd_up() {
  check_no_foreground_run
  say "==> Floci"
  "${COMPOSE[@]}" up -d --wait --quiet-pull 2>&1 | grep -v -E "$COMPOSE_PROGRESS" || true
  say "==> building vpcsim"
  build_vpcsim

  local image current since=""
  image=$(docker image inspect -f '{{.Id}}' vpcsim:dev)
  current=$(docker inspect -f '{{.Image}} {{.State.Running}}' "$RECONCILER" 2>/dev/null || true)
  if [[ "$current" != "$image true" ]]; then
    say "==> starting the reconciler"
    docker rm -f "$RECONCILER" >/dev/null 2>&1 || true
    since=$(date +%s)
    docker run -d --name "$RECONCILER" --restart unless-stopped --label vpclab.role=reconciler \
      "${VPCSIM_RUN_ARGS[@]}" vpcsim:dev run >/dev/null
  fi

  if [[ -n "$since" ]]; then
    say "==> waiting for the first reconcile"
    local line=""
    for _ in $(seq 1 90); do
      line=$(last_reconcile "$since")
      [[ -n "$line" ]] && break
      sleep 1
    done
    case "$line" in
      *"reconcile ok"*) ;;
      "") die "no reconcile result after 90 s; see: vpclab logs" ;;
      *) die "first reconcile failed: ${line#*reconcile failed }" ;;
    esac
  fi
  say
  cmd_status
}

cmd_status() {
  say "Floci       $(floci_state)   http://localhost:4566"
  local rs line
  rs=$(reconciler_state)
  line=$(last_reconcile)
  case "$line" in
    *"reconcile ok"*) say "Reconciler  $rs   last reconcile: ok" ;;
    *"reconcile failed"*) say "Reconciler  $rs   last reconcile FAILED: ${line#*reconcile failed }" ;;
    *) say "Reconciler  $rs" ;;
  esac
  if [[ "$(dashboard_state)" == running ]]; then
    say "Dashboard   running   $DASHBOARD_URL"
  else
    say "Dashboard   stopped   (start: vpclab dashboard)"
  fi
  if [[ "$(floci_state)" == running* ]]; then
    [[ -x bin/vpcsim ]] || CGO_ENABLED=0 go build -o bin/vpcsim ./cmd/vpcsim
    say
    bin/vpcsim ls
  fi
}

# cmd_down stops the lab but keeps the lab containers, so files inside
# instances survive; the reconciler starts the containers again on up.
cmd_down() {
  say "==> stopping the reconciler and the lab containers"
  docker rm -f "$RECONCILER" >/dev/null 2>&1 || true
  local ids
  ids=$(docker ps -q --filter label=vpcsim.role)
  [[ -z "$ids" ]] || docker stop -t 5 $ids >/dev/null
  say "==> stopping Floci and the dashboard"
  "${COMPOSE_ALL[@]}" down 2>&1 | grep -v -E "$COMPOSE_PROGRESS" || true
  say "Lab stopped. 'vpclab up' starts it again with the same resources and files."
}

remove_lab_containers() {
  local ids
  ids=$(docker ps -aq --filter label=vpcsim.role)
  [[ -z "$ids" ]] || docker rm -f $ids >/dev/null
  ids=$(docker network ls -q --filter label=vpcsim.role)
  [[ -z "$ids" ]] || docker network rm $ids >/dev/null
}

cmd_reset() {
  if [[ "${1:-}" != "--yes" ]]; then
    [[ -t 0 ]] || die "reset deletes all Floci state; run 'vpclab reset --yes' to confirm"
    read -r -p "Delete ALL Floci state (VPCs, instances, IAM users, S3 buckets, ...)? [y/N] " answer
    [[ "$answer" == [yY]* ]] || die "cancelled"
  fi
  cmd_down
  say "==> removing the lab containers"
  remove_lab_containers
  say "==> deleting Floci state in deploy/data"
  # Floci writes the files as root; delete them from a container.
  docker build -q -t vpcsim-runtime:dev - <deploy/runtime.Dockerfile >/dev/null
  mkdir -p deploy/data
  docker run --rm -v "$PWD/deploy/data:/data" --entrypoint find vpcsim-runtime:dev /data -mindepth 1 -delete
  cmd_up
}

cmd_sh() {
  [[ -n "${1:-}" ]] || die "usage: vpclab sh <name|instance-id>"
  [[ -x bin/vpcsim ]] || CGO_ENABLED=0 go build -o bin/vpcsim ./cmd/vpcsim
  local ids
  mapfile -t ids < <(bin/vpcsim ls -q "$1")
  case ${#ids[@]} in
    0) die "no instance with ID or Name tag '$1'; see: vpclab status" ;;
    1) ;;
    *) die "several instances are called '$1': ${ids[*]}; use the instance ID" ;;
  esac
  docker exec -it "vpcsim-${ids[0]}" bash
}

case "${1:-}" in
  up) cmd_up ;;
  status) cmd_status ;;
  down) cmd_down ;;
  reset) cmd_reset "${2:-}" ;;
  sh) cmd_sh "${2:-}" ;;
  logs) exec docker logs -f --tail 100 "$RECONCILER" ;;
  dashboard) cmd_dashboard "${2:-}" ;;
  plan)
    [[ -x bin/vpcsim ]] || CGO_ENABLED=0 go build -o bin/vpcsim ./cmd/vpcsim
    exec bin/vpcsim plan
    ;;
  *) usage ;;
esac
