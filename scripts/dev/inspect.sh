#!/usr/bin/env bash
# Show what the data plane looks like: per router, the nft drop counters,
# routes and rules; per instance, its addresses, routes and ARP table.
set -uo pipefail

for r in $(docker ps --filter label=vpcsim.role=router --format '{{.Names}}'); do
  echo "=== $r"
  docker exec "$r" sh -c '
    echo "--- links"; ip -br link
    echo "--- rules"; ip rule
    for t in $(ip rule | grep -o "lookup [0-9]*" | sort -u | cut -d" " -f2); do echo "--- table $t"; ip route show table $t; done
    echo "--- nft counters (non-zero)"; nft list ruleset | grep -E "counter packets [1-9]"
    echo "--- conntrack"; conntrack -L 2>/dev/null | head -5'
done
for c in $(docker ps --filter label=vpcsim.role=instance --format '{{.Names}}'); do
  echo "=== $c"
  docker exec "$c" sh -c 'ip -br addr; ip route; ip neigh'
done
