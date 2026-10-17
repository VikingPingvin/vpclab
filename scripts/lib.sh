# Shared by the vpcsim and vpclab scripts. Source it; it does not run alone.

export PATH=/usr/local/go/bin:$PATH

# build_vpcsim builds the vpcsim binary and the vpcsim and runtime images.
# Go and Docker cache both steps, so an unchanged tree builds in seconds.
build_vpcsim() {
  CGO_ENABLED=0 go build -o bin/vpcsim ./cmd/vpcsim
  docker build -q -t vpcsim-runtime:dev - <deploy/runtime.Dockerfile >/dev/null
  docker build -q -f deploy/vpcsim.Dockerfile -t vpcsim:dev . >/dev/null
  # Each new binary untags the previous vpcsim:dev. No container uses it.
  docker image prune -f --filter label=vpcsim.image=vpcsim >/dev/null
}

# VPCSIM_RUN_ARGS are the docker run arguments for a vpcsim container.
# --pid=host lets vpcsim open the network namespaces of the router and
# instance containers through /proc/<pid>/ns/net. --network=host lets it reach
# Floci on localhost:4566.
VPCSIM_RUN_ARGS=(
  --init --privileged --pid=host --network=host
  -v /var/run/docker.sock:/var/run/docker.sock
  -e FLOCI_ENDPOINT -e VPCSIM_INSTANCE_IMAGE -e VPCSIM_RUNTIME_IMAGE -e VPCSIM_DNS
)

# The background reconciler started by vpclab up. It must not carry the
# vpcsim.role label: vpcsim removes every labelled container it did not plan.
RECONCILER=vpcsim-reconciler
