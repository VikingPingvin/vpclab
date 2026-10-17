# The vpcsim binary on top of the runtime image (deploy/runtime.Dockerfile).
# Build the binary first: CGO_ENABLED=0 go build -o bin/vpcsim ./cmd/vpcsim
ARG RUNTIME_IMAGE=vpcsim-runtime:dev
FROM ${RUNTIME_IMAGE}
COPY bin/vpcsim /usr/local/bin/vpcsim
LABEL vpcsim.image=vpcsim
ENTRYPOINT ["vpcsim"]
