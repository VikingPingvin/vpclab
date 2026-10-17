# Tools-only image for the VPC router and internet containers, and the base
# of the vpcsim image. It changes only when this file changes, so rebuilding
# vpcsim leaves the running routers on a named image.
FROM alpine:3
RUN apk add --no-cache iproute2 nftables util-linux docker-cli tcpdump conntrack-tools
LABEL vpcsim.image=runtime
