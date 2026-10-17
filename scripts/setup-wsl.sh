#!/usr/bin/env bash
# One-time host setup for the platform inside WSL2 (Ubuntu 24.04).
# Installs Docker Engine (native, not Docker Desktop), Go, and the
# networking userland vpcsim relies on. Run with: sudo bash scripts/setup-wsl.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "run as root: sudo bash $0" >&2
  exit 1
fi

TARGET_USER="${SUDO_USER:-$(logname)}"

echo "==> networking userland"
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg iproute2 nftables conntrack tcpdump jq unzip

echo "==> kernel modules"
modprobe vrf
echo vrf > /etc/modules-load.d/vpcsim.conf

echo "==> docker engine"
if [[ -L /usr/bin/docker ]] && readlink /usr/bin/docker | grep -qi 'docker desktop\|/mnt/wsl'; then
  echo "Docker Desktop WSL integration is enabled for this distro." >&2
  echo "Disable it in Docker Desktop > Settings > Resources > WSL integration, then re-run." >&2
  exit 1
fi
if ! command -v dockerd >/dev/null; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker
usermod -aG docker "$TARGET_USER"

echo "==> go"
GO_VERSION="$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -1)"
if [[ "$(/usr/local/go/bin/go version 2>/dev/null | awk '{print $3}')" != "$GO_VERSION" ]]; then
  curl -fsSL "https://go.dev/dl/${GO_VERSION}.linux-$(dpkg --print-architecture).tar.gz" -o /tmp/go.tgz
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tgz
  rm /tmp/go.tgz
fi
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' > /etc/profile.d/go.sh

echo "==> done"
docker --version
/usr/local/go/bin/go version
echo "Open a new WSL shell (or run 'wsl --shutdown' from Windows) so the docker group membership applies."
