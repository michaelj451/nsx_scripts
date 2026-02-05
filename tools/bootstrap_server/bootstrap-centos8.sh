#!/usr/bin/env bash
set -euo pipefail

# CentOS 8 - Bootstrap Git + Docker CE
# - switches CentOS 8 repos to vault.centos.org (CentOS 8 is EOL)
# - forces HTTPS to avoid HTTP blocks / resets
# - installs git + deps
# - adds Docker CE repo
# - installs docker-ce, docker-ce-cli, containerd.io (uses --allowerasing for podman/buildah/runc conflicts)
# - enables + starts docker
# - (optional) adds your sudo user to docker group
#
# Run:
#   sudo bash bootstrap-centos8.sh
#
# Optional env vars:
#   FIX_CENTOS8_REPOS=1   # default 1
#   ADD_DOCKER_GROUP=1    # default 1
#   DOCKER_TEST=1         # default 1

FIX_CENTOS8_REPOS="${FIX_CENTOS8_REPOS:-1}"
ADD_DOCKER_GROUP="${ADD_DOCKER_GROUP:-1}"
DOCKER_TEST="${DOCKER_TEST:-1}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: run as root (use sudo)"
  exit 1
fi

TARGET_USER="${SUDO_USER:-root}"
echo "==> Target user: ${TARGET_USER}"

# --- CentOS 8 EOL repo fix (vault + https) ---
if [[ "${FIX_CENTOS8_REPOS}" == "1" ]]; then
  echo "==> Ensuring CentOS 8 repos use vault.centos.org over HTTPS..."
  # Comment mirrorlist= lines
  sed -i 's|^mirrorlist=|#mirrorlist=|g' /etc/yum.repos.d/CentOS-*.repo || true
  # Switch baseurl to vault (if present as mirror.centos.org) and force https
  sed -i 's|^#baseurl=http://mirror.centos.org|baseurl=https://vault.centos.org|g' /etc/yum.repos.d/CentOS-*.repo || true
  sed -i 's|^baseurl=http://mirror.centos.org|baseurl=https://vault.centos.org|g' /etc/yum.repos.d/CentOS-*.repo || true
  sed -i 's|http://vault.centos.org|https://vault.centos.org|g' /etc/yum.repos.d/CentOS-*.repo || true

  echo "==> Cleaning DNF cache..."
  dnf -y clean all || true
fi

echo "==> Updating package metadata..."
dnf -y makecache

echo "==> Installing base dependencies (git + tooling)..."
dnf -y install \
  git \
  yum-utils \
  device-mapper-persistent-data \
  lvm2 \
  ca-certificates \
  curl

echo "==> Git version:"
git --version

echo "==> Adding Docker CE repo (if missing)..."
if ! dnf repolist | awk '{print $1}' | grep -qx 'docker-ce-stable'; then
  dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
fi

echo "==> Installing Docker CE (using --allowerasing to resolve podman/buildah/runc conflicts on CentOS 8)..."
dnf -y install docker-ce docker-ce-cli containerd.io --allowerasing

echo "==> Enabling and starting Docker..."
systemctl enable --now docker

if [[ "${ADD_DOCKER_GROUP}" == "1" && "${TARGET_USER}" != "root" ]]; then
  echo "==> Ensuring docker group exists..."
  getent group docker >/dev/null || groupadd docker

  echo "==> Adding '${TARGET_USER}' to docker group..."
  usermod -aG docker "${TARGET_USER}"

  echo "NOTE: Log out/in or run 'newgrp docker' for group membership to apply."
fi

echo "==> Docker installed:"
docker --version
systemctl --no-pager --full status docker | sed -n '1,12p' || true

if [[ "${DOCKER_TEST}" == "1" ]]; then
  echo "==> Testing Docker as root..."
  docker run --rm hello-world || true

  if [[ "${TARGET_USER}" != "root" ]]; then
    echo "==> Testing Docker as ${TARGET_USER} (may require newgrp/logout-login first)..."
    sudo -u "${TARGET_USER}" docker run --rm hello-world || true
  fi
fi

echo "==> Done."