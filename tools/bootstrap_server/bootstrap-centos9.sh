#!/usr/bin/env bash
set -euo pipefail

# CentOS 9 Stream bootstrap
# - installs Git
# - installs Docker CE
# - enables + starts Docker
# - adds invoking sudo user to docker group
#
# Run:
#   sudo bash bootstrap-dev-centos9.sh
#
# Optional env vars:
#   ADD_DOCKER_GROUP=1   # default 1
#   DOCKER_TEST=1        # default 1

ADD_DOCKER_GROUP="${ADD_DOCKER_GROUP:-1}"
DOCKER_TEST="${DOCKER_TEST:-1}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: run as root (use sudo)"
  exit 1
fi

TARGET_USER="${SUDO_USER:-root}"

echo "==> Target user: ${TARGET_USER}"

echo "==> Updating package metadata..."
dnf -y makecache

echo "==> Installing base dependencies..."
dnf -y install \
  git \
  dnf-utils \
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

echo "==> Installing Docker CE..."
dnf -y install docker-ce docker-ce-cli containerd.io

echo "==> Enabling and starting Docker..."
systemctl enable --now docker

if [[ "${ADD_DOCKER_GROUP}" == "1" && "${TARGET_USER}" != "root" ]]; then
  echo "==> Ensuring docker group exists..."
  getent group docker >/dev/null || groupadd docker

  echo "==> Adding ${TARGET_USER} to docker group..."
  usermod -aG docker "${TARGET_USER}"

  echo "NOTE: Log out/in or run 'newgrp docker' to apply group membership."
fi

echo "==> Docker version:"
docker --version

echo "==> Docker service status:"
systemctl --no-pager --full status docker | sed -n '1,12p' || true

if [[ "${DOCKER_TEST}" == "1" ]]; then
  echo "==> Testing Docker as root..."
  docker run --rm hello-world || true

  if [[ "${TARGET_USER}" != "root" ]]; then
    echo "==> Testing Docker as ${TARGET_USER}..."
    sudo -u "${TARGET_USER}" docker run --rm hello-world || true
  fi
fi

echo "==> Bootstrap complete."