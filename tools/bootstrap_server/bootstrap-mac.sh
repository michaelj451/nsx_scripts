#!/usr/bin/env bash
set -e

echo "=== macOS Docker bootstrap starting ==="

# 1. Install Homebrew (if missing)
if ! command -v brew >/dev/null 2>&1; then
  echo "Installing Homebrew..."
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# 2. Install Docker Desktop
if ! command -v docker >/dev/null 2>&1; then
  echo "Installing Docker Desktop..."
  brew install --cask docker
fi

# 3. Start Docker
echo "Starting Docker..."
open -a Docker

echo "Waiting for Docker to be ready..."
until docker info >/dev/null 2>&1; do
  sleep 2
done

# 4. Verify
docker --version
docker compose version

echo "=== macOS Docker bootstrap complete ==="
echo "You can now run: docker compose up --build"