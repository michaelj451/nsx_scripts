#!/usr/bin/env bash
set -e

echo "=== Ubuntu Docker bootstrap starting ==="

# 1. Update system
sudo apt update && sudo apt upgrade -y

# 2. Install prerequisites
sudo apt install -y ca-certificates curl gnupg lsb-release

# 3. Add Docker GPG key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# 4. Add Docker repository
echo \
"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu \
$(lsb_release -cs) stable" \
| sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# 5. Install Docker + Compose plugin
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# 6. Enable Docker
sudo systemctl enable docker
sudo systemctl start docker

# 7. Allow current user to run docker
sudo usermod -aG docker $USER
newgrp docker <<EOF
echo "Docker group applied"
EOF

# 8. Verify
docker --version
docker compose version

echo "=== Ubuntu Docker bootstrap complete ==="
echo "Log out/in if docker group didn’t apply automatically"