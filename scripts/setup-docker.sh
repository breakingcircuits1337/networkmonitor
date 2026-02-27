#!/bin/bash
# setup-docker-no-root.sh - Setup Docker without sudo issues

echo "=== BCs_NetSec Docker Setup ==="
echo ""

# Check if user is in docker group
if groups | grep -q docker; then
    echo "✓ You are in the docker group"
else
    echo "[*] Adding user to docker group..."
    echo "987654321" | sudo -S usermod -aG docker $USER
    echo "✓ Added to docker group"
    echo "⚠️  Log out and back in for changes to take effect"
fi

# Create networkmonitor dir
mkdir -p ~/networkmonitor

# Copy compose file if not exists
if [ ! -f ~/networkmonitor/docker-compose.yml ]; then
    echo "[*] Downloading docker-compose.yml..."
    curl -fsSL https://raw.githubusercontent.com/Hackers6thsense/networkmonitor1/main/docker-compose.yml -o ~/networkmonitor/docker-compose.yml
fi

# Pull images (no sudo needed if in docker group)
echo ""
echo "[*] Pulling Docker images (this may take a while)..."
docker compose -f ~/networkmonitor/docker-compose.yml pull

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To start the stack:"
echo "  cd ~/networkmonitor"
echo "  docker compose up -d"
echo ""
echo "To view logs:"
echo "  docker compose logs -f"
