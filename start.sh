#!/bin/bash
# NetworkMonitor Startup Script
# Run this after VM resize and Ollama install

set -e

echo "🚀 Starting NetworkMonitor Stack..."

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found!"
    exit 1
fi

# Pull latest images and rebuild
cd /home/sarah/networkmonitor

echo "📦 Building and starting services..."
docker-compose up --build -d

# Wait for services
echo "⏳ Waiting for services..."
sleep 10

# Check status
echo ""
echo "📊 Service Status:"
docker ps --format "table {{.Names}}\t{{.Status}}"

HOST_IP=$(hostname -I | awk '{print $1}')

echo ""
echo "🌐 Access Points:"
echo "   UI Dashboard:     http://${HOST_IP}:8080"
echo "   Neo4j Browser:   http://${HOST_IP}:7474"
echo "   Sarah API:       http://${HOST_IP}:5000"
echo ""
echo "🔧 Ollama (on host):"
echo "   Install:         curl -fsSL https://ollama.com/install.sh | sh"
echo "   Start model:     ollama run llama3.2"
echo ""
echo "✅ Done!"
