#!/bin/bash
# Ollama Installation & Setup for NetworkMonitor

echo "🤖 Installing Ollama..."

# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama service
echo "▶️ Starting Ollama..."
ollama serve &
sleep 3

# Primary model: aratan/Ministral-3-14B-Reasoning-2512 — reasoning-tuned Mistral 3B
echo "📥 Pulling aratan/Ministral-3-14B-Reasoning-2512..."
ollama pull aratan/Ministral-3-14B-Reasoning-2512

# Fallback model: qwen2.5:7b — excellent JSON output for batch analysis
echo "📥 Pulling qwen2.5:7b (fallback, ~5.2GB)..."
ollama pull qwen2.5:7b

echo ""
echo "✅ Ollama ready!"
echo "   Test: ollama run aratan/Ministral-3-14B-Reasoning-2512 'Hello'"
echo ""
echo "📡 To connect from Docker, use: http://host.docker.internal:11434"
