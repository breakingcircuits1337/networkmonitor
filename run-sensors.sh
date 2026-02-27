#!/bin/bash
# run-sensor.sh - Run sensors on host (not in Docker for better permissions)
# Run this on your Kali VM to start sensors locally

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== BCs_NetSec Sensor Runner ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Warning: Some sensors need root (scapy, iptables)"
    echo "Run with: sudo $0"
    echo ""
fi

# Install dependencies
echo "[1/4] Checking Python dependencies..."
pip3 install --user kafka-python python-nmap scapy watchdog neo4j 2>/dev/null

# Export vars
export KAFKA_BOOTSTRAP="localhost:9092"
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="neo4jpassword"

echo "[2/4] Starting sensors..."

# Start traffic analyzer in background
echo "  - Traffic Analyzer (Ctrl+C to stop)"
python3 "$SCRIPT_DIR/scripts/traffic-analyzer.py" &

# Start asset discovery in background
echo "  - Asset Discovery (runs every 15 min)"
python3 "$SCRIPT_DIR/scripts/asset-discovery.py" &

echo "[3/4] Starting alert processors..."

# Start alert forwarder in background
echo "  - IDS Alert Forwarder"
python3 "$SCRIPT_DIR/scripts/ids-alert-forwarder.py" &

# Start Neo4j sink in background
echo "  - Alert Sink to Neo4j"
python3 "$SCRIPT_DIR/scripts/alert-sink-neo4j.py" &

echo "[4/4] All sensors running!"
echo ""
echo "Services:"
echo "  Kafka:    localhost:9092"
echo "  Neo4j:    localhost:7474 (neo4j/neo4jpassword)"
echo "  Kafka UI: localhost:8080"
echo ""
echo "Press Ctrl+C to stop all sensors"

wait
