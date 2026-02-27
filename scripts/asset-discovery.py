#!/usr/bin/env python3
"""
Asset Discovery - Scans network and sends assets to Kafka
"""
import json
import os
import time
import nmap
from kafka import KafkaProducer

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
NETWORK_RANGE = os.getenv("NETWORK_RANGE", "192.168.1.0/24")
INTERVAL = int(os.getenv("SCAN_INTERVAL_SECONDS", "900"))

print(f"Starting asset discovery on {NETWORK_RANGE} -> Kafka {KAFKA_BOOTSTRAP}")

producer = KafkaProducer(
    bootstrap_servers=KAFKA_BOOTSTRAP,
    value_serializer=lambda v: json.dumps(v).encode()
)

nm = nmap.PortScanner()

while True:
    print(f"Scanning {NETWORK_RANGE}...")
    nm.scan(hosts=NETWORK_RANGE, arguments="-sn")
    
    for host in nm.all_hosts():
        asset = {
            "ip": host,
            "hostname": nm[host].hostname(),
            "state": nm[host].state(),
            "mac": nm[host].get("addresses", {}).get("mac", "")
        }
        print(f"Found: {asset}")
        producer.send("asset.discovery", asset)
    
    time.sleep(INTERVAL)
