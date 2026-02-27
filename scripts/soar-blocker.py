#!/usr/bin/env python3
"""
SOAR Blocker - Auto-blocks malicious IPs based on IDS alerts
"""
import json
import os
import subprocess
from kafka import KafkaConsumer

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
IDS_TOPIC = os.getenv("IDS_TOPIC", "security.alerts")
SEVERITY_THRESHOLD = int(os.getenv("SEVERITY_THRESHOLD", "2"))

print(f"Starting SOAR Blocker: Kafka {IDS_TOPIC} -> iptables (severity >= {SEVERITY_THRESHOLD})")

consumer = KafkaConsumer(
    IDS_TOPIC,
    bootstrap_servers=KAFKA_BOOTSTRAP,
    value_deserializer=lambda m: json.loads(m.decode()),
    auto_offset_reset='earliest',
    group_id='soar-blocker'
)

blocked_ips = set()

for message in consumer:
    alert = message.value
    severity = alert.get('alert', {}).get('severity', 0)
    
    if severity >= SEVERITY_THRESHOLD:
        src_ip = alert.get('src_ip')
        if src_ip and src_ip not in blocked_ips:
            print(f"[ALERT] Blocking {src_ip} (severity: {severity})")
            try:
                subprocess.run(['iptables', '-A', 'INPUT', '-s', src_ip, '-j', 'DROP'], check=True)
                blocked_ips.add(src_ip)
                print(f"[BLOCKED] {src_ip}")
            except Exception as e:
                print(f"[ERROR] {e}")
