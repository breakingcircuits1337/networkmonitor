#!/usr/bin/env python3
"""
IDS Alert Forwarder - Monitors Suricata eve.json and forwards alerts to Kafka
"""
import json
import os
from kafka import KafkaProducer
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
EVE_FILE = os.getenv("EVE_FILE", "/var/log/suricata/eve.json")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "security.alerts")

print(f"Starting IDS Alert Forwarder: {EVE_FILE} -> Kafka {KAFKA_BOOTSTRAP}")

producer = KafkaProducer(
    bootstrap_servers=KAFKA_BOOTSTRAP,
    value_serializer=lambda v: json.dumps(v).encode()
)

class EveHandler(FileSystemEventHandler):
    def __init__(self):
        self.position = 0
        
    def on_modified(self, event):
        if event.src_path.endswith('eve.json'):
            try:
                with open(event.src_path) as f:
                    f.seek(self.position)
                    for line in f:
                        try:
                            alert = json.loads(line)
                            if alert.get('event_type') == 'alert':
                                print(f"Alert: {alert.get('alert', {}).get('signature', 'Unknown')}")
                                producer.send(KAFKA_TOPIC, alert)
                        except: pass
                    self.position = f.tell()
            except: pass

handler = EveHandler()
observer = Observer()
observer.schedule(handler, os.path.dirname(EVE_FILE), recursive=False)
observer.start()

print("Watching for IDS alerts...")
import time
while True:
    time.sleep(1)
