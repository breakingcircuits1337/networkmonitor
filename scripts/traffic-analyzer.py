#!/usr/bin/env python3
"""
Traffic Analyzer - Sends network flow data to Kafka
"""
import json
import os
from kafka import KafkaProducer
from scapy.all import *

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
INTERFACE = os.getenv("INTERFACE", "eth0")

print(f"Starting traffic analyzer on {INTERFACE} -> Kafka {KAFKA_BOOTSTRAP}")

producer = KafkaProducer(
    bootstrap_servers=KAFKA_BOOTSTRAP,
    value_serializer=lambda v: json.dumps(v).encode()
)

def pkt_handler(pkt):
    if pkt.haslayer(IP):
        flow = {
            "src": pkt[IP].src,
            "dst": pkt[IP].dst,
            "proto": pkt[IP].proto,
            "len": pkt[IP].len,
            "ttl": pkt[IP].ttl
        }
        producer.send("netflow", flow)

sniff(iface=INTERFACE, prn=pkt_handler, store=0)
