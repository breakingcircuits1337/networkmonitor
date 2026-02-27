#!/usr/bin/env python3
"""
Alert Sink to Neo4j - Consumes alerts from Kafka and writes to Neo4j graph
"""
import json
import os
from kafka import KafkaConsumer
from neo4j import GraphDatabase

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "security.alerts")
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "neo4jpassword")

print(f"Starting Alert Sink: Kafka {KAFKA_TOPIC} -> Neo4j {NEO4J_URI}")

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

consumer = KafkaConsumer(
    KAFKA_TOPIC,
    bootstrap_servers=KAFKA_BOOTSTRAP,
    value_deserializer=lambda m: json.loads(m.decode()),
    auto_offset_reset='earliest',
    group_id='alert-sink-neo4j'
)

def create_alert(tx, alert):
    src_ip = alert.get('src_ip', 'unknown')
    dest_ip = alert.get('dest_ip', 'unknown')
    signature = alert.get('alert', {}).get('signature', 'unknown')
    severity = alert.get('alert', {}).get('severity', 0)
    timestamp = alert.get('timestamp', '')
    
    tx.run("""
        MERGE (src:IP {address: $src_ip})
        MERGE (dest:IP {address: $dest_ip})
        CREATE (alert:Alert {
            signature: $signature,
            severity: $severity,
            timestamp: $timestamp
        })
        CREATE (src)-[:DETECTED]->(alert)
        CREATE (alert)-[:TARGETS]->(dest)
    """, src_ip=src_ip, dest_ip=dest_ip, signature=signature, severity=severity, timestamp=timestamp)

print("Listening for alerts...")
for message in consumer:
    alert = message.value
    print(f"Writing alert: {alert.get('alert', {}).get('signature', 'Unknown')}")
    with driver.session() as session:
        session.execute_write(create_alert, alert)
