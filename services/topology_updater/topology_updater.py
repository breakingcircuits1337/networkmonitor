import signal
import sys
import os
import json
import logging
from kafka import KafkaConsumer
from neo4j import GraphDatabase
from common.config import get_env

import threading

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("topology_updater")

def ensure_constraint(driver):
    # Neo4j 5.x syntax: CREATE CONSTRAINT IF NOT EXISTS FOR (a:Asset) REQUIRE a.ip IS UNIQUE;
    cypher = """
    CREATE CONSTRAINT IF NOT EXISTS
    FOR (a:Asset)
    REQUIRE a.ip IS UNIQUE
    """
    with driver.session() as session:
        session.execute_write(lambda tx: tx.run(cypher))
    logger.info("Ensured uniqueness constraint on :Asset(ip)")

def upsert_asset(tx, asset):
    cypher = """
    MERGE (a:Asset {ip: $ip})
    ON CREATE SET a.created_at = $ts
    SET a.last_seen = $ts,
        a.mac = $mac,
        a.hostname = $hostname,
        a.ports = $ports
    """
    tx.run(
        cypher,
        ip=asset["ip"],
        ts=asset["timestamp"],
        mac=asset.get("mac"),
        hostname=asset.get("hostname"),
        ports=asset.get("ports", [])
    )

def main():
    kafka_bootstrap = get_env("KAFKA_BOOTSTRAP", "kafka:9092")
    kafka_topic = get_env("KAFKA_TOPIC", "asset.discovery")
    group_id = "topology-updater"

    neo4j_uri = get_env("NEO4J_URI", "bolt://neo4j:7687")
    neo4j_user = get_env("NEO4J_USER", "neo4j")
    neo4j_password = get_env("NEO4J_PASSWORD", "neo4jpassword")

    logger.info(f"Starting Topology Updater Service")
    logger.info(f"Config: KAFKA_BOOTSTRAP={kafka_bootstrap} KAFKA_TOPIC={kafka_topic} NEO4J_URI={neo4j_uri}")

    consumer = KafkaConsumer(
        kafka_topic,
        bootstrap_servers=kafka_bootstrap,
        group_id=group_id,
        auto_offset_reset='earliest',
        value_deserializer=lambda v: json.loads(v.decode('utf-8')),
        enable_auto_commit=True,
        consumer_timeout_ms=10000  # exit poll every 10s to check shutdown
    )

    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    ensure_constraint(driver)

    stop_event = threading.Event()

    def sigterm_handler(sig, frame):
        logger.info("Received SIGTERM, shutting down gracefully...")
        stop_event.set()
    signal.signal(signal.SIGTERM, sigterm_handler)

    try:
        logger.info("Consuming asset records from Kafka...")
        while not stop_event.is_set():
            for message in consumer:
                asset = message.value
                logger.info(f"Updating asset: {asset.get('ip')} ({asset.get('hostname')}) ports={len(asset.get('ports', []))}")
                try:
                    with driver.session() as session:
                        session.execute_write(upsert_asset, asset)
                except Exception as e:
                    logger.error(f"Failed to update asset in Neo4j: {e}")
                if stop_event.is_set():
                    break
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        consumer.close()
        driver.close()
        logger.info("Topology Updater service stopped.")

if __name__ == "__main__":
    main()