import os
import json
import logging
import signal
import uuid
from datetime import datetime
from kafka import KafkaConsumer
from neo4j import GraphDatabase
from common.config import get_env

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("alert_sink_neo4j")

def ensure_constraints(driver):
    cypher = """
    CREATE CONSTRAINT IF NOT EXISTS
    FOR (al:Alert)
    REQUIRE al.id IS UNIQUE
    """
    with driver.session() as session:
        session.execute_write(lambda tx: tx.run(cypher))
    logger.info("Ensured uniqueness constraint on :Alert(id)")

def create_alert(tx, alert):
    cypher = """
    MERGE (src:Asset {ip: $src_ip})
    ON CREATE SET src.created_at = timestamp()
    WITH src
    CREATE (al:Alert {
        id: $id,
        signature: $sig,
        category: $cat,
        severity: $sev,
        timestamp: $ts
    })
    MERGE (src)-[:TRIGGERED]->(al)
    """
    params = {
        "id": alert["id"],
        "src_ip": alert["src_ip"],
        "sig": alert.get("signature"),
        "cat": alert.get("category"),
        "sev": alert.get("severity"),
        "ts": alert["timestamp"]
    }
    tx.run(cypher, **params)
    # If dest_ip present, relate alert to target asset
    if alert.get("dest_ip"):
        cypher2 = """
        MERGE (dest:Asset {ip: $dest_ip})
        ON CREATE SET dest.created_at = timestamp()
        WITH dest
        MATCH (al:Alert {id: $id})
        MERGE (al)-[:TARGETS]->(dest)
        """
        tx.run(cypher2, dest_ip=alert["dest_ip"], id=alert["id"])

def isoformat(ts=None):
    return datetime.utcfromtimestamp(ts or datetime.utcnow().timestamp()).isoformat() + "Z"

def main():
    kafka_bootstrap = get_env("KAFKA_BOOTSTRAP", "kafka:9092")
    kafka_topic = get_env("KAFKA_TOPIC", "alert.correlated")
    neo4j_uri = get_env("NEO4J_URI", "bolt://neo4j:7687")
    neo4j_user = get_env("NEO4J_USER", "neo4j")
    neo4j_password = get_env("NEO4J_PASSWORD", "neo4jpassword")
    group_id = "neo4j-alert-sink"

    logger.info(f"Starting Alert Sink Neo4j Service")
    logger.info(f"Config: KAFKA_BOOTSTRAP={kafka_bootstrap} KAFKA_TOPIC={kafka_topic} NEO4J_URI={neo4j_uri}")

    consumer = KafkaConsumer(
        kafka_topic,
        bootstrap_servers=kafka_bootstrap,
        group_id=group_id,
        auto_offset_reset='earliest',
        value_deserializer=lambda v: json.loads(v.decode('utf-8')),
        enable_auto_commit=True,
        consumer_timeout_ms=10000
    )

    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    ensure_constraints(driver)

    stop_flag = {"stop": False}
    def handle_sigterm(sig, frame):
        logger.info("Received SIGTERM, shutting down gracefully...")
        stop_flag["stop"] = True
    signal.signal(signal.SIGTERM, handle_sigterm)

    count = 0
    try:
        while not stop_flag["stop"]:
            for msg in consumer:
                alert = msg.value
                alert_id = str(uuid.uuid4())
                # Use event timestamp if present, else now
                ts = alert.get("timestamp") or isoformat()
                alert_db = {
                    "id": alert_id,
                    "src_ip": alert.get("src_ip"),
                    "dest_ip": alert.get("dest_ip"),
                    "signature": alert.get("signature"),
                    "category": alert.get("category"),
                    "severity": alert.get("severity"),
                    "timestamp": ts,
                }
                try:
                    with driver.session() as session:
                        session.execute_write(create_alert, alert_db)
                    count += 1
                    if count % 100 == 0:
                        logger.info(f"Ingested {count} alerts into Neo4j")
                except Exception as e:
                    logger.error(f"Failed to write alert to Neo4j: {e}")
                if stop_flag["stop"]:
                    break
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received, exiting...")
    finally:
        consumer.close()
        driver.close()
        logger.info("Alert Sink Neo4j service stopped.")

if __name__ == "__main__":
    main()