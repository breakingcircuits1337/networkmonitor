import os
import time
import json
import logging
from kafka import KafkaProducer
from common.config import get_env

import signal

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("ids_alert_forwarder")

def tail_f(path, stop_event):
    # Open file and seek to end, but handle file rotation
    with open(path, 'r') as f:
        f.seek(0, os.SEEK_END)
        while not stop_event.is_set():
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line

def main():
    eve_file = get_env("EVE_FILE", "/var/log/suricata/eve.json")
    kafka_bootstrap = get_env("KAFKA_BOOTSTRAP", "kafka:9092")
    kafka_topic = get_env("KAFKA_TOPIC", "security.alerts")
    log_interval = 50
    alert_count = 0

    logger.info(f"Starting IDS Alert Forwarder")
    logger.info(f"Config: EVE_FILE={eve_file} KAFKA_BOOTSTRAP={kafka_bootstrap} KAFKA_TOPIC={kafka_topic}")

    producer = KafkaProducer(
        bootstrap_servers=kafka_bootstrap,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        retries=5
    )

    stop_event = False
    def handle_sigterm(sig, frame):
        nonlocal stop_event
        stop_event = True
        logger.info("Received SIGTERM, shutting down...")

    signal.signal(signal.SIGTERM, handle_sigterm)

    try:
        for line in tail_f(eve_file, lambda: stop_event):
            try:
                data = json.loads(line)
                if data.get("event_type") in ("alert", "anomaly", "http", "dns"):
                    producer.send(kafka_topic, data)
                    alert_count += 1
                    if alert_count % log_interval == 0:
                        logger.info(f"Forwarded {alert_count} IDS alerts to Kafka")
            except Exception as e:
                logger.warning(f"Failed to parse/forward EVE line: {e}")
            if stop_event:
                break
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received, shutting down...")
    except FileNotFoundError:
        logger.error(f"EVE file not found: {eve_file}")
    finally:
        logger.info("IDS Alert Forwarder stopped.")

if __name__ == "__main__":
    main()