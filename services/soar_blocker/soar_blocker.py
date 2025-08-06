import os
import time
import json
import logging
import subprocess
from datetime import datetime, timedelta

from kafka import KafkaConsumer, KafkaProducer, TopicPartition
from common.config import get_env

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("soar_blocker")

def now():
    return time.time()

def main():
    kafka_bootstrap = get_env("KAFKA_BOOTSTRAP", "kafka:9092")
    ids_topic = get_env("IDS_TOPIC", "security.alerts")
    ueba_topic = get_env("UEBA_TOPIC", "ueba.alerts")
    severity_threshold = float(get_env("SEVERITY_THRESHOLD", 2))
    anomaly_threshold = float(get_env("ANOMALY_THRESHOLD", 0.5))
    blocklist_cmd = get_env("BLOCKLIST_CMD", "echo blocking {ip}")
    check_interval = int(get_env("CHECK_INTERVAL", 300))
    blocklist_topic = "blocklist.actions"

    # { src_ip: (score, expiry_time) }
    anomaly_scores = {}
    blocked = set()

    producer = KafkaProducer(
        bootstrap_servers=kafka_bootstrap,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        retries=2
    )

    topics = [ids_topic]
    if ueba_topic:
        topics.append(ueba_topic)
    consumer = KafkaConsumer(
        *topics,
        bootstrap_servers=kafka_bootstrap,
        group_id="soar-blocker",
        auto_offset_reset='earliest',
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        enable_auto_commit=True,
        consumer_timeout_ms=10000
    )

    ttl_sec = 600  # anomaly score valid for 10 min

    last_check = now()
    logger.info(f"SOAR Blocker starting: IDS_TOPIC={ids_topic} UEBA_TOPIC={ueba_topic} THRESHOLDS: severity>={severity_threshold}, anomaly>={anomaly_threshold}")

    try:
        while True:
            # Clean up expired anomaly scores every check_interval
            if now() - last_check > check_interval:
                cutoff = now() - ttl_sec
                anomaly_scores = {ip: (score, exp) for ip, (score, exp) in anomaly_scores.items() if exp > cutoff}
                last_check = now()
            for msg in consumer:
                topic = msg.topic
                val = msg.value
                # UEBA anomaly score
                if topic == ueba_topic:
                    ip = val.get("ip") or val.get("src_ip")
                    score = float(val.get("score", 1))
                    if ip:
                        anomaly_scores[ip] = (score, now() + ttl_sec)
                        logger.debug(f"Set anomaly score {score} for {ip}")
                # IDS alert
                elif topic == ids_topic:
                    src_ip = val.get("src_ip")
                    severity = float(val.get("severity", 0))
                    if not src_ip:
                        continue
                    score, exp = anomaly_scores.get(src_ip, (1, now() + ttl_sec))
                    if severity >= severity_threshold and score >= anomaly_threshold and src_ip not in blocked:
                        # Block it!
                        cmd = blocklist_cmd.format(ip=src_ip)
                        try:
                            subprocess.run(cmd, shell=True, check=True)
                            logger.info(f"Blocked {src_ip} (severity={severity}, anomaly={score}) CMD: {cmd}")
                        except Exception as e:
                            logger.error(f"Blocklist command failed for {src_ip}: {e}")
                        blocked.add(src_ip)
                        # Produce to blocklist.actions
                        try:
                            producer.send(blocklist_topic, {
                                "ip": src_ip,
                                "severity": severity,
                                "anomaly_score": score,
                                "timestamp": datetime.utcnow().isoformat() + "Z",
                                "cmd": cmd
                            })
                        except Exception as e:
                            logger.warning(f"Failed to produce blocklist action: {e}")
                if now() - last_check > check_interval:
                    break
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received, shutting down...")
    finally:
        consumer.close()
        producer.close()
        logger.info("SOAR Blocker stopped.")

if __name__ == "__main__":
    main()