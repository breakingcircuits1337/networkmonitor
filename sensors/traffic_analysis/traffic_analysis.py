import os
import time
import signal
import json
import logging
from datetime import datetime
from threading import Event, Thread

from scapy.all import sniff, IP, TCP, UDP
from kafka import KafkaProducer

from common.config import get_env

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("traffic_analysis")

# Flow key: (src_ip, dst_ip, src_port, dst_port, protocol)
flows = {}
flows_lock = Event()  # Not a lock, just an exit event
shutdown_event = Event()

def isoformat(ts):
    return datetime.utcfromtimestamp(ts).isoformat() + "Z"

def packet_handler(pkt):
    # Only handle IP packets with TCP/UDP
    if not IP in pkt:
        return
    ip = pkt[IP]
    proto = ip.proto
    src_ip = ip.src
    dst_ip = ip.dst
    src_port, dst_port = 0, 0
    if proto == 6 and TCP in pkt:  # TCP
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif proto == 17 and UDP in pkt:  # UDP
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    else:
        # Ignore non-TCP/UDP
        return

    key = (src_ip, dst_ip, src_port, dst_port, proto)
    pkt_len = len(pkt)
    now = time.time()
    f = flows.get(key)
    if f:
        f["packets"] += 1
        f["bytes"] += pkt_len
        f["last_seen"] = now
    else:
        flows[key] = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "bytes": pkt_len,
            "packets": 1,
            "first_seen": now,
            "last_seen": now,
        }

def flush_flows(producer, topic):
    global flows
    count = 0
    for flow in flows.values():
        record = {
            "src_ip": flow["src_ip"],
            "dst_ip": flow["dst_ip"],
            "src_port": flow["src_port"],
            "dst_port": flow["dst_port"],
            "protocol": flow["protocol"],
            "bytes": flow["bytes"],
            "packets": flow["packets"],
            "first_seen": isoformat(flow["first_seen"]),
            "last_seen": isoformat(flow["last_seen"]),
        }
        producer.send(topic, record)
        count += 1
    producer.flush()
    logger.info(f"Flushed {count} flow records to Kafka topic '{topic}'")
    flows = {}

def periodic_flusher(producer, topic, window_seconds):
    while not shutdown_event.is_set():
        time.sleep(window_seconds)
        flush_flows(producer, topic)

def main():
    interface = get_env("INTERFACE", "eth0")
    flow_window = int(get_env("FLOW_WINDOW_SECONDS", 30))
    kafka_bootstrap = get_env("KAFKA_BOOTSTRAP", "kafka:9092")
    kafka_topic = get_env("KAFKA_TOPIC", "netflow")

    logger.info(f"Starting Traffic Analysis Sensor")
    logger.info(f"Config: INTERFACE={interface} FLOW_WINDOW_SECONDS={flow_window} KAFKA_BOOTSTRAP={kafka_bootstrap} KAFKA_TOPIC={kafka_topic}")

    producer = KafkaProducer(
        bootstrap_servers=kafka_bootstrap,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        retries=5
    )

    def handle_sigterm(signum, frame):
        logger.info("Received SIGTERM, flushing flows and shutting down...")
        shutdown_event.set()

    signal.signal(signal.SIGTERM, handle_sigterm)

    flusher_thread = Thread(target=periodic_flusher, args=(producer, kafka_topic, flow_window), daemon=True)
    flusher_thread.start()

    try:
        sniff(
            iface=interface,
            prn=packet_handler,
            store=False,
            stop_filter=lambda x: shutdown_event.is_set()
        )
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received, shutting down...")
        shutdown_event.set()
    finally:
        flush_flows(producer, kafka_topic)
        logger.info("Traffic Analysis Sensor stopped.")

if __name__ == "__main__":
    main()