import os
import time
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from scapy.all import IP, ICMP, UDP, TCP, Raw, send, RandShort
from common.config import get_env
import threading
import json

app = Flask(__name__)
CORS(app)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("packet_launcher")

ENABLE = get_env("ENABLE_PACKET_LAUNCHER", "false").lower() == "true"
LAUNCH_TOKEN = get_env("LAUNCH_TOKEN", None)
KAFKA_BOOTSTRAP = get_env("KAFKA_BOOTSTRAP", None)
AUDIT_TOPIC = "packet.launch.audit"

# Kafka producer (lazy)
producer = None
if KAFKA_BOOTSTRAP:
    try:
        from kafka import KafkaProducer
        producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            retries=3
        )
    except Exception as e:
        logger.warning(f"Kafka unavailable: {e}")

def launch_worker(ip, proto, size, rate, count):
    pkt = None
    size = min(size, 1500)
    payload = b"X" * max(0, size)
    if proto == "ICMP":
        pkt = IP(dst=ip)/ICMP()/payload
    elif proto == "UDP":
        pkt = IP(dst=ip)/UDP(dport=RandShort())/Raw(payload)
    elif proto == "TCP":
        pkt = IP(dst=ip)/TCP(dport=80, flags="S")/Raw(payload)
    else:
        logger.warning(f"Unknown protocol: {proto}")
        return

    sleep_time = 1.0 / max(rate, 1)
    for i in range(count):
        send(pkt, verbose=False)
        if i < count - 1:
            time.sleep(sleep_time)
    logger.info(f"Launched {count} {proto} packets of size {size} to {ip} at {rate} pps.")

@app.route("/launch", methods=["POST"])
def launch():
    if not ENABLE:
        return jsonify({"error": "Packet launching is disabled."}), 403
    if LAUNCH_TOKEN:
        if request.headers.get("X-Token") != LAUNCH_TOKEN:
            return jsonify({"error": "Invalid token"}), 403
    try:
        data = request.get_json(force=True)
        ip = data.get("ip", "")
        proto = data.get("protocol", "").upper()
        size = int(data.get("size", 64))
        rate = int(data.get("rate", 1))
        count = int(data.get("count", 1))
        # Basic validations
        if proto not in ("ICMP", "UDP", "TCP"):
            return jsonify({"error": "Protocol must be ICMP, UDP, or TCP"}), 400
        if not ip or len(ip) > 50:
            return jsonify({"error": "Invalid IP"}), 400
        if not (1 <= size <= 1500):
            return jsonify({"error": "Packet size must be 1-1500 bytes"}), 400
        if not (1 <= rate <= 100):
            return jsonify({"error": "Rate must be 1-100 pps"}), 400
        if not (1 <= count <= 1000):
            return jsonify({"error": "Count must be 1-1000"}), 400
        # Launch in background thread
        t = threading.Thread(target=launch_worker, args=(ip, proto, size, rate, count))
        t.daemon = True
        t.start()
        msg = f"Launch: {count} {proto} packets to {ip} (size={size}, rate={rate}pps)"
        logger.info(msg)
        # Audit to kafka
        if producer:
            audit_rec = {
                "ip": ip, "protocol": proto, "size": size, "rate": rate, "count": count,
                "user_agent": request.headers.get("User-Agent"),
                "remote_addr": request.remote_addr,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
            try:
                producer.send(AUDIT_TOPIC, audit_rec)
            except Exception as e:
                logger.warning(f"Failed to audit to Kafka: {e}")
        return jsonify({"result": "Packet launch triggered.", "detail": msg}), 200
    except Exception as e:
        logger.exception(f"Error in /launch: {e}")
        return jsonify({"error": str(e)}), 400

@app.route("/")
def index():
    return jsonify({
        "service": "packet_launcher",
        "enabled": ENABLE,
        "usage": "POST /launch {ip,protocol,size,rate,count} (see README)"
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000, threaded=True)