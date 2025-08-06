import os
import json
import logging
import signal
import threading
import queue
import time

from flask import Flask, Response
from flask_cors import CORS
from kafka import KafkaConsumer, KafkaProducer
import geoip2.database

from common.config import get_env

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("geoip_enricher")

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

event_queue = queue.Queue(maxsize=3000)
event_buffer = []
buffer_max = 2000

shutdown_event = threading.Event()

def geoip_lookup(ip, reader):
    try:
        resp = reader.city(ip)
        loc = resp.location
        country = resp.country.iso_code or ""
        lat = loc.latitude if loc and loc.latitude else None
        lon = loc.longitude if loc and loc.longitude else None
        return country, lat, lon
    except Exception:
        return None, None, None

def sse_stream():
    """Generator for Server-Sent Events"""
    while not shutdown_event.is_set():
        try:
            event = event_queue.get(timeout=1)
            yield f'data: {json.dumps(event)}\n\n'
        except queue.Empty:
            continue

@app.route('/events')
def events():
    return Response(sse_stream(), mimetype='text/event-stream')

def kafka_consumer_thread():
    kafka_bootstrap = get_env("KAFKA_BOOTSTRAP", "kafka:9092")
    in_topic = get_env("IN_TOPIC", "netflow")
    out_topic = get_env("OUT_TOPIC", "geo.flows")
    geoip_db = get_env("GEOIP_DB", "/geoip/GeoLite2-City.mmdb")

    group_id = "geoip-enricher"
    log_interval = 500
    msg_count = 0

    producer = KafkaProducer(
        bootstrap_servers=kafka_bootstrap,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        retries=5
    )
    consumer = KafkaConsumer(
        in_topic,
        bootstrap_servers=kafka_bootstrap,
        group_id=group_id,
        auto_offset_reset='earliest',
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        enable_auto_commit=True,
        consumer_timeout_ms=10000
    )

    try:
        reader = geoip2.database.Reader(geoip_db)
    except Exception as e:
        logger.error(f"GeoIP DB load error: {e}")
        return

    global event_buffer
    try:
        while not shutdown_event.is_set():
            for msg in consumer:
                ev = msg.value
                src_ip = ev.get("src_ip")
                dst_ip = ev.get("dst_ip")
                bytes_ = ev.get("bytes")
                timestamp = ev.get("first_seen") or ev.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                country, lat, lon = geoip_lookup(src_ip, reader)
                if lat is not None and lon is not None:
                    geo_event = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "bytes": bytes_,
                        "country": country,
                        "lat": lat,
                        "lon": lon,
                        "timestamp": timestamp
                    }
                    # Produce to Kafka
                    producer.send(out_topic, geo_event)
                    # SSE - push to buffer and queue
                    event_buffer.append(geo_event)
                    if len(event_buffer) > buffer_max:
                        event_buffer = event_buffer[-buffer_max:]
                    # Non-blocking put (drop if queue full)
                    try:
                        event_queue.put_nowait(geo_event)
                    except queue.Full:
                        pass
                    msg_count += 1
                    if msg_count % log_interval == 0:
                        logger.info(f"GeoIP-enriched {msg_count} flow events")
                if shutdown_event.is_set():
                    break
    except Exception as e:
        logger.error(f"Error in Kafka/GeoIP loop: {e}")
    finally:
        consumer.close()
        producer.close()
        reader.close()
        logger.info("GeoIP enricher stopped.")

def run_flask():
    http_port = int(get_env("HTTP_PORT", 5000))
    logger.info(f"Starting Flask SSE server on port {http_port}")
    app.run(host="0.0.0.0", port=http_port, threaded=True)

def main():
    # SIGTERM handling
    def handle_sigterm(sig, frame):
        logger.info("Received SIGTERM, shutting down...")
        shutdown_event.set()
    signal.signal(signal.SIGTERM, handle_sigterm)

    t1 = threading.Thread(target=kafka_consumer_thread, daemon=True)
    t1.start()
    try:
        run_flask()
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received, shutting down...")
        shutdown_event.set()
    t1.join()

if __name__ == "__main__":
    main()