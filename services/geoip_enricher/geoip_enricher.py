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

# Per-client SSE queues — each connected browser tab gets its own queue
# so all clients receive every event (no queue.get() stealing).
_sse_clients: list = []
_sse_lock = threading.Lock()

event_buffer = []
buffer_max = 2000

shutdown_event = threading.Event()


def _broadcast(geo_event):
    """Push event to every connected SSE client queue; prune disconnected clients."""
    payload = json.dumps(geo_event)
    with _sse_lock:
        alive = []
        for q in _sse_clients:
            try:
                q.put_nowait(payload)
            except queue.Full:
                # Client queue full (slow consumer) — skip this event for them
                # but keep the connection alive; they'll resume on next event
                pass
            alive.append(q)
        _sse_clients[:] = alive

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
    """Generator for Server-Sent Events — replay buffer then stream live.

    Each call creates a dedicated per-client queue so every SSE consumer
    (globe + chat widget) receives every event independently.
    """
    client_q: queue.Queue = queue.Queue(maxsize=500)
    with _sse_lock:
        _sse_clients.append(client_q)

    try:
        # Replay recent history so new tabs see existing data immediately
        for event in list(event_buffer):
            yield f'data: {json.dumps(event)}\n\n'

        # Stream live events
        while not shutdown_event.is_set():
            try:
                payload = client_q.get(timeout=1)
                yield f'data: {payload}\n\n'
            except queue.Empty:
                yield ': heartbeat\n\n'
    finally:
        with _sse_lock:
            try:
                _sse_clients.remove(client_q)
            except ValueError:
                pass

@app.route('/events')
def events():
    return Response(sse_stream(), mimetype='text/event-stream')

@app.route('/health')
def health():
    from flask import jsonify
    return jsonify({"status": "ok", "sse_clients": len(_sse_clients)})

def kafka_consumer_thread():
    kafka_bootstrap = get_env("KAFKA_BOOTSTRAP", "kafka:9092")
    in_topic = get_env("IN_TOPIC", "netflow")
    out_topic = get_env("OUT_TOPIC", "geo.events")
    geoip_db = get_env("GEOIP_DB", "/geoip/GeoLite2-City.mmdb")
    extra = get_env("EXTRA_TOPICS", "security.alerts,dpi.events")
    topics = [in_topic] + [t.strip() for t in extra.split(",") if t.strip()]
    # New service topics — always included so globe receives threat intel / DNS / cred events
    for _new_topic in ("ioc.feed", "dns.events", "credential.alerts"):
        if _new_topic not in topics:
            topics.append(_new_topic)

    group_id = "geoip-enricher"
    log_interval = 500
    msg_count = 0

    producer = KafkaProducer(
        bootstrap_servers=kafka_bootstrap,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        retries=5
    )
    consumer = KafkaConsumer(
        *topics,
        bootstrap_servers=kafka_bootstrap,
        group_id=group_id,
        auto_offset_reset='latest',
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        enable_auto_commit=True,
        consumer_timeout_ms=10000
    )

    try:
        reader = geoip2.database.Reader(geoip_db)
    except Exception as e:
        logger.error(f"GeoIP DB load error: {e}")
        return

    import ipaddress
    home_lat = float(get_env("HOME_LAT", "38.9"))
    home_lon = float(get_env("HOME_LON", "-77.0"))

    def _home_coords():
        return "LAN", home_lat, home_lon

    def _resolve_coords(src_ip):
        """GeoIP lookup with RFC1918 fallback to home coords."""
        country, lat, lon = geoip_lookup(src_ip, reader) if src_ip else (None, None, None)
        if (lat is None or lon is None) and src_ip:
            try:
                addr = ipaddress.ip_address(src_ip)
                if addr.is_private or addr.is_loopback:
                    return _home_coords()
            except Exception:
                pass
        return country, lat, lon

    def _push_sse(geo_event):
        event_buffer.append(geo_event)
        if len(event_buffer) > buffer_max:
            del event_buffer[:-buffer_max]
        _broadcast(geo_event)

    global event_buffer
    try:
        while not shutdown_event.is_set():
            for msg in consumer:
                ev = msg.value
                topic = msg.topic

                # ── Determine event type ────────────────────────────────────
                if topic == in_topic:
                    event_type = "flow"
                elif topic == "raw.flows":
                    event_type = "raw_flow"
                elif topic == "security.alerts":
                    event_type = "ids_alert"
                elif topic == "dpi.events":
                    event_type = "dpi_event"
                elif topic == "voip.events":
                    event_type = "voip"
                elif topic == "ai.analysis":
                    event_type = "ai_analysis"
                elif topic == "blocklist.actions":
                    event_type = "blocklist"
                elif topic == "ioc.feed":
                    event_type = "ioc"
                elif topic == "dns.events":
                    event_type = ev.get("event_type", "dns_event")
                elif topic == "credential.alerts":
                    event_type = ev.get("alert_type", "credential_alert")
                else:
                    event_type = "other"

                geo_event = {"event_type": event_type, "topic": topic}
                now_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

                # ── blocklist: pass straight to SSE, no GeoIP needed ────────
                if event_type == "blocklist":
                    geo_event.update({
                        "ip":        ev.get("ip", ""),
                        "reason":    ev.get("reason", ""),
                        "llm_reason": ev.get("llm_reason", ""),
                        "timestamp": ev.get("timestamp", now_str),
                    })
                    _push_sse(geo_event)
                    continue

                # ── All other events: extract IPs then GeoIP-enrich ─────────
                src_ip = None
                dst_ip = None
                bytes_ = 0
                timestamp = now_str

                if event_type in ("flow", "raw_flow"):
                    src_ip    = ev.get("src_ip")
                    dst_ip    = ev.get("dst_ip")
                    bytes_    = ev.get("bytes", 0)
                    timestamp = ev.get("first_seen") or ev.get("timestamp") or now_str
                    if event_type == "raw_flow":
                        for field in ("protocol", "proto_name", "src_port", "dst_port", "packets"):
                            if field in ev:
                                geo_event[field] = ev[field]

                elif event_type == "ids_alert":
                    src_ip    = ev.get("src_ip")
                    dst_ip    = ev.get("dest_ip")
                    timestamp = ev.get("timestamp") or now_str
                    for field in ("signature", "category", "severity"):
                        if field in ev:
                            geo_event[field] = ev[field]
                    # Suricata nests alert fields
                    alert = ev.get("alert", {})
                    for field in ("signature", "category", "severity"):
                        if field in alert and field not in geo_event:
                            geo_event[field] = alert[field]

                elif event_type == "dpi_event":
                    # Zeek conn.log style
                    if "id" in ev and isinstance(ev["id"], dict):
                        src_ip    = ev["id"].get("orig_h")
                        dst_ip    = ev["id"].get("resp_h")
                        bytes_    = ev.get("resp_bytes") or ev.get("orig_bytes") or 0
                        timestamp = ev.get("ts") or now_str
                        geo_event["protocol"] = ev.get("proto")
                    else:
                        continue  # skip non-connlog DPI events

                elif event_type == "voip":
                    src_ip    = ev.get("src_ip")
                    dst_ip    = ev.get("dst_ip") or ev.get("dest_ip")
                    timestamp = ev.get("timestamp") or now_str
                    geo_event["method"]  = ev.get("method", "")
                    geo_event["call_id"] = ev.get("call_id", "")

                elif event_type == "ai_analysis":
                    src_ip    = ev.get("src_ip", "")
                    timestamp = ev.get("timestamp") or now_str
                    for field in ("severity", "confidence", "threat_type",
                                  "summary", "recommendation", "source_topic"):
                        geo_event[field] = ev.get(field, "")

                elif event_type == "ioc":
                    src_ip    = ev.get("indicator", "") if ev.get("ioc_type") == "ip" else ""
                    timestamp = ev.get("timestamp") or now_str
                    for field in ("ioc_type", "indicator", "threat_type", "source",
                                  "confidence", "suricata_rule"):
                        geo_event[field] = ev.get(field, "")

                elif event_type in ("dns_event", "dns_trace"):
                    src_ip    = ev.get("src_ip", "")
                    timestamp = ev.get("timestamp") or now_str
                    for field in ("query", "is_dga", "dga_score", "is_rpz_hit",
                                  "is_nxdomain", "nx_burst", "hops"):
                        geo_event[field] = ev.get(field)

                elif event_type in ("email_breach", "paste_exposure", "credential_alert"):
                    src_ip    = ""
                    timestamp = ev.get("timestamp") or now_str
                    for field in ("email", "breach_name", "breach_date",
                                  "data_classes", "severity", "alert_type"):
                        geo_event[field] = ev.get(field, "")
                    # Pin credential alerts to home coords
                    country, lat, lon = _home_coords()

                geo_event.update({
                    "src_ip":    src_ip,
                    "dst_ip":    dst_ip,
                    "bytes":     bytes_,
                    "timestamp": timestamp,
                })

                country, lat, lon = _resolve_coords(src_ip)

                # Pin non-flow events with unresolvable coords to home base
                # (VoIP/AI analysis from LAN IPs have no public GeoIP entry)
                if (lat is None or lon is None) and event_type != "flow":
                    country, lat, lon = _home_coords()

                geo_event["country"] = country
                geo_event["lat"]     = lat
                geo_event["lon"]     = lon

                if lat is None or lon is None:
                    continue  # drop flows with no coords (can't place on globe)

                # Publish geo-enriched event to geo.events (flows/alerts/DPI only)
                if event_type not in ("ai_analysis", "voip"):
                    producer.send(out_topic, geo_event)

                _push_sse(geo_event)
                msg_count += 1
                if msg_count % log_interval == 0:
                    logger.info(f"GeoIP-enriched {msg_count} events")

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