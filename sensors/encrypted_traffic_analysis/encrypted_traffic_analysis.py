import os
import time
import json
import logging
import hashlib
from datetime import datetime
from threading import Event, Thread
import signal

from scapy.all import sniff, TCP, IP, Raw
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
from scapy.layers.tls.record import TLS
from scapy.layers.tls.extensions import TLSServerNameIndication
from kafka import KafkaProducer

from common.config import get_env

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("encrypted_traffic_analysis")

shutdown_event = Event()

def isoformat(ts=None):
    return datetime.utcfromtimestamp(ts or time.time()).isoformat() + "Z"

def get_sni(hello):
    # Try to extract SNI from ClientHello
    sni = None
    if hasattr(hello, "ext") and hello.ext:
        for ext in hello.ext:
            if ext.__class__.__name__ == "TLSServerNameIndication":
                sni = ext.servernames[0].servername.decode() if ext.servernames else None
    return sni

def compute_ja3(client_hello):
    # See: https://github.com/salesforce/ja3
    def join_ints(seq):
        return '-'.join(str(x) for x in seq)
    try:
        ver = client_hello.version
        ciphers = [c for c in getattr(client_hello, "ciphers", [])]
        exts = [e.ext_type for e in getattr(client_hello, "ext", [])]
        ec = []
        epf = []
        # Extension: elliptic_curves (10), ec_point_formats (11)
        for e in getattr(client_hello, "ext", []):
            if hasattr(e, "ext_type") and e.ext_type == 10 and hasattr(e, "elliptic_curves"):
                ec = e.elliptic_curves
            if hasattr(e, "ext_type") and e.ext_type == 11 and hasattr(e, "ec_point_formats"):
                epf = e.ec_point_formats
        ja3_str = "%s,%s,%s,%s,%s" % (
            ver,
            join_ints(ciphers),
            join_ints(exts),
            join_ints(ec),
            join_ints(epf)
        )
        ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()
        return ja3_str, ja3_hash
    except Exception as e:
        logger.debug(f"Failed JA3 extraction: {e}")
        return None, None

def compute_ja3s(server_hello):
    try:
        ver = server_hello.version
        # one cipher
        ciphers = [server_hello.cipher]
        exts = [e.ext_type for e in getattr(server_hello, "ext", [])]
        ec = []
        epf = []
        for e in getattr(server_hello, "ext", []):
            if hasattr(e, "ext_type") and e.ext_type == 10 and hasattr(e, "elliptic_curves"):
                ec = e.elliptic_curves
            if hasattr(e, "ext_type") and e.ext_type == 11 and hasattr(e, "ec_point_formats"):
                epf = e.ec_point_formats
        ja3s_str = "%s,%s,%s,%s,%s" % (
            ver,
            '-'.join(str(x) for x in ciphers),
            '-'.join(str(x) for x in exts),
            '-'.join(str(x) for x in ec),
            '-'.join(str(x) for x in epf)
        )
        ja3s_hash = hashlib.md5(ja3s_str.encode()).hexdigest()
        return ja3s_str, ja3s_hash
    except Exception as e:
        logger.debug(f"Failed JA3S extraction: {e}")
        return None, None

def parse_tls(pkt):
    # Expects scapy TLS layer present
    if not pkt.haslayer(TLS):
        return None
    tls = pkt[TLS]
    for record in tls.records:
        if hasattr(record, "msg"):
            for msg in record.msg:
                if isinstance(msg, TLSClientHello):
                    # Direction: client
                    ja3_str, ja3_hash = compute_ja3(msg)
                    sni = get_sni(msg)
                    return {
                        "direction": "client",
                        "ja3": ja3_str,
                        "ja3_hash": ja3_hash,
                        "sni": sni,
                        "ja3s": None,
                        "ja3s_hash": None
                    }
                elif isinstance(msg, TLSServerHello):
                    ja3s_str, ja3s_hash = compute_ja3s(msg)
                    return {
                        "direction": "server",
                        "ja3": None,
                        "ja3_hash": None,
                        "sni": None,
                        "ja3s": ja3s_str,
                        "ja3s_hash": ja3s_hash
                    }
    return None

def main():
    interface = get_env("INTERFACE", "eth0")
    kafka_bootstrap = get_env("KAFKA_BOOTSTRAP", "kafka:9092")
    kafka_topic = get_env("KAFKA_TOPIC", "tls.meta")
    log_interval = 100

    logger.info(f"Starting Encrypted Traffic Analysis Sensor")
    logger.info(f"Config: INTERFACE={interface} KAFKA_BOOTSTRAP={kafka_bootstrap} KAFKA_TOPIC={kafka_topic}")

    producer = KafkaProducer(
        bootstrap_servers=kafka_bootstrap,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        retries=5
    )

    sig_count = {"count": 0}

    def handle_sigterm(sig, frame):
        logger.info("Received SIGTERM, shutting down...")
        shutdown_event.set()
    signal.signal(signal.SIGTERM, handle_sigterm)

    def pkt_handler(pkt):
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return
        if not pkt.haslayer(TLS):
            return
        tls_meta = parse_tls(pkt)
        if tls_meta:
            now = time.time()
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            rec = {
                "timestamp": isoformat(now),
                "direction": tls_meta["direction"],
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "ja3": tls_meta.get("ja3"),
                "ja3_hash": tls_meta.get("ja3_hash"),
                "sni": tls_meta.get("sni"),
                "ja3s": tls_meta.get("ja3s"),
                "ja3s_hash": tls_meta.get("ja3s_hash")
            }
            producer.send(kafka_topic, rec)
            sig_count["count"] += 1
            if sig_count["count"] % log_interval == 0:
                logger.info(f"Processed {sig_count['count']} TLS handshake messages")

    logger.info("Sniffing interface for TLS handshakes (tcp port 443)...")
    try:
        sniff(
            iface=interface,
            filter="tcp port 443",
            prn=pkt_handler,
            store=False,
            stop_filter=lambda x: shutdown_event.is_set()
        )
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received, shutting down...")
        shutdown_event.set()
    finally:
        logger.info("Encrypted Traffic Analysis Sensor stopped.")

if __name__ == "__main__":
    main()