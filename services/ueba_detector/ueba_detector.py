#!/usr/bin/env python3
"""
UEBA Detector — User & Entity Behaviour Anomaly Detection

Consumes:  netflow, security.alerts, dns.events
Produces:  ueba.alerts

Approach
--------
For each IP seen in the last BASELINE_WINDOW_MINUTES, we maintain a
rolling history of per-window metric buckets:

  netflow  : bytes_sent, bytes_recv, pkt_count, unique_dst_ports,
             unique_dst_ips
  alerts   : alert_count   (from security.alerts)
  dns      : query_count, nxdomain_count, dga_count

Every EMIT_INTERVAL_SECONDS we:
  1. Compute the current window values for each IP.
  2. Compare them against the IP's own rolling baseline (mean + stdev).
  3. Calculate a z-score per metric; the anomaly score is the
     sigmoid-clipped maximum z-score across all metrics.
  4. Emit a ueba.alerts event for any IP whose score ≥ EMIT_THRESHOLD
     and for which we have at least MIN_BASELINE_WINDOWS of history.

The score is designed to feed directly into soar_blocker's anomaly_scores
dict, which gates automatic IP blocking.
"""

import json
import logging
import math
import os
import signal
import statistics
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from kafka import KafkaConsumer, KafkaProducer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("ueba_detector")

# ── Config ────────────────────────────────────────────────────────────────────
KAFKA_BOOTSTRAP          = os.getenv("KAFKA_BOOTSTRAP",        "kafka:9092")
CONSUME_TOPICS           = os.getenv("CONSUME_TOPICS",
                                     "netflow,security.alerts,dns.events").split(",")
UEBA_TOPIC               = os.getenv("UEBA_TOPIC",             "ueba.alerts")
EMIT_INTERVAL_SECONDS    = int(os.getenv("EMIT_INTERVAL_SECONDS",  "300"))   # 5 min
BASELINE_WINDOW_MINUTES  = int(os.getenv("BASELINE_WINDOW_MINUTES", "60"))   # 1 hr
MIN_BASELINE_WINDOWS     = int(os.getenv("MIN_BASELINE_WINDOWS",    "3"))     # need 3+ history points
EMIT_THRESHOLD           = float(os.getenv("EMIT_THRESHOLD",        "0.6"))  # 0-1
ZSCORE_CAP               = float(os.getenv("ZSCORE_CAP",            "10.0")) # cap raw z-score
CONSUMER_GROUP           = os.getenv("KAFKA_CONSUMER_GROUP",   "ueba-detector")
MAX_TRACKED_IPS          = int(os.getenv("MAX_TRACKED_IPS",        "10000")) # DoS guard

# ── State ─────────────────────────────────────────────────────────────────────
# Current accumulator for the active window (reset every EMIT_INTERVAL_SECONDS)
_current: dict = defaultdict(lambda: {
    "bytes_sent": 0, "bytes_recv": 0, "pkt_count": 0,
    "dst_ports": set(), "dst_ips": set(),
    "alert_count": 0,
    "query_count": 0, "nxdomain_count": 0, "dga_count": 0,
})

# Historical baselines: { ip: deque([{"bytes_sent": x, ...}, ...]) }
# Each deque entry is a completed window snapshot (raw values, not sets).
# Retain enough windows to cover BASELINE_WINDOW_MINUTES of history.
_HISTORY_MAXLEN = max(MIN_BASELINE_WINDOWS + 1,
                      BASELINE_WINDOW_MINUTES * 60 // EMIT_INTERVAL_SECONDS)
_history: dict = defaultdict(lambda: deque(maxlen=_HISTORY_MAXLEN))

_state_lock = threading.Lock()
_shutdown   = threading.Event()


# ── Kafka helpers ─────────────────────────────────────────────────────────────
def _make_producer() -> KafkaProducer:
    while not _shutdown.is_set():
        try:
            return KafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP,
                value_serializer=lambda v: json.dumps(v).encode(),
                retries=3,
            )
        except Exception as e:
            log.warning(f"Kafka producer init failed: {e} — retrying in 5s")
            time.sleep(5)


# ── Anomaly scoring ───────────────────────────────────────────────────────────
def _zscore(value: float, history_values: list) -> float:
    """Compute z-score of value against a list of historical values.
    Returns 0 if insufficient history or stdev is 0.
    """
    if len(history_values) < 2:
        return 0.0
    mu  = statistics.mean(history_values)
    sig = statistics.stdev(history_values)
    if sig == 0:
        return 0.0
    return min(abs((value - mu) / sig), ZSCORE_CAP)


def _sigmoid_score(z: float) -> float:
    """Map max z-score to a 0-1 anomaly score via a shifted sigmoid."""
    # sigmoid(z - 2): score reaches 0.5 at z=2 (2 std dev above baseline)
    return 1.0 / (1.0 + math.exp(-(z - 2.0)))


def _score_ip(ip: str, current_snapshot: dict, history: deque) -> tuple[float, str]:
    """Compute anomaly score and reason string for a single IP."""
    if len(history) < MIN_BASELINE_WINDOWS:
        return 0.0, "insufficient baseline"

    metrics = {
        "bytes_sent":    current_snapshot["bytes_sent"],
        "bytes_recv":    current_snapshot["bytes_recv"],
        "pkt_count":     current_snapshot["pkt_count"],
        "dst_ports":     current_snapshot["dst_ports"],
        "dst_ips":       current_snapshot["dst_ips"],
        "alert_count":   current_snapshot["alert_count"],
        "query_count":   current_snapshot["query_count"],
        "nxdomain_count":current_snapshot["nxdomain_count"],
        "dga_count":     current_snapshot["dga_count"],
    }

    z_scores: dict = {}
    for key, val in metrics.items():
        historical = [h[key] for h in history if key in h]
        z_scores[key] = _zscore(float(val), historical)

    max_key = max(z_scores, key=z_scores.get)
    max_z   = z_scores[max_key]
    score   = _sigmoid_score(max_z)

    # Build a reason string from all z-scores ≥ 2
    high = [f"{k} z={v:.1f}" for k, v in sorted(z_scores.items(),
                                                   key=lambda x: -x[1])
            if v >= 2.0]
    reason = "; ".join(high[:4]) if high else f"max {max_key} z={max_z:.1f}"

    return score, reason


# ── Consumer thread ───────────────────────────────────────────────────────────
def _consume():
    """Background thread: accumulate per-IP metrics from Kafka topics."""
    while not _shutdown.is_set():
        try:
            consumer = KafkaConsumer(
                *CONSUME_TOPICS,
                bootstrap_servers=KAFKA_BOOTSTRAP,
                group_id=CONSUMER_GROUP,
                auto_offset_reset="latest",
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                enable_auto_commit=True,
                consumer_timeout_ms=2000,
            )
            log.info(f"UEBA consumer connected, topics: {CONSUME_TOPICS}")
            while not _shutdown.is_set():
                for msg in consumer:
                    topic = msg.topic
                    val   = msg.value
                    _process_event(topic, val)
        except Exception as e:
            log.warning(f"Consumer error: {e} — reconnecting in 5s")
            time.sleep(5)


def _process_event(topic: str, val: dict):
    src_ip = val.get("src_ip") or val.get("ip") or ""
    if not src_ip:
        return

    with _state_lock:
        bucket = _current[src_ip]
        if topic == "netflow":
            bucket["bytes_sent"]  += int(val.get("bytes_sent",  0))
            bucket["bytes_recv"]  += int(val.get("bytes_recv",  0))
            bucket["pkt_count"]   += int(val.get("pkt_count",   0))
            dst_port = val.get("dst_port")
            dst_ip   = val.get("dst_ip")
            if dst_port:
                bucket["dst_ports"].add(int(dst_port))
            if dst_ip:
                bucket["dst_ips"].add(dst_ip)

        elif topic == "security.alerts":
            bucket["alert_count"] += 1

        elif topic == "dns.events":
            bucket["query_count"]   += 1
            if val.get("is_nxdomain"):
                bucket["nxdomain_count"] += 1
            if val.get("is_dga"):
                bucket["dga_count"] += 1


# ── Emit loop ─────────────────────────────────────────────────────────────────
def _emit_loop(producer: KafkaProducer):
    """Main loop: every EMIT_INTERVAL_SECONDS, score all IPs and publish."""
    log.info(
        f"UEBA emit loop started — interval={EMIT_INTERVAL_SECONDS}s "
        f"threshold={EMIT_THRESHOLD} min_windows={MIN_BASELINE_WINDOWS}"
    )
    while not _shutdown.is_set():
        time.sleep(EMIT_INTERVAL_SECONDS)
        if _shutdown.is_set():
            break
        _process_window(producer)


def _process_window(producer: KafkaProducer):
    with _state_lock:
        snapshot = {}
        for ip, bucket in _current.items():
            snapshot[ip] = {
                "bytes_sent":     bucket["bytes_sent"],
                "bytes_recv":     bucket["bytes_recv"],
                "pkt_count":      bucket["pkt_count"],
                "dst_ports":      len(bucket["dst_ports"]),
                "dst_ips":        len(bucket["dst_ips"]),
                "alert_count":    bucket["alert_count"],
                "query_count":    bucket["query_count"],
                "nxdomain_count": bucket["nxdomain_count"],
                "dga_count":      bucket["dga_count"],
            }
        _current.clear()

    if not snapshot:
        return

    # Append window to history before scoring
    for ip, snap in snapshot.items():
        _history[ip].append(snap)

    # Score and emit
    emitted = 0
    for ip, snap in snapshot.items():
        score, reason = _score_ip(ip, snap, _history[ip])
        if score < EMIT_THRESHOLD:
            continue
        event = {
            "ip":        ip,
            "src_ip":    ip,
            "score":     round(score, 4),
            "reason":    reason,
            "metrics":   snap,
            "window_s":  EMIT_INTERVAL_SECONDS,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        try:
            producer.send(UEBA_TOPIC, event)
            log.info(f"UEBA alert: {ip} score={score:.2f} reason={reason}")
            emitted += 1
        except Exception as e:
            log.warning(f"Failed to publish UEBA alert for {ip}: {e}")

    log.info(
        f"Window processed: {len(snapshot)} IPs evaluated, "
        f"{emitted} anomalies emitted (score >= {EMIT_THRESHOLD})"
    )

    # Prune stale IPs to keep _history bounded (DoS guard: MAX_TRACKED_IPS)
    if len(_history) > MAX_TRACKED_IPS:
        stale = [ip for ip in list(_history) if ip not in snapshot]
        to_drop = len(_history) - MAX_TRACKED_IPS
        for ip in stale[:to_drop]:
            del _history[ip]


# ── Graceful shutdown ─────────────────────────────────────────────────────────
def _handle_signal(sig, frame):
    log.info("Shutdown signal received")
    _shutdown.set()


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)

    log.info("UEBA Detector starting")
    log.info(f"  Topics: {CONSUME_TOPICS}")
    log.info(f"  Output: {UEBA_TOPIC}")
    log.info(f"  Emit interval: {EMIT_INTERVAL_SECONDS}s")
    log.info(f"  Baseline window: {BASELINE_WINDOW_MINUTES}min")
    log.info(f"  Anomaly threshold: {EMIT_THRESHOLD}")

    producer = _make_producer()
    if producer is None:
        log.error("Could not connect to Kafka — exiting")
        sys.exit(1)

    consumer_thread = threading.Thread(target=_consume, daemon=True, name="ueba-consumer")
    consumer_thread.start()

    _emit_loop(producer)

    producer.close()
    log.info("UEBA Detector stopped")


if __name__ == "__main__":
    main()
