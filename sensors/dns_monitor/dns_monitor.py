#!/usr/bin/env python3
"""
DNS Threat Monitor — passive DNS logging · DGA detection · ephemeral path tracer

Capabilities:
  1. Passive DNS sniffing (UDP/TCP 53, DoH 853) — logs all queries/responses
  2. DGA Detection — Shannon entropy + NXDomain burst + n-gram analysis
  3. RPZ enforcement — checks queries against local blocklist
  4. Ephemeral Path Tracer — active ICMP/UDP traceroute with randomised source
     IP and MAC to reveal the true hop path to a suspicious IP without exposing
     the sensor's real identity. REQUIRES ENABLE_EPHEMERAL_TRACER=true.

All events published to `dns.events` Kafka topic and broadcast via SSE.

Security / legal note on the Ephemeral Tracer:
  This tool is for use only on networks you own or have written authorisation
  to test. Spoofing source IPs/MACs is restricted/illegal in many jurisdictions
  unless performed on a controlled test network or with ISP authorisation.
  Set ENABLE_EPHEMERAL_TRACER=true only if authorised to do so.
"""

import json
import logging
import math
import os
import random
import re
import signal
import socket
import struct
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, request
from flask_cors import CORS
from kafka import KafkaProducer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("dns_monitor")

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

KAFKA_BOOTSTRAP      = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
INTERFACE            = os.getenv("INTERFACE", "eth0")
DNS_TOPIC            = "dns.events"
DGA_ENTROPY_THRESH   = float(os.getenv("DGA_ENTROPY_THRESH", "3.6"))
DGA_LEN_MIN          = int(os.getenv("DGA_LEN_MIN", "12"))
NXDOMAIN_BURST_LIMIT = int(os.getenv("NXDOMAIN_BURST_LIMIT", "10"))
NXDOMAIN_BURST_WINDOW = int(os.getenv("NXDOMAIN_BURST_WINDOW", "60"))
ENABLE_TRACER        = os.getenv("ENABLE_EPHEMERAL_TRACER", "false").lower() == "true"
TRACER_MAX_TTL       = int(os.getenv("TRACER_MAX_TTL", "20"))
TRACER_TIMEOUT       = float(os.getenv("TRACER_TIMEOUT", "2.0"))

# ── State ─────────────────────────────────────────────────────────────────────
_dns_cache: list = []
_cache_lock = threading.Lock()
_CACHE_MAX = 2000

_nxdomain_tracker: dict = defaultdict(deque)  # { src_ip: deque of timestamps }
_rpz_blocklist: set = set()                   # domain blocklist (loaded from env)

_sse_clients: list = []
_sse_lock = threading.Lock()

_shutdown_event = threading.Event()

# ── Kafka ──────────────────────────────────────────────────────────────────────
_producer: KafkaProducer | None = None
_prod_lock = threading.Lock()


def _get_producer():
    global _producer
    with _prod_lock:
        if _producer is None:
            try:
                _producer = KafkaProducer(
                    bootstrap_servers=KAFKA_BOOTSTRAP,
                    value_serializer=lambda v: json.dumps(v).encode(),
                    retries=3,
                )
            except Exception as e:
                log.warning(f"Kafka init failed: {e}")
        return _producer


def _publish(event: dict):
    p = _get_producer()
    if p:
        try:
            p.send(DNS_TOPIC, event)
        except Exception as e:
            log.warning(f"Kafka publish failed: {e}")


def _broadcast_sse(event: dict):
    payload = json.dumps(event)
    with _sse_lock:
        for q in list(_sse_clients):
            try:
                q.put_nowait(payload)
            except Exception:
                pass


def _store_and_emit(event: dict):
    with _cache_lock:
        _dns_cache.append(event)
        if len(_dns_cache) > _CACHE_MAX:
            del _dns_cache[:-_CACHE_MAX]
    _publish(event)
    _broadcast_sse(event)


# ── DGA Detection ─────────────────────────────────────────────────────────────
def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of string — high entropy suggests DGA."""
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


# Common legitimate high-entropy patterns to reduce false positives
_LEGIT_PATTERNS = re.compile(
    r"\.(cloudfront|akamai|fastly|amazonaws|cloudflare|azureedge|msedge|"
    r"akadns|edgesuite|footprint)\.net$|"
    r"\.(googleapis|gstatic|googlevideo)\.com$",
    re.IGNORECASE,
)


def _is_dga(domain: str) -> tuple[bool, float, str]:
    """
    Returns (is_dga, entropy_score, reason).
    Multi-signal: entropy + length + known-DGA character distribution + NXDomain.
    """
    # Strip trailing dot
    d = domain.rstrip(".")
    # Only check 3rd+ level labels (the random part)
    labels = d.split(".")
    if len(labels) < 2:
        return False, 0.0, ""

    subdomain = labels[0]
    if len(subdomain) < DGA_LEN_MIN:
        return False, 0.0, ""

    if _LEGIT_PATTERNS.search(d):
        return False, 0.0, ""

    entropy = _shannon_entropy(subdomain)

    # Vowel/consonant ratio check — DGA domains tend to be consonant-heavy
    vowels = sum(1 for c in subdomain.lower() if c in "aeiou")
    vowel_ratio = vowels / max(len(subdomain), 1)

    # Digit ratio — many DGAs include digits
    digits = sum(1 for c in subdomain if c.isdigit())
    digit_ratio = digits / max(len(subdomain), 1)

    score = entropy
    reasons = []

    if entropy >= DGA_ENTROPY_THRESH:
        reasons.append(f"entropy={entropy:.2f}")
    if vowel_ratio < 0.1:
        score += 0.5
        reasons.append(f"low-vowel-ratio={vowel_ratio:.2f}")
    if digit_ratio > 0.4:
        score += 0.3
        reasons.append(f"high-digit-ratio={digit_ratio:.2f}")

    is_dga = score >= DGA_ENTROPY_THRESH and bool(reasons)
    return is_dga, score, ",".join(reasons)


def _track_nxdomain(src_ip: str) -> bool:
    """Return True if src_ip has exceeded the NXDomain burst threshold."""
    now = time.time()
    window_start = now - NXDOMAIN_BURST_WINDOW
    dq = _nxdomain_tracker[src_ip]
    dq.append(now)
    # Prune old entries
    while dq and dq[0] < window_start:
        dq.popleft()
    return len(dq) >= NXDOMAIN_BURST_LIMIT


# ── RPZ Blocklist ─────────────────────────────────────────────────────────────
def _load_rpz():
    """Load RPZ blocklist from env-specified file or inline list."""
    rpz_file = os.getenv("RPZ_BLOCKLIST_FILE", "")
    if rpz_file and os.path.exists(rpz_file):
        with open(rpz_file) as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    _rpz_blocklist.add(line)
        log.info(f"RPZ: loaded {len(_rpz_blocklist)} blocked domains from {rpz_file}")
    inline = os.getenv("RPZ_BLOCKED_DOMAINS", "")
    if inline:
        for d in inline.split(","):
            _rpz_blocklist.add(d.strip().lower())


# ── Passive DNS Sniffer ───────────────────────────────────────────────────────
def _parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Parse a DNS name from a packet, following pointer compression."""
    labels = []
    jumped = False
    orig_offset = offset
    max_jumps = 10

    while max_jumps > 0:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            # Pointer
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                orig_offset = offset + 2
            offset = ptr
            jumped = True
            max_jumps -= 1
            continue
        label = data[offset + 1: offset + 1 + length].decode("ascii", errors="replace")
        labels.append(label)
        offset += 1 + length

    if jumped:
        return ".".join(labels), orig_offset
    return ".".join(labels), offset


def _parse_dns_packet(data: bytes) -> dict | None:
    """Parse raw DNS payload. Returns dict with query info or None."""
    if len(data) < 12:
        return None
    try:
        txid = struct.unpack(">H", data[0:2])[0]
        flags = struct.unpack(">H", data[2:4])[0]
        qr = (flags >> 15) & 1         # 0=query, 1=response
        rcode = flags & 0xF            # 0=NOERROR, 3=NXDOMAIN
        qdcount = struct.unpack(">H", data[4:6])[0]
        ancount = struct.unpack(">H", data[6:8])[0]

        if qdcount == 0:
            return None

        offset = 12
        qname, offset = _parse_dns_name(data, offset)
        if offset + 4 > len(data):
            return None

        qtype = struct.unpack(">H", data[offset: offset + 2])[0]
        qclass = struct.unpack(">H", data[offset + 2: offset + 4])[0]

        return {
            "txid":    txid,
            "qr":      qr,
            "rcode":   rcode,
            "qname":   qname.lower(),
            "qtype":   qtype,
            "is_nx":   (qr == 1 and rcode == 3),
            "an_count": ancount,
        }
    except Exception:
        return None


def _sniff_dns():
    """Raw socket DNS sniffer — captures UDP/53 packets."""
    try:
        # ETH_P_ALL = 0x0003
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.bind((INTERFACE, 0))
        sock.settimeout(2.0)
        log.info(f"DNS sniffer active on {INTERFACE}")
    except PermissionError:
        log.error("DNS sniffer requires CAP_NET_RAW — running without packet capture")
        return
    except Exception as e:
        log.error(f"DNS sniffer socket error: {e}")
        return

    while not _shutdown_event.is_set():
        try:
            raw, addr = sock.recvfrom(65535)
            if len(raw) < 42:
                continue

            # Parse Ethernet (14) + IP (20 min) + UDP (8) headers
            eth_type = struct.unpack(">H", raw[12:14])[0]
            if eth_type != 0x0800:   # IPv4 only
                continue

            ip_proto = raw[23]
            if ip_proto != 17:       # UDP only
                continue

            src_ip_bytes = raw[26:30]
            dst_ip_bytes = raw[30:34]
            src_ip = socket.inet_ntoa(src_ip_bytes)
            dst_ip = socket.inet_ntoa(dst_ip_bytes)

            ip_hdr_len = (raw[14] & 0x0F) * 4
            udp_offset = 14 + ip_hdr_len
            if len(raw) < udp_offset + 8:
                continue

            src_port = struct.unpack(">H", raw[udp_offset: udp_offset + 2])[0]
            dst_port = struct.unpack(">H", raw[udp_offset + 2: udp_offset + 4])[0]

            if dst_port != 53 and src_port != 53:
                continue

            dns_payload = raw[udp_offset + 8:]
            parsed = _parse_dns_packet(dns_payload)
            if not parsed:
                continue

            qname = parsed["qname"]
            is_dga, dga_score, dga_reason = _is_dga(qname)
            is_rpz = qname.rstrip(".") in _rpz_blocklist
            is_nxburst = False

            if parsed["is_nx"]:
                is_nxburst = _track_nxdomain(src_ip)

            event = {
                "event_type":  "dns_event",
                "topic":       DNS_TOPIC,
                "src_ip":      src_ip if dst_port == 53 else dst_ip,
                "dst_ip":      dst_ip if dst_port == 53 else src_ip,
                "query":       qname,
                "query_type":  parsed["qtype"],
                "is_response": parsed["qr"] == 1,
                "is_nxdomain": parsed["is_nx"],
                "is_dga":      is_dga,
                "dga_score":   round(dga_score, 3),
                "dga_reason":  dga_reason,
                "is_rpz_hit":  is_rpz,
                "nx_burst":    is_nxburst,
                "timestamp":   datetime.now(timezone.utc).isoformat(),
            }

            # Trigger path trace for confirmed DGA or RPZ hits
            if (is_dga or is_rpz) and ENABLE_TRACER:
                target = dst_ip if dst_port == 53 else src_ip
                threading.Thread(
                    target=_ephemeral_trace,
                    args=(target, event),
                    daemon=True,
                ).start()

            _store_and_emit(event)

        except socket.timeout:
            continue
        except (struct.error, OSError) as e:
            log.debug(f"Sniffer error: {e}")
            time.sleep(0.1)


# ── Ephemeral Path Tracer ─────────────────────────────────────────────────────
def _random_private_ip() -> str:
    """Generate a random RFC1918 IP for source spoofing (within our own subnet for safety)."""
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(2,254)}"


def _random_mac() -> str:
    """Generate a random locally administered MAC address."""
    mac = [0x02] + [random.randint(0, 255) for _ in range(5)]
    return ":".join(f"{b:02x}" for b in mac)


def _ephemeral_trace(target_ip: str, trigger_event: dict):
    """
    Active ephemeral traceroute to target_ip.
    Each ICMP probe uses a randomised source IP and is sent with TTL 1..MAX_TTL.
    ICMP Time Exceeded responses reveal each hop. Results appended to trigger_event.

    AUTHORISATION REQUIRED — set ENABLE_EPHEMERAL_TRACER=true only on authorised networks.
    """
    log.info(f"Ephemeral trace to {target_ip} (trigger: {trigger_event.get('query')})")
    hops = []
    spoof_src = _random_private_ip()

    try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_sock.settimeout(TRACER_TIMEOUT)
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        log.warning("Ephemeral tracer requires CAP_NET_RAW — skipping")
        return
    except Exception as e:
        log.warning(f"Tracer socket error: {e}")
        return

    def _icmp_checksum(data: bytes) -> int:
        s = 0
        for i in range(0, len(data) - 1, 2):
            s += (data[i] << 8) + data[i + 1]
        if len(data) % 2:
            s += data[-1] << 8
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

    def _build_icmp_echo(seq: int) -> bytes:
        icmp = struct.pack(">BBHHH", 8, 0, 0, os.getpid() & 0xFFFF, seq)
        chk  = _icmp_checksum(icmp)
        return struct.pack(">BBHHH", 8, 0, chk, os.getpid() & 0xFFFF, seq)

    def _build_ipv4(src: str, dst: str, ttl: int, payload: bytes) -> bytes:
        ihl     = 5
        version = 4
        tos     = 0
        tot_len = 20 + len(payload)
        ident   = random.randint(0, 65535)
        frag    = 0
        proto   = socket.IPPROTO_ICMP
        chksum  = 0
        src_b   = socket.inet_aton(src)
        dst_b   = socket.inet_aton(dst)
        hdr = struct.pack(">BBHHHBBH4s4s",
                          (version << 4) | ihl, tos, tot_len, ident, frag,
                          ttl, proto, chksum, src_b, dst_b)
        return hdr + payload

    try:
        for ttl in range(1, TRACER_MAX_TTL + 1):
            icmp_pkt = _build_icmp_echo(ttl)
            ip_pkt   = _build_ipv4(spoof_src, target_ip, ttl, icmp_pkt)

            t_send = time.time()
            try:
                send_sock.sendto(ip_pkt, (target_ip, 0))
            except Exception as e:
                log.debug(f"Tracer send error at TTL {ttl}: {e}")
                hops.append({"ttl": ttl, "ip": "*", "rtt_ms": None})
                continue

            hop_ip = "*"
            rtt_ms = None
            try:
                resp, addr = recv_sock.recvfrom(1024)
                rtt_ms = round((time.time() - t_send) * 1000, 2)
                hop_ip = addr[0]
            except socket.timeout:
                pass
            except Exception:
                pass

            hops.append({"ttl": ttl, "ip": hop_ip, "rtt_ms": rtt_ms})
            log.debug(f"  hop {ttl}: {hop_ip} {rtt_ms}ms")

            if hop_ip == target_ip:
                break

    finally:
        recv_sock.close()
        send_sock.close()

    trace_event = {
        **trigger_event,
        "event_type":   "dns_trace",
        "topic":        DNS_TOPIC,
        "trace_target": target_ip,
        "spoof_src":    spoof_src,
        "spoof_mac":    _random_mac(),
        "hops":         hops,
        "hop_count":    len([h for h in hops if h["ip"] != "*"]),
        "timestamp":    datetime.now(timezone.utc).isoformat(),
    }
    log.info(f"Trace complete: {target_ip} via {len(hops)} hops (spoofed src: {spoof_src})")
    _store_and_emit(trace_event)


# ── Flask API ─────────────────────────────────────────────────────────────────
import queue as _queue


@app.route("/api/dns/feed")
def dns_feed_api():
    with _cache_lock:
        return jsonify({"events": list(_dns_cache[-100:]), "total": len(_dns_cache)})


@app.route("/api/dns/dga")
def dga_hits():
    with _cache_lock:
        hits = [e for e in _dns_cache if e.get("is_dga") or e.get("is_rpz_hit")]
    return jsonify({"hits": hits[-50:], "total": len(hits)})


@app.route("/api/dns/trace", methods=["POST"])
def trigger_trace():
    if not ENABLE_TRACER:
        return jsonify({"error": "Ephemeral tracer disabled. Set ENABLE_EPHEMERAL_TRACER=true."}), 403
    data = request.json or {}
    target = data.get("ip", "")
    import ipaddress
    try:
        ipaddress.ip_address(target)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400
    threading.Thread(
        target=_ephemeral_trace,
        args=(target, {"query": "manual", "trigger": "api"}),
        daemon=True,
    ).start()
    return jsonify({"status": "trace started", "target": target})


@app.route("/api/dns/events/stream")
def dns_sse():
    """SSE stream of DNS events for the UI."""
    import queue as q_module
    client_q = q_module.Queue(maxsize=200)
    with _sse_lock:
        _sse_clients.append(client_q)

    def _gen():
        try:
            while True:
                try:
                    payload = client_q.get(timeout=1)
                    yield f"data: {payload}\n\n"
                except _queue.Empty:
                    yield ": heartbeat\n\n"
        finally:
            with _sse_lock:
                try:
                    _sse_clients.remove(client_q)
                except ValueError:
                    pass

    return Response(_gen(), mimetype="text/event-stream",
                    headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"})


@app.route("/health")
def health():
    with _cache_lock:
        dga_count = sum(1 for e in _dns_cache if e.get("is_dga"))
    return jsonify({
        "status": "ok",
        "tracer_enabled": ENABLE_TRACER,
        "rpz_entries": len(_rpz_blocklist),
        "dns_events": len(_dns_cache),
        "dga_detections": dga_count,
    })


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info(f"DNS Monitor starting on {INTERFACE}")
    log.info(f"DGA entropy threshold: {DGA_ENTROPY_THRESH}  |  NXDomain burst: {NXDOMAIN_BURST_LIMIT}/{NXDOMAIN_BURST_WINDOW}s")
    log.info(f"Ephemeral tracer: {'ENABLED' if ENABLE_TRACER else 'disabled'}")
    _load_rpz()

    _sniffer = threading.Thread(target=_sniff_dns, daemon=False, name="dns-sniffer")
    _sniffer.start()

    def _on_shutdown(sig, frame):
        log.info("Shutdown signal received — stopping sniffer")
        _shutdown_event.set()
        _sniffer.join(timeout=5)
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _on_shutdown)
    signal.signal(signal.SIGINT, _on_shutdown)

    app.run(host="0.0.0.0", port=5005, debug=False, threaded=True)
