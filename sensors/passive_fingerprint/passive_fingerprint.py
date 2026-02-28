import time
import logging
import json

from scapy.all import sniff, IP, TCP, UDP, DNS, Raw, conf as scapy_conf
from kafka import KafkaProducer
from common.config import get_env

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("passive_fingerprint")

KAFKA_BOOTSTRAP = get_env("KAFKA_BOOTSTRAP", "kafka:9092")
KAFKA_TOPIC     = get_env("KAFKA_TOPIC",     "fingerprint.events")
INTERFACE       = get_env("INTERFACE",       "eth0")

# ── p0f-style OS signature database ───────────────────────────────────────────
# Fields: (label, init_ttl, win_sizes, df, tcp_opt_order)
#   init_ttl    : expected initial TTL bucket (32 / 64 / 128 / 255)
#   win_sizes   : set of typical SYN window sizes (empty → match any)
#   df          : True / False / None (None = ignore)
#   tcp_opt_order : tuple of Scapy TCP option names in SYN order (prefix match)
OS_SIGS = [
    # ── Windows ──────────────────────────────────────────────────────────────
    ("Windows 10/11",  128, {64240, 65535, 8192}, True,
     ("MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK")),
    ("Windows 7/8",    128, {8192, 65535},        True,
     ("MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK")),
    ("Windows Server", 128, {65535},              True,
     ("MSS", "NOP", "NOP", "SAckOK")),
    ("Windows XP",     128, {65535, 16384},       False,
     ("MSS", "NOP", "NOP")),
    # ── Linux ─────────────────────────────────────────────────────────────────
    ("Linux 5.x", 64, {29200, 65535, 43690, 26883, 62727}, True,
     ("MSS", "SAckOK", "Timestamp", "NOP", "WScale")),
    ("Linux 4.x", 64, {29200, 14600, 65535},               True,
     ("MSS", "SAckOK", "Timestamp", "NOP", "WScale")),
    ("Linux 2.6", 64, {5840, 14600, 32120},                True,
     ("MSS", "SAckOK", "Timestamp", "NOP", "WScale")),
    # ── macOS / iOS ───────────────────────────────────────────────────────────
    ("macOS", 64, {65535}, True,
     ("MSS", "NOP", "WScale", "NOP", "NOP", "Timestamp", "SAckOK", "NOP", "NOP")),
    ("iOS",   64, {65535, 43690}, True,
     ("MSS", "NOP", "WScale", "SAckOK", "Timestamp", "NOP", "NOP")),
    # ── BSD ───────────────────────────────────────────────────────────────────
    ("FreeBSD", 64, {65535},  True,
     ("MSS", "NOP", "WScale", "SAckOK", "Timestamp", "NOP", "NOP")),
    ("OpenBSD", 64, {16384},  True,
     ("MSS", "NOP", "NOP", "SAckOK", "Timestamp")),
    # ── Android ───────────────────────────────────────────────────────────────
    ("Android", 64, {65535, 14600, 5840}, True,
     ("MSS", "SAckOK", "Timestamp", "NOP", "WScale")),
    # ── Network / Embedded ────────────────────────────────────────────────────
    ("Cisco IOS", 255, {4096, 8192, 16384}, False, ("MSS",)),
    ("HP-UX",     255, {32768},              True,  ("MSS", "NOP", "WScale")),
    # ── Generic TTL-only fallbacks ────────────────────────────────────────────
    ("Generic *nix",    64,  set(), None, ()),
    ("Generic Windows", 128, set(), None, ()),
    ("Generic Network", 255, set(), None, ()),
]


def _initial_ttl_bucket(ttl):
    """Round observed TTL up to the nearest common initial TTL value."""
    for bucket in (32, 64, 128, 255):
        if ttl <= bucket:
            return bucket
    return 255


def _opt_names(pkt):
    """Return TCP option names in order as a tuple (Scapy string names)."""
    if not pkt.haslayer(TCP):
        return ()
    return tuple(name for name, _ in pkt[TCP].options)


def _opt_value(pkt, option_name):
    """Return the numeric value of a named TCP option, or None."""
    if not pkt.haslayer(TCP):
        return None
    for name, val in pkt[TCP].options:
        if name == option_name:
            return val
    return None


def guess_os(ttl, win, df, opt_names):
    """Score each signature; return (label, score, init_ttl_bucket)."""
    init_ttl = _initial_ttl_bucket(ttl)
    best_label, best_score = "Unknown", 0

    for label, sig_ttl, wins, sig_df, sig_opts in OS_SIGS:
        if init_ttl != sig_ttl:
            continue            # TTL bucket must match first
        score = 2              # base: TTL match

        if wins and win in wins:
            score += 4         # characteristic window size
        if sig_df is not None and df == sig_df:
            score += 2         # DF flag
        if sig_opts:
            actual = opt_names[:len(sig_opts)]
            if actual == sig_opts:
                score += 5     # exact option prefix match
            elif set(sig_opts) == set(actual):
                score += 2     # same options, different order

        if score > best_score:
            best_score, best_label = score, label

    return best_label, best_score, init_ttl


# ── Kafka producer (lazy) ──────────────────────────────────────────────────────
_producer = None


def _get_producer():
    global _producer
    if _producer:
        return _producer
    try:
        _producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            retries=3,
        )
        logger.info("Kafka producer connected")
    except Exception as e:
        logger.warning(f"Kafka unavailable: {e}")
    return _producer


def _emit(ev):
    p = _get_producer()
    if p:
        try:
            p.send(KAFKA_TOPIC, ev)
        except Exception as e:
            logger.debug(f"Kafka send error: {e}")
    else:
        logger.debug(f"[fp] {ev.get('event_type')} {ev.get('src_ip', '')}")


# ── Packet processing ──────────────────────────────────────────────────────────
def process_pkt(pkt):
    if not pkt.haslayer(IP):
        return

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    ip  = pkt[IP]

    # 1 ── Passive OS fingerprint from TCP SYN ─────────────────────────────────
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]

        if tcp.flags == 0x02:      # SYN only (not SYN-ACK)
            ttl       = ip.ttl
            win       = tcp.window
            df        = bool(ip.flags & 0x2)
            opt_names = _opt_names(pkt)
            mss       = _opt_value(pkt, "MSS")
            ws        = _opt_value(pkt, "WScale")

            os_label, score, init_ttl = guess_os(ttl, win, df, opt_names)

            _emit({
                "event_type":    "os_fingerprint",
                "topic":         KAFKA_TOPIC,
                "timestamp":     now,
                "src_ip":        ip.src,
                "dst_ip":        ip.dst,
                "src_port":      tcp.sport,
                "dst_port":      tcp.dport,
                "ttl":           ttl,
                "init_ttl":      init_ttl,
                "window":        win,
                "df":            df,
                "mss":           mss,
                "window_scale":  ws,
                "tcp_options":   list(opt_names),
                "os_guess":      os_label,
                "os_confidence": score,
            })

        # 2 ── SSH version banner ───────────────────────────────────────────────
        if (tcp.sport == 22 or tcp.dport == 22) and pkt.haslayer(Raw):
            try:
                banner = bytes(pkt[Raw].load).decode("utf-8", errors="ignore").strip()
                if banner.startswith("SSH-"):
                    _emit({
                        "event_type": "ssh_banner",
                        "topic":      KAFKA_TOPIC,
                        "timestamp":  now,
                        "src_ip":     ip.src,
                        "dst_ip":     ip.dst,
                        "src_port":   tcp.sport,
                        "dst_port":   tcp.dport,
                        "ssh_banner": banner[:200],
                    })
            except Exception:
                pass

        # 3 ── HTTP proxy-header detection ─────────────────────────────────────
        if tcp.dport in (80, 8080, 3128, 8888) and pkt.haslayer(Raw):
            try:
                raw = bytes(pkt[Raw].load).decode("utf-8", errors="ignore")
                if any(raw.startswith(m) for m in ("GET ", "POST ", "HEAD ", "OPTIONS ", "CONNECT ")):
                    indicators = {}
                    for line in raw.split("\r\n"):
                        low = line.lower()
                        if low.startswith("via:"):
                            indicators["via"] = line[4:].strip()[:200]
                        elif low.startswith("x-forwarded-for:"):
                            indicators["x_forwarded_for"] = line[16:].strip()[:100]
                        elif low.startswith("x-real-ip:"):
                            indicators["x_real_ip"] = line[10:].strip()[:50]
                        elif low.startswith("user-agent:"):
                            indicators["user_agent"] = line[11:].strip()[:150]
                    if indicators:
                        _emit({
                            "event_type": "http_proxy_headers",
                            "topic":      KAFKA_TOPIC,
                            "timestamp":  now,
                            "src_ip":     ip.src,
                            "dst_ip":     ip.dst,
                            **indicators,
                        })
            except Exception:
                pass

    # 4 ── DNS EDNS(0) fingerprinting ──────────────────────────────────────────
    if pkt.haslayer(DNS) and pkt.haslayer(UDP):
        dns = pkt[DNS]
        if dns.arcount and dns.ar:
            try:
                rr = dns.ar              # first additional record
                if rr.type == 41:        # OPT record → EDNS(0)
                    query_name = ""
                    if dns.qd:
                        query_name = bytes(dns.qd.qname).decode(
                            "utf-8", errors="ignore"
                        ).rstrip(".")
                    _emit({
                        "event_type":        "dns_edns",
                        "topic":             KAFKA_TOPIC,
                        "timestamp":         now,
                        "src_ip":            ip.src,
                        "dst_ip":            ip.dst,
                        "query":             query_name[:200],
                        "edns_payload_size": rr.rclass,
                        "edns_do_bit":       bool((rr.ttl >> 15) & 1),
                    })
            except Exception:
                pass


def main():
    scapy_conf.verb = 0
    logger.info(
        f"Passive fingerprint sensor starting — iface={INTERFACE}, topic={KAFKA_TOPIC}"
    )
    sniff(
        iface=INTERFACE,
        filter="tcp or (udp port 53)",
        prn=process_pkt,
        store=False,
    )


if __name__ == "__main__":
    main()
