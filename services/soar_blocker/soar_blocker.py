import os
import time
import json
import logging
import ipaddress
import shlex
import subprocess
import threading
from datetime import datetime

import requests
from kafka import KafkaConsumer, KafkaProducer
from common.config import get_env

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("soar_blocker")


def now():
    return time.time()


# ---------------------------------------------------------------------------
# Firewall Principle: IP Validation & Sanitization
# Reject any src_ip that is not a valid IPv4/IPv6 address before it can
# reach shell interpolation.  Valid IPs contain only [0-9a-fA-F:.] so they
# carry no shell metacharacters, but an explicit ipaddress parse is the
# authoritative guard.
# ---------------------------------------------------------------------------
def validate_ip(ip: str) -> bool:
    """Return True only for well-formed IPv4 or IPv6 addresses."""
    if not ip:
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Firewall Principle: Allowlisting — protect private & trusted IPs
# Private/RFC1918/loopback addresses must never be blocked by an automated
# system unless the operator explicitly opts in (BLOCK_PRIVATE_IPS=true).
# An additional per-deployment allowlist (TRUSTED_IPS) covers monitoring
# servers, admin machines, etc.
# ---------------------------------------------------------------------------
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
]


def is_private_ip(ip: str) -> bool:
    """Return True if ip belongs to a private/RFC1918/loopback range."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def build_trusted_set(trusted_str: str):
    """
    Parse TRUSTED_IPS env var (comma-separated IPs or CIDRs).
    Returns (trusted_ip_set, trusted_net_list).
    """
    trusted_ips = set()
    trusted_nets = []
    if not trusted_str:
        return trusted_ips, trusted_nets
    for entry in trusted_str.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                trusted_nets.append(ipaddress.ip_network(entry, strict=False))
            else:
                ipaddress.ip_address(entry)   # validate before storing
                trusted_ips.add(entry)
        except ValueError:
            logger.warning(f"Invalid entry in TRUSTED_IPS, ignoring: {entry!r}")
    return trusted_ips, trusted_nets


def is_trusted_ip(ip: str, trusted_ips: set, trusted_nets: list) -> bool:
    """Return True if ip is in the operator-configured allowlist."""
    if ip in trusted_ips:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in trusted_nets)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Firewall Principle: Block TTL — automatic block expiry & unblock
# Permanent iptables rules accumulate false positives that can never be
# corrected without manual intervention.  TTL-based unblocking lets the
# system re-evaluate an IP after a configurable cooling period.
# ---------------------------------------------------------------------------
_block_expiry: dict = {}   # { ip: expiry_timestamp }
_block_lock = threading.Lock()


def _do_unblock(ip: str, unblock_cmd_template: str, ttl_sec: int):
    """Executed by a Timer thread when a block's TTL expires."""
    if not validate_ip(ip):
        return
    cmd_str = unblock_cmd_template.format(ip=ip)
    try:
        subprocess.run(shlex.split(cmd_str), check=False, timeout=10)
        logger.info(f"Auto-unblocked {ip} after TTL={ttl_sec}s")
    except Exception as e:
        logger.warning(f"Unblock command failed for {ip}: {e}")
    with _block_lock:
        _block_expiry.pop(ip, None)


def schedule_unblock(ip: str, unblock_cmd_template: str, ttl_sec: int):
    """Schedule iptables rule removal after ttl_sec seconds."""
    with _block_lock:
        _block_expiry[ip] = now() + ttl_sec
    t = threading.Timer(ttl_sec, _do_unblock, args=(ip, unblock_cmd_template, ttl_sec))
    t.daemon = True
    t.start()


def is_block_active(ip: str) -> bool:
    """Return True if ip has an active (non-expired) TTL block entry."""
    with _block_lock:
        exp = _block_expiry.get(ip)
    if exp is None:
        return False
    return now() < exp


# ---------------------------------------------------------------------------
# Firewall Principle: Egress Filtering
# Blocking only the INPUT chain leaves compromised internal hosts free to
# reach out to attackers.  An optional BLOCKLIST_EGRESS_CMD adds an OUTPUT
# rule so that bidirectional communication with the threat IP is severed.
# ---------------------------------------------------------------------------

def execute_block(ip: str, ingress_cmd_template: str, egress_cmd_template,
                  unblock_cmd_template, block_ttl_sec: int) -> bool:
    """
    Execute ingress block (and optional egress block) for a validated IP.

    Uses the ipaddress-validated ip with shlex.split + shell=False to
    prevent command injection even if the env-configured template is
    unusual.  Schedules auto-unblock when block_ttl_sec > 0.
    """
    # Guard: only valid IPs reach here, but re-check defensively
    if not validate_ip(ip):
        logger.error(f"BLOCK REJECTED — invalid IP format: {ip!r}")
        return False

    # Ingress block (INPUT chain)
    ingress_cmd = ingress_cmd_template.format(ip=ip)
    try:
        subprocess.run(shlex.split(ingress_cmd), check=True, timeout=10)
        logger.info(f"Ingress blocked: {ip}")
    except Exception as e:
        logger.error(f"Ingress block command failed for {ip}: {e}")
        return False

    # Egress block (OUTPUT chain) — optional
    if egress_cmd_template:
        egress_cmd = egress_cmd_template.format(ip=ip)
        try:
            subprocess.run(shlex.split(egress_cmd), check=True, timeout=10)
            logger.info(f"Egress blocked: {ip}")
        except Exception as e:
            logger.warning(f"Egress block command failed for {ip}: {e}")

    # Schedule TTL-based unblock
    if block_ttl_sec > 0 and unblock_cmd_template:
        schedule_unblock(ip, unblock_cmd_template, block_ttl_sec)

    return True


# ---------------------------------------------------------------------------
# Firewall Principle: Alert Rate Limiting
# A single IDS alert is not sufficient evidence to justify an automatic
# block.  Requiring N alerts within a time window reduces false positives
# from noisy signatures and prevents one-shot alert injection from
# triggering blocks.
# ---------------------------------------------------------------------------
_alert_counts: dict = {}   # { ip: (count, window_start) }


def alert_rate_check(ip: str, min_alerts: int, window_sec: int) -> bool:
    """
    Return True once ip has triggered >= min_alerts within window_sec.
    Resets the counter when the window rolls over.
    """
    n = now()
    count, start = _alert_counts.get(ip, (0, n))
    if n - start > window_sec:
        count, start = 0, n   # window expired — reset
    count += 1
    _alert_counts[ip] = (count, start)
    if count < min_alerts:
        logger.debug(
            f"Rate-limit hold for {ip}: {count}/{min_alerts} alerts in {window_sec}s window"
        )
        return False
    return True


# ---------------------------------------------------------------------------
# Ollama helpers
# ---------------------------------------------------------------------------
_ollama_cache = {"ok": False, "ts": 0.0}
OLLAMA_TTL = 30


def ollama_available(ollama_url: str) -> bool:
    n = now()
    if n - _ollama_cache["ts"] > OLLAMA_TTL:
        try:
            r = requests.get(f"{ollama_url}/api/tags", timeout=3)
            _ollama_cache["ok"] = r.status_code == 200
        except Exception:
            _ollama_cache["ok"] = False
        _ollama_cache["ts"] = n
    return _ollama_cache["ok"]


_BLOCK_PROMPT = """\
You are a network security decision engine. Decide whether to block the IP below.

IP: {ip}
UEBA anomaly score: {score}

Triggering IDS alert:
{alert_json}

Recent AI triage results for this IP:
{ai_context}

Consider: false positive risk, severity, confidence in detection, whether the IP is \
internal (192.168.x.x / 10.x.x.x / 172.16-31.x.x).

Respond with ONLY this JSON (no extra keys):
{{
  "block": <true|false>,
  "confidence": <float 0.0-1.0>,
  "reason": "<one concise sentence>"
}}"""


def llm_consult(ip: str, alert: dict, score: float,
                ai_analyses: list, ollama_url: str, model: str) -> dict:
    """
    Ask Ollama whether to block the IP.
    Returns dict with keys: block (bool), confidence (float), reason (str).
    Returns None if Ollama is unavailable or errors.
    """
    ai_lines = []
    for a in ai_analyses[-3:]:
        ai_lines.append(
            f"  [{a.get('severity','?')}] {a.get('summary','?')} "
            f"(confidence={a.get('confidence','?')}, rec={a.get('recommendation','?')})"
        )
    ai_context = "\n".join(ai_lines) if ai_lines else "  No prior AI triage available."

    prompt = _BLOCK_PROMPT.format(
        ip=ip,
        score=score,
        alert_json=json.dumps(alert, indent=2)[:800],
        ai_context=ai_context,
    )
    try:
        resp = requests.post(
            f"{ollama_url}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.1, "num_predict": 256},
            },
            timeout=30,
        )
        if resp.status_code == 200:
            return json.loads(resp.json().get("response", "{}"))
    except Exception as e:
        logger.warning(f"LLM consult error for {ip}: {e}")
    return None


# ---------------------------------------------------------------------------
# AI analysis cache — consumes ai.analysis topic, keyed by src_ip
# ---------------------------------------------------------------------------
_ai_cache: dict = {}   # { ip: [analysis, ...] }  (last 5 per IP)
_ai_cache_lock = threading.Lock()
AI_CACHE_PER_IP = 5


def _ai_cache_worker(kafka_bootstrap: str):
    """Background thread: keeps a rolling cache of ai_analyst results."""
    while True:
        try:
            consumer = KafkaConsumer(
                "ai.analysis",
                bootstrap_servers=kafka_bootstrap,
                group_id="soar-blocker-ai-cache",
                auto_offset_reset="latest",
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                consumer_timeout_ms=5000,
                enable_auto_commit=True,
            )
            for msg in consumer:
                a = msg.value
                ip = a.get("src_ip", "")
                if not ip:
                    continue
                with _ai_cache_lock:
                    bucket = _ai_cache.setdefault(ip, [])
                    bucket.append(a)
                    if len(bucket) > AI_CACHE_PER_IP:
                        bucket.pop(0)
        except Exception as e:
            logger.warning(f"AI cache worker error: {e}")
            time.sleep(5)


def get_ai_analyses(ip: str) -> list:
    with _ai_cache_lock:
        return list(_ai_cache.get(ip, []))


# ---------------------------------------------------------------------------
# Block decision
# ---------------------------------------------------------------------------
def should_block(
    ip: str,
    alert: dict,
    anomaly_score: float,
    *,
    llm_enabled: bool,
    ollama_url: str,
    model: str,
    llm_min_confidence: float,
    llm_fallback_block: bool,
) -> tuple[bool, dict]:
    """
    Returns (do_block: bool, llm_result: dict).
    llm_result is {} when LLM was not used.
    """
    if not llm_enabled:
        return True, {}

    if not ollama_available(ollama_url):
        logger.warning(f"Ollama unavailable — LLM fallback={llm_fallback_block} for {ip}")
        return llm_fallback_block, {"reason": "Ollama unavailable, used fallback"}

    ai_analyses = get_ai_analyses(ip)
    result = llm_consult(ip, alert, anomaly_score, ai_analyses, ollama_url, model)

    if result is None:
        logger.warning(f"LLM consult returned None — fallback={llm_fallback_block} for {ip}")
        return llm_fallback_block, {"reason": "LLM consult failed, used fallback"}

    do_block = result.get("block", False)
    confidence = float(result.get("confidence", 0.0))
    reason = result.get("reason", "")

    logger.info(
        f"LLM decision for {ip}: block={do_block} confidence={confidence:.2f} reason={reason}"
    )

    if do_block and confidence < llm_min_confidence:
        logger.info(
            f"LLM said block but confidence {confidence:.2f} < {llm_min_confidence} — skipping"
        )
        return False, result

    return do_block, result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    kafka_bootstrap    = get_env("KAFKA_BOOTSTRAP",       "kafka:9092")
    ids_topic          = get_env("IDS_TOPIC",             "security.alerts")
    ueba_topic         = get_env("UEBA_TOPIC",            "ueba.alerts")
    severity_threshold = float(get_env("SEVERITY_THRESHOLD", "2"))
    anomaly_threshold  = float(get_env("ANOMALY_THRESHOLD",  "0.5"))
    blocklist_cmd      = get_env("BLOCKLIST_CMD",         "echo 'iptables -A INPUT -s {ip} -j DROP'")
    check_interval     = int(get_env("CHECK_INTERVAL",    "300"))

    # --- Firewall Principle: Egress Filtering ---
    # Set BLOCKLIST_EGRESS_CMD to also block outbound traffic to/from the IP.
    # Example: "iptables -A OUTPUT -d {ip} -j DROP"
    egress_cmd_raw  = get_env("BLOCKLIST_EGRESS_CMD", "").strip()
    egress_cmd      = egress_cmd_raw if egress_cmd_raw else None

    # --- Firewall Principle: Block TTL / Auto-Unblock ---
    # BLOCK_TTL_SECONDS=0 means permanent blocks (original behaviour).
    # Set to e.g. 3600 to auto-unblock after 1 hour.
    # BLOCKLIST_UNBLOCK_CMD must undo whatever BLOCKLIST_CMD does.
    # Example: "iptables -D INPUT -s {ip} -j DROP"
    block_ttl_sec   = int(get_env("BLOCK_TTL_SECONDS",    "0"))
    unblock_cmd_raw = get_env("BLOCKLIST_UNBLOCK_CMD", "").strip()
    unblock_cmd     = unblock_cmd_raw if unblock_cmd_raw else None

    # --- Firewall Principle: Alert Rate Limiting ---
    # Require MIN_ALERTS_TO_BLOCK alerts within ALERT_WINDOW_SECONDS before
    # committing to a block.  Default=1 preserves the original behaviour.
    min_alerts_to_block = int(get_env("MIN_ALERTS_TO_BLOCK",  "1"))
    alert_window_sec    = int(get_env("ALERT_WINDOW_SECONDS", "60"))

    # --- Firewall Principle: Allowlisting ---
    # Private/RFC1918 IPs are never blocked unless BLOCK_PRIVATE_IPS=true.
    # TRUSTED_IPS is a comma-separated list of IPs or CIDRs that are always
    # exempt from blocking (monitoring servers, admin hosts, etc.).
    block_private_ips = get_env("BLOCK_PRIVATE_IPS", "false").lower() == "true"
    trusted_ips_str   = get_env("TRUSTED_IPS", "")
    trusted_ips, trusted_nets = build_trusted_set(trusted_ips_str)

    # LLM config — disabled by default
    llm_enabled        = get_env("LLM_BLOCK_ENABLED",    "false").lower() == "true"
    ollama_url         = get_env("OLLAMA_URL",           "http://host.docker.internal:11434")
    ollama_model       = get_env("OLLAMA_MODEL",         "qwen2.5:7b")
    llm_min_confidence = float(get_env("LLM_BLOCK_CONFIDENCE", "0.8"))
    llm_fallback_block = get_env("LLM_FALLBACK_BLOCK",  "true").lower() == "true"

    blocklist_topic = "blocklist.actions"
    anomaly_scores  = {}   # { ip: (score, expiry_ts) }
    blocked         = set()
    ttl_sec         = 600

    logger.info(
        f"SOAR Blocker starting — "
        f"severity_threshold={severity_threshold} "
        f"anomaly_threshold={anomaly_threshold} "
        f"llm_enabled={llm_enabled} model={ollama_model if llm_enabled else 'N/A'} | "
        f"block_ttl={block_ttl_sec}s "
        f"egress_blocking={'yes' if egress_cmd else 'no'} "
        f"min_alerts={min_alerts_to_block}/{alert_window_sec}s | "
        f"block_private={block_private_ips} "
        f"trusted_entries={len(trusted_ips) + len(trusted_nets)}"
    )

    # Start AI analysis cache worker
    t = threading.Thread(
        target=_ai_cache_worker, args=(kafka_bootstrap,), daemon=True, name="ai-cache"
    )
    t.start()

    producer = KafkaProducer(
        bootstrap_servers=kafka_bootstrap,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        retries=2,
    )

    topics = [ids_topic]
    if ueba_topic:
        topics.append(ueba_topic)

    consumer = KafkaConsumer(
        *topics,
        bootstrap_servers=kafka_bootstrap,
        group_id="soar-blocker",
        auto_offset_reset="earliest",
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        enable_auto_commit=True,
        consumer_timeout_ms=10000,
    )

    last_check = now()

    try:
        while True:
            # Periodic housekeeping
            if now() - last_check > check_interval:
                # Clean expired anomaly scores
                cutoff = now() - ttl_sec
                anomaly_scores = {
                    ip: (s, exp)
                    for ip, (s, exp) in anomaly_scores.items()
                    if exp > cutoff
                }
                # Remove expired blocks from in-memory set so IPs can be
                # re-evaluated once their TTL unblock has fired.
                if block_ttl_sec > 0:
                    blocked = {ip for ip in blocked if is_block_active(ip)}
                last_check = now()

            for msg in consumer:
                topic = msg.topic
                val   = msg.value

                # UEBA anomaly score update
                if topic == ueba_topic:
                    ip    = val.get("ip") or val.get("src_ip")
                    score = float(val.get("score", 1))
                    if ip:
                        anomaly_scores[ip] = (score, now() + ttl_sec)
                        logger.debug(f"Anomaly score {score} for {ip}")
                    continue

                # IDS alert
                if topic != ids_topic:
                    continue

                src_ip   = val.get("src_ip")
                # Suricata nests severity inside alert{}; fall back to top-level
                severity = float(
                    val.get("alert", {}).get("severity")
                    or val.get("severity")
                    or 0
                )
                if not src_ip:
                    continue

                # --- Firewall Principle: IP Validation ---
                # Reject malformed or injected src_ip values before any
                # further processing or shell interpolation.
                if not validate_ip(src_ip):
                    logger.warning(f"Dropping alert with invalid src_ip: {src_ip!r}")
                    continue

                # --- Firewall Principle: Allowlisting (Private IPs) ---
                if not block_private_ips and is_private_ip(src_ip):
                    logger.debug(f"Allowlist: skipping private IP {src_ip}")
                    continue

                # --- Firewall Principle: Allowlisting (Trusted IPs) ---
                if is_trusted_ip(src_ip, trusted_ips, trusted_nets):
                    logger.info(f"Allowlist: skipping trusted IP {src_ip}")
                    continue

                score, _exp = anomaly_scores.get(src_ip, (1, now() + ttl_sec))

                # Suricata severity: 1=critical, 2=high, 3=medium, 4=low
                # Block only events with severity NUMBER <= threshold (most serious)
                if severity == 0 or severity > severity_threshold or score < anomaly_threshold:
                    continue
                if src_ip in blocked:
                    continue

                # --- Firewall Principle: Alert Rate Limiting ---
                if not alert_rate_check(src_ip, min_alerts_to_block, alert_window_sec):
                    continue

                # LLM consultation (gated by LLM_BLOCK_ENABLED)
                do_block, llm_result = should_block(
                    src_ip, val, score,
                    llm_enabled=llm_enabled,
                    ollama_url=ollama_url,
                    model=ollama_model,
                    llm_min_confidence=llm_min_confidence,
                    llm_fallback_block=llm_fallback_block,
                )

                if not do_block:
                    logger.info(f"Block skipped for {src_ip} — LLM vetoed")
                    continue

                # --- Execute block (injection-safe, egress-aware, TTL-aware) ---
                success = execute_block(
                    src_ip,
                    blocklist_cmd,
                    egress_cmd,
                    unblock_cmd,
                    block_ttl_sec,
                )
                if not success:
                    continue

                logger.info(
                    f"Blocked {src_ip} severity={severity} anomaly={score} "
                    f"llm_reason={llm_result.get('reason', 'N/A')}"
                )
                blocked.add(src_ip)

                # Publish audit event
                audit = {
                    "ip":             src_ip,
                    "severity":       severity,
                    "anomaly_score":  score,
                    "timestamp":      datetime.utcnow().isoformat() + "Z",
                    "cmd":            blocklist_cmd.format(ip=src_ip),
                    "block_ttl_sec":  block_ttl_sec,
                    "egress_blocked": egress_cmd is not None,
                    "llm_enabled":    llm_enabled,
                    "llm_block":      llm_result.get("block"),
                    "llm_confidence": llm_result.get("confidence"),
                    "llm_reason":     llm_result.get("reason"),
                }
                try:
                    producer.send(blocklist_topic, audit)
                except Exception as e:
                    logger.warning(f"Failed to publish blocklist action: {e}")

                if now() - last_check > check_interval:
                    break

    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        consumer.close()
        producer.close()
        logger.info("SOAR Blocker stopped.")


if __name__ == "__main__":
    main()
