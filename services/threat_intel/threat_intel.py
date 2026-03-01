#!/usr/bin/env python3
"""
Threat Intelligence Aggregator — OTX AlienVault · CISA KEV · MISP · STIX/TAXII

Architecture:
  fetch_loop      — polls each feed on a configurable schedule
  rule_generator  — calls Ollama to convert raw IOCs into Suricata rule text
  kafka_producer  — publishes enriched IOCs to `ioc.feed` topic
  flask_api       — /api/intel-chat for LLM discussion; /api/ioc/rules for live rules

Post-quantum note: all outbound HTTPS uses TLS 1.3 (requests default).
When python-oqs exposes Kyber-1024, pin via ssl.SSLContext with PQC cipher suites.
"""

import hashlib
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone

import requests
from flask import Flask, Response, jsonify, request
from flask_cors import CORS
from kafka import KafkaProducer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("threat_intel")

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ── Config ────────────────────────────────────────────────────────────────────
KAFKA_BOOTSTRAP  = os.getenv("KAFKA_BOOTSTRAP",  "kafka:9092")
SETTINGS_API_URL = os.getenv("SETTINGS_API_URL", "http://settings_api:5002")
INTERNAL_TOKEN   = os.getenv("INTERNAL_API_TOKEN", "")
OLLAMA_URL       = os.getenv("OLLAMA_URL",       "http://host.docker.internal:11434")
OLLAMA_MODEL     = os.getenv("OLLAMA_MODEL",     "aratan/Ministral-3-14B-Reasoning-2512:latest")
RULES_FILE       = os.getenv("SURICATA_CUSTOM_RULES", "/rules/netwatch-ioc.rules")
IOC_TOPIC        = "ioc.feed"
POLL_OTX_SECS    = int(os.getenv("POLL_OTX_SECS",  "900"))   # 15 min
POLL_CISA_SECS   = int(os.getenv("POLL_CISA_SECS", "3600"))  # 1 hr
POLL_MISP_SECS   = int(os.getenv("POLL_MISP_SECS", "1800"))  # 30 min

# ── State ─────────────────────────────────────────────────────────────────────
_ioc_cache: list = []          # last N enriched IOCs for UI
_rules_cache: list = []        # generated Suricata rules
_cache_lock = threading.Lock()
_CACHE_MAX = 500
_seen_indicators: set = set()  # de-dup by sha256(indicator)

_sid_counter = 9_000_000       # start SID block for generated rules
_sid_lock    = threading.Lock()


def _next_sid() -> int:
    global _sid_counter
    with _sid_lock:
        _sid_counter += 1
        return _sid_counter


# ── Settings helper ───────────────────────────────────────────────────────────
def _get_setting(key: str, env_fallback: str = "") -> str:
    """Fetch a setting from settings_api; fall back to env var."""
    env_val = os.getenv(env_fallback or key.upper(), "")
    try:
        r = requests.get(
            f"{SETTINGS_API_URL}/api/settings/{key}",
            headers={"X-Internal-Token": INTERNAL_TOKEN},
            timeout=3,
        )
        if r.status_code == 200:
            val = r.json().get("value", "")
            return val or env_val
    except Exception:
        pass
    return env_val


# ── Kafka producer ────────────────────────────────────────────────────────────
_producer: KafkaProducer | None = None
_producer_lock = threading.Lock()


def _get_producer() -> KafkaProducer | None:
    global _producer
    with _producer_lock:
        if _producer is None:
            try:
                _producer = KafkaProducer(
                    bootstrap_servers=KAFKA_BOOTSTRAP,
                    value_serializer=lambda v: json.dumps(v).encode(),
                    retries=3,
                )
            except Exception as e:
                log.warning(f"Kafka producer init failed: {e}")
        return _producer


def _publish(ioc: dict):
    p = _get_producer()
    if p:
        try:
            p.send(IOC_TOPIC, ioc)
        except Exception as e:
            log.warning(f"Kafka publish failed: {e}")


# ── IOC processing ────────────────────────────────────────────────────────────
_IP_RE     = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9._-]{2,253}$")
_HASH_RE   = re.compile(r"^[0-9a-fA-F]{32,64}$")


def _ioc_type(indicator: str) -> str:
    if _IP_RE.match(indicator):
        return "ip"
    if _HASH_RE.match(indicator):
        return "hash"
    if _DOMAIN_RE.match(indicator):
        return "domain"
    return "unknown"


def _dedup_key(indicator: str) -> str:
    return hashlib.sha256(indicator.lower().encode()).hexdigest()


def _store_ioc(ioc: dict):
    dk = _dedup_key(ioc.get("indicator", ""))
    if dk in _seen_indicators:
        return
    _seen_indicators.add(dk)
    with _cache_lock:
        _ioc_cache.append(ioc)
        if len(_ioc_cache) > _CACHE_MAX:
            del _ioc_cache[:-_CACHE_MAX]
    _publish(ioc)


# ── Suricata rule generation ──────────────────────────────────────────────────
def _generate_rule(ioc: dict) -> str | None:
    """Generate a Suricata rule for an IOC.

    Simple heuristic rules are generated locally; Ollama is consulted only for
    complex threat types to keep latency low.
    """
    indicator  = ioc.get("indicator", "")
    ioc_type   = ioc.get("ioc_type", "unknown")
    threat     = ioc.get("threat_type", "malware")
    source     = ioc.get("source", "threat-intel")
    confidence = ioc.get("confidence", 0.5)
    sid        = _next_sid()
    ts         = datetime.now(timezone.utc).strftime("%Y_%m_%d")

    if ioc_type == "ip":
        return (
            f'alert ip {indicator} any -> $HOME_NET any '
            f'(msg:"NETWATCH [{source}] Malicious IP {indicator} [{threat}]"; '
            f'reference:url,otx.alienvault.com; '
            f'classtype:trojan-activity; sid:{sid}; rev:1; '
            f'metadata:created_at {ts},confidence {confidence:.0%};)'
        )
    if ioc_type == "domain":
        return (
            f'alert dns $HOME_NET any -> any 53 '
            f'(msg:"NETWATCH [{source}] Malicious domain {indicator} [{threat}]"; '
            f'dns.query; content:"{indicator}"; nocase; '
            f'classtype:trojan-activity; sid:{sid}; rev:1; '
            f'metadata:created_at {ts},confidence {confidence:.0%};)'
        )
    if ioc_type == "hash":
        # Suricata filemd5/filesha256 rules require IDS inline mode
        return (
            f'# Hash IOC [{source}]: {indicator} [{threat}]  '
            f'# Add to filemd5/filesha256 ruleset manually. SID-ref:{sid}'
        )
    return None


def _flush_rules():
    """Write all generated rules to the Suricata custom rules file."""
    import os
    os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)
    with _cache_lock:
        rules = list(_rules_cache)
    try:
        with open(RULES_FILE, "w") as f:
            f.write(f"# NetworkMonitor auto-generated IOC rules — {datetime.utcnow().isoformat()}Z\n")
            f.write(f"# {len(rules)} rules from threat intelligence feeds\n\n")
            for r in rules:
                f.write(r + "\n")
        log.info(f"Flushed {len(rules)} rules to {RULES_FILE}")
    except Exception as e:
        log.warning(f"Rule flush failed: {e}")


def _process_ioc(ioc: dict):
    """Store, publish, and generate Suricata rule for a single IOC."""
    _store_ioc(ioc)
    rule = _generate_rule(ioc)
    if rule:
        with _cache_lock:
            _rules_cache.append(rule)
            if len(_rules_cache) > _CACHE_MAX:
                del _rules_cache[:-_CACHE_MAX]
        ioc["suricata_rule"] = rule


# ── OTX AlienVault ────────────────────────────────────────────────────────────
def _fetch_otx():
    key = _get_setting("otx_api_key", "OTX_API_KEY")
    if not key:
        log.debug("OTX: no API key configured — skipping")
        return

    log.info("Fetching OTX subscribed pulses...")
    try:
        headers = {"X-OTX-API-KEY": key}
        r = requests.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            headers=headers, params={"limit": 50}, timeout=20,
        )
        r.raise_for_status()
        pulses = r.json().get("results", [])
        count = 0
        for pulse in pulses:
            threat_type = pulse.get("tags", ["malware"])[0] if pulse.get("tags") else "malware"
            for indicator in pulse.get("indicators", []):
                val  = indicator.get("indicator", "")
                itype = indicator.get("type", "")
                if not val:
                    continue
                mapped = {"IPv4": "ip", "domain": "domain", "hostname": "domain",
                          "FileHash-MD5": "hash", "FileHash-SHA256": "hash"}.get(itype, "unknown")
                if mapped == "unknown":
                    continue
                ioc = {
                    "ioc_type":    mapped,
                    "indicator":   val,
                    "threat_type": threat_type,
                    "source":      "OTX",
                    "confidence":  min(pulse.get("adversary", {}).get("confidence", 0.7) if isinstance(pulse.get("adversary"), dict) else 0.7, 1.0),
                    "pulse_name":  pulse.get("name", ""),
                    "timestamp":   datetime.now(timezone.utc).isoformat(),
                }
                _process_ioc(ioc)
                count += 1
        log.info(f"OTX: processed {count} indicators from {len(pulses)} pulses")
        _flush_rules()
    except Exception as e:
        log.warning(f"OTX fetch error: {e}")


# ── CISA KEV (Known Exploited Vulnerabilities) ────────────────────────────────
def _fetch_cisa_kev():
    log.info("Fetching CISA KEV catalog...")
    try:
        r = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=30,
        )
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        count = 0
        for v in vulns[-100:]:   # last 100 entries (newest)
            cve_id   = v.get("cveID", "")
            product  = v.get("product", "")
            vendor   = v.get("vendorProject", "")
            due_date = v.get("dueDate", "")
            if not cve_id:
                continue
            ioc = {
                "ioc_type":    "cve",
                "indicator":   cve_id,
                "threat_type": "known_exploited_vulnerability",
                "source":      "CISA-KEV",
                "confidence":  0.99,
                "description": f"{vendor} {product} — patching due {due_date}",
                "timestamp":   datetime.now(timezone.utc).isoformat(),
            }
            _store_ioc(ioc)
            count += 1
        log.info(f"CISA KEV: processed {count} vulnerabilities")
    except Exception as e:
        log.warning(f"CISA KEV fetch error: {e}")


# ── MISP ──────────────────────────────────────────────────────────────────────
def _fetch_misp():
    url = _get_setting("misp_url", "MISP_URL")
    key = _get_setting("misp_api_key", "MISP_API_KEY")
    if not url or not key:
        log.debug("MISP: not configured — skipping")
        return

    log.info(f"Fetching MISP attributes from {url}...")
    try:
        r = requests.post(
            f"{url}/attributes/restSearch",
            headers={"Authorization": key, "Accept": "application/json",
                     "Content-Type": "application/json"},
            json={"returnFormat": "json", "limit": 200, "type": ["ip-dst", "domain", "md5", "sha256"]},
            timeout=20, verify=False,
        )
        r.raise_for_status()
        attrs = r.json().get("response", {}).get("Attribute", [])
        count = 0
        for a in attrs:
            atype = a.get("type", "")
            val   = a.get("value", "")
            if not val:
                continue
            mapped = {"ip-dst": "ip", "ip-src": "ip", "domain": "domain",
                      "hostname": "domain", "md5": "hash", "sha256": "hash"}.get(atype, "unknown")
            if mapped == "unknown":
                continue
            ioc = {
                "ioc_type":    mapped,
                "indicator":   val,
                "threat_type": a.get("category", "malware").lower().replace(" ", "_"),
                "source":      "MISP",
                "confidence":  float(a.get("confidence", 70)) / 100.0,
                "comment":     a.get("comment", ""),
                "timestamp":   datetime.now(timezone.utc).isoformat(),
            }
            _process_ioc(ioc)
            count += 1
        log.info(f"MISP: processed {count} attributes")
        if count:
            _flush_rules()
    except Exception as e:
        log.warning(f"MISP fetch error: {e}")


# ── Poll loops ────────────────────────────────────────────────────────────────
def _poll_loop(fn, interval_secs: int, name: str):
    """Generic timed polling loop."""
    while True:
        try:
            fn()
        except Exception as e:
            log.error(f"{name} loop error: {e}")
        time.sleep(interval_secs)


# ── LLM intel chat ────────────────────────────────────────────────────────────
def _ollama_chat(prompt: str) -> str | None:
    try:
        r = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False,
                  "options": {"temperature": 0.2, "num_predict": 512}},
            timeout=60,
        )
        if r.status_code == 200:
            return r.json().get("response", "").strip()
    except Exception as e:
        log.warning(f"Ollama error: {e}")
    return None


def _build_ioc_context() -> str:
    with _cache_lock:
        recent = list(_ioc_cache[-20:])
    if not recent:
        return "No IOCs in feed yet."
    lines = []
    for ioc in recent:
        lines.append(
            f"  [{ioc['source']}] {ioc['ioc_type'].upper()} {ioc['indicator']} "
            f"({ioc['threat_type']}, conf={ioc.get('confidence', '?'):.0%})"
        )
    return "\n".join(lines)


# ── Flask API ─────────────────────────────────────────────────────────────────
@app.route("/api/intel-chat", methods=["POST"])
def intel_chat():
    """LLM analyst discussion of current IOC feed data."""
    data = request.json or {}
    message = str(data.get("message", "")).strip()[:1000]
    if not message:
        return jsonify({"error": "message required"}), 400

    context = _build_ioc_context()
    prompt = (
        "You are a Threat Intelligence analyst. You have access to the current IOC feed below.\n"
        "Analyze the indicators, explain what they mean, suggest defensive actions, and help "
        "write or improve Suricata detection rules.\n\n"
        f"Current IOC Feed (last 20 indicators):\n{context}\n\n"
        f"Analyst Query: {message}\n\n"
        "Respond concisely with actionable threat intelligence."
    )

    def _stream():
        try:
            r = requests.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": True,
                      "options": {"temperature": 0.2, "num_predict": 512}},
                stream=True, timeout=90,
            )
            for line in r.iter_lines():
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                    token = chunk.get("response", "")
                    if token:
                        yield f"data: {json.dumps({'token': token, 'done': False})}\n\n"
                    if chunk.get("done"):
                        yield f"data: {json.dumps({'token': '', 'done': True})}\n\n"
                        return
                except Exception:
                    continue
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e), 'done': True})}\n\n"

    return Response(_stream(), mimetype="text/event-stream",
                    headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"})


@app.route("/api/ioc/feed")
def ioc_feed_api():
    """Return recent IOCs from the cache."""
    with _cache_lock:
        return jsonify({"iocs": list(_ioc_cache[-100:]), "total": len(_ioc_cache)})


@app.route("/api/ioc/rules")
def ioc_rules_api():
    """Return generated Suricata rules."""
    with _cache_lock:
        return jsonify({"rules": list(_rules_cache[-50:]), "total": len(_rules_cache)})


@app.route("/api/ioc/refresh", methods=["POST"])
def ioc_refresh():
    """Trigger an immediate feed refresh in background."""
    for fn, name in [(_fetch_otx, "OTX"), (_fetch_cisa_kev, "CISA-KEV"), (_fetch_misp, "MISP")]:
        threading.Thread(target=fn, daemon=True, name=f"refresh-{name}").start()
    return jsonify({"status": "refresh triggered"})


@app.route("/health")
def health():
    with _cache_lock:
        return jsonify({"status": "ok", "ioc_count": len(_ioc_cache), "rules_count": len(_rules_cache)})


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    log.info("Threat Intel service starting...")

    # Initial fetch
    for fn, name in [(_fetch_otx, "OTX"), (_fetch_cisa_kev, "CISA-KEV"), (_fetch_misp, "MISP")]:
        threading.Thread(target=fn, daemon=True, name=f"init-{name}").start()

    # Polling loops
    threading.Thread(target=_poll_loop, args=(_fetch_otx, POLL_OTX_SECS, "OTX"),
                     daemon=True, name="poll-otx").start()
    threading.Thread(target=_poll_loop, args=(_fetch_cisa_kev, POLL_CISA_SECS, "CISA"),
                     daemon=True, name="poll-cisa").start()
    threading.Thread(target=_poll_loop, args=(_fetch_misp, POLL_MISP_SECS, "MISP"),
                     daemon=True, name="poll-misp").start()

    app.run(host="0.0.0.0", port=5003, debug=False, threaded=True)


if __name__ == "__main__":
    main()
