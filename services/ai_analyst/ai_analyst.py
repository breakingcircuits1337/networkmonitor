#!/usr/bin/env python3
"""
ai_analyst — Background Ollama analysis worker for NetworkMonitor.

Architecture:
  kafka_consumer_worker  — subscribes to event topics, routes to queues
  immediate_worker       — analyzes high-severity alerts without delay
  batch_worker           — accumulates lower-priority events, flushes every window

All results are published to Kafka topic `ai.analysis` and written to Neo4j
as AIAnalysis nodes linked to source assets.
"""
import json
import logging
import queue
import threading
import time
import uuid
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify
from kafka import KafkaConsumer, KafkaProducer
from neo4j import GraphDatabase
from common.config import get_env

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s %(message)s",
)
log = logging.getLogger("ai_analyst")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
KAFKA_BOOTSTRAP      = get_env("KAFKA_BOOTSTRAP",      "localhost:9092")
OLLAMA_URL           = get_env("OLLAMA_URL",           "http://host.docker.internal:11434")
OLLAMA_MODEL         = get_env("OLLAMA_MODEL",         "aratan/Ministral-3-14B-Reasoning-2512:latest")
# Secondary model — used for threat narratives and deep security analysis.
# cybersecserver/matrix-ai is security-domain-tuned; used for summaries + high-severity deep dives.
SECONDARY_MODEL      = get_env("SECONDARY_MODEL",      "cybersecserver/matrix-ai:latest")
NEO4J_URI            = get_env("NEO4J_URI",            "bolt://neo4j:7687")
NEO4J_USER           = get_env("NEO4J_USER",           "neo4j")
NEO4J_PASSWORD       = get_env("NEO4J_PASSWORD",       "neo4jpassword")
ANALYSIS_TOPICS      = get_env("ANALYSIS_TOPICS",      "alert.correlated,security.alerts,dpi.events,voip.events").split(",")
BATCH_WINDOW_SECONDS = int(get_env("BATCH_WINDOW_SECONDS", "30"))
IMMEDIATE_SEVERITY   = int(get_env("IMMEDIATE_SEVERITY",   "2"))   # Suricata: 1=critical,2=high,3=med,4=low
MAX_BATCH_SIZE           = int(get_env("MAX_BATCH_SIZE",           "20"))  # max events included in a batch prompt
HTTP_PORT                = int(get_env("HTTP_PORT",                "5001"))
SUMMARY_INTERVAL_MINUTES = int(get_env("SUMMARY_INTERVAL_MINUTES", "60"))
SUMMARY_INTERVAL_SECONDS = SUMMARY_INTERVAL_MINUTES * 60

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
_stats = {
    "analyzed": 0,
    "errors": 0,
    "block_recommended": 0,
    "started_at": datetime.now(timezone.utc).isoformat(),
}
_recent_analyses = []    # ring buffer — last 20 results
_hourly_buffer: list = []  # [(ts_float, analysis)] pruned to 2× summary interval
_latest_summary: dict = {} # last generated ThreatSummary
_state_lock = threading.Lock()

_immediate_q: queue.Queue = queue.Queue()
_batch_q: queue.Queue = queue.Queue()

# Limit concurrent Ollama requests — 14B model can't handle 7 simultaneous calls
_ollama_sem = threading.Semaphore(1)

# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------
_ollama_cache = {"ok": False, "ts": 0.0}
OLLAMA_TTL = 30


def ollama_available() -> bool:
    now = time.time()
    if now - _ollama_cache["ts"] > OLLAMA_TTL:
        try:
            r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=3)
            _ollama_cache["ok"] = r.status_code == 200
        except Exception:
            _ollama_cache["ok"] = False
        _ollama_cache["ts"] = now
    return _ollama_cache["ok"]


def ollama_text(prompt: str, model: str = None) -> str:
    """Query Ollama for a natural language response — no JSON enforcement.

    Uses SECONDARY_MODEL by default for threat narratives (security-tuned).
    Falls back to primary OLLAMA_MODEL if secondary is unavailable.
    """
    use_model = model or SECONDARY_MODEL
    with _ollama_sem:
        try:
            r = requests.post(
                f"{OLLAMA_URL}/api/generate",
                json={
                    "model": use_model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.4, "num_predict": 400},
                },
                timeout=180,
            )
            if r.status_code == 200:
                text = r.json().get("response", "").strip()
                if text:
                    log.debug(f"[{use_model}] narrative generated ({len(text)} chars)")
                    return text
        except Exception as e:
            log.warning(f"Ollama [{use_model}] text error: {e}")

        # Fallback to primary model if secondary failed
        if use_model != OLLAMA_MODEL:
            log.info(f"Secondary model unavailable — falling back to {OLLAMA_MODEL}")
            try:
                r = requests.post(
                    f"{OLLAMA_URL}/api/generate",
                    json={
                        "model": OLLAMA_MODEL,
                        "prompt": prompt,
                        "stream": False,
                        "options": {"temperature": 0.4, "num_predict": 300},
                    },
                    timeout=180,
                )
                if r.status_code == 200:
                    return r.json().get("response", "").strip()
            except Exception as e:
                log.warning(f"Ollama [{OLLAMA_MODEL}] fallback error: {e}")
    return ""


def ollama_analyze(prompt: str, model: str = None) -> dict:
    """Query Ollama with JSON mode enforced. Returns parsed dict or empty dict.

    Uses a semaphore to serialize requests — the 14B model can't handle
    multiple concurrent calls within the timeout window.
    """
    use_model = model or OLLAMA_MODEL
    with _ollama_sem:
        try:
            r = requests.post(
                f"{OLLAMA_URL}/api/generate",
                json={
                    "model": use_model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0.1, "num_predict": 128},
                },
                timeout=300,
            )
            if r.status_code == 200:
                return json.loads(r.json().get("response", "{}"))
        except Exception as e:
            log.warning(f"Ollama [{use_model}] analyze error: {e}")
    return {}


# ---------------------------------------------------------------------------
# Rule-based fast analysis (CPU-friendly fallback for slow Ollama hardware)
# ---------------------------------------------------------------------------
_SIG_PATTERNS = [
    ("port_scan",       ["scan", "sweep", "probe", "nmap", "masscan"]),
    ("brute_force",     ["brute", "ssh login", "auth fail", "credential"]),
    ("c2_beacon",       ["beacon", "c2", "command and control", "trojan", "cobalt strike", "metasploit"]),
    ("data_exfil",      ["exfil", "data transfer", "upload", "large outbound"]),
    ("exploit",         ["exploit", "overflow", "shellcode", "rop", "cve-", "injection"]),
    ("recon",           ["recon", "fingerprint", "banner grab", "version detect", "os detect"]),
    ("voip_abuse",      ["sip", "invite flood", "register", "toll fraud", "voip"]),
    ("dns_tunnel",      ["dns", "tunnel", "dga", "domain generation"]),
    ("lateral_movement",["lateral", "smb", "rdp", "wmi", "pass-the-hash", "kerberos"]),
]

_SURICATA_SEV_MAP = {1: "critical", 2: "high", 3: "medium", 4: "low"}

_RECO_MAP = {
    "critical": "block",
    "high":     "block",
    "medium":   "investigate",
    "low":      "monitor",
    "info":     "ignore",
}


def fast_analyze(event: dict, topic: str) -> dict:
    """Deterministic rule-based analysis — runs in microseconds, always succeeds."""
    # --- severity ---
    raw_sev = (
        event.get("alert", {}).get("severity")
        or event.get("severity")
        or event.get("sev")
        or 4
    )
    try:
        sev_label = _SURICATA_SEV_MAP.get(int(raw_sev), "low")
    except (ValueError, TypeError):
        sev_label = str(raw_sev).lower() if isinstance(raw_sev, str) else "low"
        if sev_label not in _SURICATA_SEV_MAP.values():
            sev_label = "low"

    # --- signature/summary text ---
    sig = (
        event.get("alert", {}).get("signature")
        or event.get("signature")
        or event.get("alert_signature")
        or event.get("proto", "")
        or ""
    )
    sig_lower = sig.lower()

    # --- threat type from signature patterns ---
    threat_type = "unknown"
    for ttype, keywords in _SIG_PATTERNS:
        if any(kw in sig_lower for kw in keywords):
            threat_type = ttype
            break

    # DPI/flow-specific overrides
    if topic == "voip.events":
        threat_type = "voip_abuse" if threat_type == "unknown" else threat_type
    elif topic in ("netflow", "raw.flows") and threat_type == "unknown":
        bytes_ = event.get("bytes", 0)
        threat_type = "data_exfil" if bytes_ > 10_000_000 else "normal"

    # --- source IP ---
    src_ip = event.get("src_ip") or event.get("alert", {}).get("src_ip") or ""
    dst_ip = event.get("dest_ip") or event.get("dst_ip") or ""

    summary = (
        sig if sig else f"{topic} event from {src_ip}"
    )[:100]

    return {
        "severity":       sev_label,
        "confidence":     0.7,
        "threat_type":    threat_type,
        "src_ip":         src_ip,
        "summary":        summary,
        "recommendation": _RECO_MAP.get(sev_label, "monitor"),
        "reasoning":      (
            f"Rule-based triage: sig={sig[:60]!r} sev={raw_sev} "
            f"src={src_ip} dst={dst_ip} topic={topic}"
        ),
    }


# ---------------------------------------------------------------------------
# Neo4j
# ---------------------------------------------------------------------------
_driver = None


def get_driver():
    global _driver
    if _driver is None:
        try:
            _driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        except Exception as e:
            log.warning(f"Neo4j connect failed: {e}")
    return _driver


def ensure_constraints():
    drv = get_driver()
    if not drv:
        return
    try:
        with drv.session() as s:
            s.run(
                "CREATE CONSTRAINT IF NOT EXISTS "
                "FOR (a:AIAnalysis) REQUIRE a.event_id IS UNIQUE"
            )
            s.run(
                "CREATE CONSTRAINT IF NOT EXISTS "
                "FOR (s:ThreatSummary) REQUIRE s.summary_id IS UNIQUE"
            )
    except Exception as e:
        log.warning(f"Neo4j constraint error: {e}")


def neo4j_write(analysis: dict):
    drv = get_driver()
    if not drv:
        return
    try:
        with drv.session() as s:
            s.run(
                """
                MERGE (a:AIAnalysis {event_id: $event_id})
                SET a.timestamp      = $timestamp,
                    a.source_topic   = $source_topic,
                    a.severity       = $severity,
                    a.confidence     = $confidence,
                    a.threat_type    = $threat_type,
                    a.src_ip         = $src_ip,
                    a.summary        = $summary,
                    a.recommendation = $recommendation,
                    a.reasoning      = $reasoning,
                    a.batch_size     = $batch_size
                WITH a
                OPTIONAL MATCH (asset:Asset {ip: $src_ip})
                FOREACH (_ IN CASE WHEN asset IS NOT NULL THEN [1] ELSE [] END |
                    MERGE (asset)-[:HAS_ANALYSIS]->(a)
                )
                """,
                event_id     = analysis["event_id"],
                timestamp    = analysis["timestamp"],
                source_topic = analysis["source_topic"],
                severity     = analysis["severity"],
                confidence   = analysis["confidence"],
                threat_type  = analysis["threat_type"],
                src_ip       = analysis.get("src_ip", ""),
                summary      = analysis["summary"],
                recommendation = analysis["recommendation"],
                reasoning    = analysis["reasoning"],
                batch_size   = analysis.get("batch_size", 1),
            )
    except Exception as e:
        log.warning(f"Neo4j write error: {e}")


def neo4j_write_summary(summary: dict):
    drv = get_driver()
    if not drv:
        return
    try:
        with drv.session() as s:
            s.run(
                """
                MERGE (ts:ThreatSummary {summary_id: $summary_id})
                SET ts.timestamp         = $timestamp,
                    ts.period_minutes    = $period_minutes,
                    ts.total_analyzed    = $total_analyzed,
                    ts.block_recommended = $block_recommended,
                    ts.narrative         = $narrative
                """,
                summary_id       = summary["summary_id"],
                timestamp        = summary["timestamp"],
                period_minutes   = summary["period_minutes"],
                total_analyzed   = summary["total_analyzed"],
                block_recommended= summary["block_recommended"],
                narrative        = summary["narrative"],
            )
        log.info(f"ThreatSummary written to Neo4j: {summary['summary_id']}")
    except Exception as e:
        log.warning(f"Neo4j ThreatSummary write error: {e}")


# ---------------------------------------------------------------------------
# Kafka producer
# ---------------------------------------------------------------------------
_producer = None


def get_producer():
    global _producer
    if _producer is None:
        try:
            _producer = KafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                retries=3,
            )
        except Exception as e:
            log.warning(f"Kafka producer init error: {e}")
    return _producer


def publish(analysis: dict):
    prod = get_producer()
    if prod:
        try:
            prod.send("ai.analysis", analysis)
        except Exception as e:
            log.warning(f"Kafka publish error: {e}")


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------
_TRIAGE_PROMPT = """\
You are a network security analyst AI. Analyze the security event below and respond ONLY with a JSON object.

Event topic: {topic}
Event data:
{event_json}

Respond with exactly this JSON structure (no extra keys):
{{
  "severity":       "critical|high|medium|low|info",
  "confidence":     <float 0.0-1.0>,
  "threat_type":    "port_scan|c2_beacon|data_exfil|brute_force|voip_abuse|exploit|recon|lateral_movement|unknown",
  "src_ip":         "<source IP, or empty string if unknown>",
  "summary":        "<one concise sentence>",
  "recommendation": "block|monitor|investigate|ignore",
  "reasoning":      "<2-3 sentences explaining your assessment>"
}}"""

_BATCH_PROMPT = """\
You are a network security analyst AI. Analyze this batch of {count} events from topic `{topic}` \
(last {window}s) and respond ONLY with a JSON object.

Events:
{events_text}

Respond with exactly this JSON structure (no extra keys):
{{
  "severity":       "critical|high|medium|low|info",
  "confidence":     <float 0.0-1.0>,
  "threat_type":    "port_scan|c2_beacon|data_exfil|brute_force|anomaly|normal|unknown",
  "src_ip":         "<top offending IP, or empty string>",
  "summary":        "<one sentence describing the batch>",
  "recommendation": "block|monitor|investigate|ignore",
  "reasoning":      "<2-3 sentences on notable patterns>"
}}"""


def _format_event(e: dict, topic: str) -> str:
    if topic in ("security.alerts", "alert.correlated"):
        sig = e.get("alert", {}).get("signature") or e.get("signature", "?")
        sev = e.get("alert", {}).get("severity") or e.get("severity", "?")
        return f"  [{sev}] {sig} | {e.get('src_ip','?')} -> {e.get('dest_ip','?')}"
    if topic == "dpi.events":
        return (
            f"  {e.get('proto','?')} {e.get('src_ip','?')}:{e.get('src_port','?')}"
            f" -> {e.get('dst_ip','?')}:{e.get('dst_port','?')}"
            f" app={e.get('app_proto','?')}"
        )
    if topic == "voip.events":
        return f"  {e.get('method','?')} from {e.get('src_ip','?')} to {e.get('dst_ip','?')}"
    if topic == "netflow":
        return f"  {e.get('src_ip','?')} -> {e.get('dst_ip','?')} {e.get('bytes',0)} bytes"
    return f"  {json.dumps(e)[:120]}"


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------
def _make_analysis(raw: dict, topic: str, original: dict = None, batch_size: int = 1) -> dict:
    return {
        "event_id":      str(uuid.uuid4()),
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "source_topic":  topic,
        "original_event": original or {},
        "severity":      raw.get("severity", "unknown"),
        "confidence":    float(raw.get("confidence", 0.0)),
        "threat_type":   raw.get("threat_type", "unknown"),
        "src_ip":        raw.get("src_ip", (original or {}).get("src_ip", "")),
        "summary":       raw.get("summary", ""),
        "recommendation": raw.get("recommendation", "ignore"),
        "reasoning":     raw.get("reasoning", ""),
        "batch_size":    batch_size,
    }


def record(analysis: dict):
    publish(analysis)
    neo4j_write(analysis)
    with _state_lock:
        _stats["analyzed"] += 1
        if analysis["recommendation"] == "block":
            _stats["block_recommended"] += 1
        _recent_analyses.append(analysis)
        if len(_recent_analyses) > 20:
            _recent_analyses.pop(0)
        # Feed hourly buffer; prune entries older than 2× summary interval
        ts = time.time()
        _hourly_buffer.append((ts, analysis))
        cutoff = ts - (SUMMARY_INTERVAL_SECONDS * 2)
        while _hourly_buffer and _hourly_buffer[0][0] < cutoff:
            _hourly_buffer.pop(0)
    log.info(
        "[%s] %s | src=%s | %s | -> %s",
        analysis["source_topic"],
        analysis["severity"].upper(),
        analysis.get("src_ip", "?"),
        analysis["summary"][:80],
        analysis["recommendation"],
    )


_DEEP_DIVE_PROMPT = """\
You are a cybersecurity expert. A critical/high severity security event was detected.
Provide a detailed threat assessment including attack vector, potential impact, \
affected assets, and specific mitigation steps.

Event topic: {topic}
Initial triage: severity={severity}, threat_type={threat_type}, recommendation={recommendation}
Source IP: {src_ip}

Full event:
{event_json}

Write a focused 3-5 sentence security assessment with actionable recommendations."""


def analyze_single(event: dict, topic: str):
    """Triage a single event — uses fast rule-based analysis."""
    raw = fast_analyze(event, topic)
    if not raw:
        with _state_lock:
            _stats["errors"] += 1
        return
    record(_make_analysis(raw, topic, original=event))


def analyze_batch(events: list, topic: str):
    """Triage a batch by analyzing each event with fast rule-based analysis,
    then rolling up a single representative result (worst severity)."""
    if not events:
        return
    results = [fast_analyze(e, topic) for e in events[:MAX_BATCH_SIZE]]
    # Pick highest severity
    _order = ["critical", "high", "medium", "low", "info", "unknown"]
    results.sort(key=lambda r: _order.index(r.get("severity", "unknown")) if r.get("severity", "unknown") in _order else 99)
    best = results[0] if results else {}
    if not best:
        return
    # Build a batch summary
    threat_counts: dict = {}
    for r in results:
        tt = r.get("threat_type", "unknown")
        threat_counts[tt] = threat_counts.get(tt, 0) + 1
    top_threat = max(threat_counts, key=threat_counts.get)
    best["summary"] = f"Batch of {len(events)}: top threat={top_threat} ({threat_counts[top_threat]} events), worst={best.get('severity','?')}"
    best["reasoning"] = f"Rule-based batch triage: {dict(list(threat_counts.items())[:5])}"
    record(_make_analysis(best, topic, batch_size=len(events)))


# ---------------------------------------------------------------------------
# Workers
# ---------------------------------------------------------------------------
def immediate_worker():
    """Analyzes high-severity alerts as soon as they arrive."""
    log.info("immediate_worker started")
    while True:
        try:
            topic, event = _immediate_q.get(timeout=1)
            analyze_single(event, topic)
        except queue.Empty:
            pass
        except Exception as e:
            log.error(f"immediate_worker error: {e}")


def batch_worker():
    """Collects lower-priority events and flushes every BATCH_WINDOW_SECONDS."""
    log.info(f"batch_worker started (window={BATCH_WINDOW_SECONDS}s)")
    batches: dict = {t: [] for t in ANALYSIS_TOPICS}
    last_flush = time.time()

    while True:
        # Drain the batch queue
        while not _batch_q.empty():
            try:
                topic, event = _batch_q.get_nowait()
                if topic in batches:
                    batches[topic].append(event)
            except queue.Empty:
                break

        if time.time() - last_flush >= BATCH_WINDOW_SECONDS:
            for topic, events in batches.items():
                if events:
                    log.info(f"Flushing batch: {len(events)} events from {topic}")
                    analyze_batch(events, topic)
                    batches[topic] = []
            last_flush = time.time()

        time.sleep(1)


def kafka_consumer_worker():
    """Consumes Kafka topics and routes events to the appropriate queue."""
    log.info(f"kafka_consumer_worker starting — topics={ANALYSIS_TOPICS}")
    while True:
        try:
            consumer = KafkaConsumer(
                *ANALYSIS_TOPICS,
                bootstrap_servers=KAFKA_BOOTSTRAP,
                group_id="ai-analyst",
                auto_offset_reset="latest",
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                enable_auto_commit=True,
                consumer_timeout_ms=5000,
            )
            log.info("Kafka consumer connected")
            for msg in consumer:
                event = msg.value
                topic = msg.topic

                # Route IDS/correlated alerts by severity
                if topic in ("security.alerts", "alert.correlated"):
                    try:
                        sev = int(
                            event.get("alert", {}).get("severity")
                            or event.get("severity")
                            or 99
                        )
                    except (ValueError, TypeError):
                        sev = 99
                    if sev <= IMMEDIATE_SEVERITY:
                        _immediate_q.put((topic, event))
                        continue

                # Everything else (low-sev alerts, DPI, VoIP, flows) → batch
                _batch_q.put((topic, event))

        except Exception as e:
            log.error(f"kafka_consumer_worker error: {e} — retrying in 5s")
            time.sleep(5)


# ---------------------------------------------------------------------------
# Scheduled threat summary
# ---------------------------------------------------------------------------
_SUMMARY_PROMPT = """\
Write a concise threat intelligence summary for a security analyst.
Cover: overall threat level, key events, top offending IPs, recommended priority action.
Be specific and actionable. 3-4 sentences max.

Report period: last {period_minutes} minutes
Total events analyzed: {total}
Severity breakdown: {severities}
Threat types detected: {threat_types}
Block recommended for {block_count} IPs
Top source IPs: {top_ips}

Notable events:
{notable}"""


def generate_threat_summary(analyses: list) -> dict:
    """Generate an Ollama narrative + stats for the analysis window."""
    from collections import Counter

    severities   = Counter(a.get("severity", "unknown") for a in analyses)
    threat_types = Counter(
        a.get("threat_type") for a in analyses
        if a.get("threat_type") not in ("unknown", "normal", None)
    )
    block_recs = [a for a in analyses if a.get("recommendation") == "block"]
    top_ips    = Counter(a.get("src_ip") for a in analyses if a.get("src_ip")).most_common(5)

    notable_lines = [
        f"  - [{a.get('severity','?')}] {a.get('summary','(no summary)')}"
        for a in analyses[-10:]
    ]

    prompt = _SUMMARY_PROMPT.format(
        period_minutes = SUMMARY_INTERVAL_MINUTES,
        total          = len(analyses),
        severities     = dict(severities),
        threat_types   = dict(threat_types) or "none",
        block_count    = len(block_recs),
        top_ips        = [ip for ip, _ in top_ips] or "none",
        notable        = "\n".join(notable_lines) or "  (none)",
    )

    narrative = ollama_text(prompt)

    return {
        "summary_id":       str(uuid.uuid4()),
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "period_minutes":   SUMMARY_INTERVAL_MINUTES,
        "total_analyzed":   len(analyses),
        "severity_counts":  dict(severities),
        "threat_types":     dict(threat_types),
        "block_recommended": len(block_recs),
        "top_ips":          [{"ip": ip, "count": c} for ip, c in top_ips],
        "narrative":        narrative or "No significant threats detected in this period.",
    }


def summarizer_worker():
    """Wakes every SUMMARY_INTERVAL_SECONDS, generates and stores a ThreatSummary."""
    global _latest_summary
    log.info(f"summarizer_worker started (interval={SUMMARY_INTERVAL_MINUTES}min)")
    # Wait one full interval before the first run so there's data to summarise
    time.sleep(SUMMARY_INTERVAL_SECONDS)
    while True:
        try:
            cutoff = time.time() - SUMMARY_INTERVAL_SECONDS
            with _state_lock:
                recent = [a for ts, a in _hourly_buffer if ts >= cutoff]

            log.info(f"Generating threat summary from {len(recent)} analyses in the last {SUMMARY_INTERVAL_MINUTES}min...")

            if not ollama_available():
                log.warning("Ollama unavailable — skipping summary generation")
            elif not recent:
                log.info("No analyses in last period — skipping summary")
            else:
                summary = generate_threat_summary(recent)
                neo4j_write_summary(summary)
                with _state_lock:
                    _latest_summary = summary
                log.info(f"Threat summary generated: {summary['narrative'][:100]}...")
        except Exception as e:
            log.error(f"summarizer_worker error: {e}")
        time.sleep(SUMMARY_INTERVAL_SECONDS)


# ---------------------------------------------------------------------------
# Sub-agent role system
# ---------------------------------------------------------------------------

# Each role's specialized prompt template.
# All produce the standard ai.analysis JSON schema + optional extra fields.
_ROLE_PROMPTS = {

    "threat_hunter": """\
You are an elite APT threat hunter. Analyze this security event for advanced threats:
- C2 beaconing indicators, lateral movement, privilege escalation, persistence
- Living-off-the-land binaries, known APT TTPs, supply chain indicators
- Unusual outbound connections, DNS anomalies, credential abuse

Event (topic: {topic}):
{event_json}

Respond ONLY with this JSON (no extra keys):
{{
  "severity":       "critical|high|medium|low|info",
  "confidence":     <float 0.0-1.0>,
  "threat_type":    "apt|c2_beacon|lateral_movement|persistence|privilege_esc|data_exfil|recon|unknown",
  "src_ip":         "<source IP or empty>",
  "summary":        "<one concise sentence>",
  "recommendation": "block|isolate|monitor|investigate|ignore",
  "reasoning":      "<2-3 sentences on APT indicators observed>",
  "mitre_tactic":   "<MITRE ATT&CK tactic name or empty>"
}}""",

    "traffic_analyst": """\
You are a network traffic behavioral analyst. Analyze this batch of {count} flow/DPI \
events from the last {window}s. Look for:
- Beaconing (regular time intervals to external hosts)
- Data exfiltration (large sustained outbound transfers)
- Port scanning / service enumeration
- DNS tunneling, protocol anomalies, unexpected app protocols

Events:
{events_text}

Respond ONLY with this JSON (no extra keys):
{{
  "severity":       "critical|high|medium|low|info",
  "confidence":     <float 0.0-1.0>,
  "threat_type":    "beaconing|data_exfil|port_scan|dns_tunnel|protocol_anomaly|normal|unknown",
  "src_ip":         "<top offending IP or empty>",
  "summary":        "<one sentence on observed pattern>",
  "recommendation": "block|monitor|investigate|ignore",
  "reasoning":      "<2-3 sentences on behavioral indicators>",
  "pattern":        "<specific pattern name detected>"
}}""",

    "incident_responder": """\
You are a senior incident responder. A threat has been detected. Generate a \
MITRE ATT&CK-mapped incident response plan with concrete containment steps.

Triggering analysis:
{event_json}

Respond ONLY with this JSON (no extra keys):
{{
  "severity":         "critical|high|medium|low",
  "confidence":       <float 0.0-1.0>,
  "threat_type":      "<from triggering event>",
  "src_ip":           "<from triggering event>",
  "summary":          "<one sentence incident summary>",
  "recommendation":   "block|isolate|investigate",
  "reasoning":        "<incident context and scope>",
  "mitre_technique":  "<ATT&CK technique ID e.g. T1059.001>",
  "playbook":         ["<step 1: immediate action>", "<step 2: containment>", "<step 3: eradication>", "<step 4: recovery>"]
}}""",

    "voip_guardian": """\
You are a VoIP security specialist. Analyze this SIP/RTP event for threats:
- INVITE floods, registration hijacking, toll fraud
- Vishing campaigns, SIP scanning, RTP injection, caller ID spoofing

Event:
{event_json}

Respond ONLY with this JSON (no extra keys):
{{
  "severity":       "critical|high|medium|low|info",
  "confidence":     <float 0.0-1.0>,
  "threat_type":    "invite_flood|toll_fraud|sip_scan|vishing|rtp_injection|reg_hijack|normal|unknown",
  "src_ip":         "<source IP or empty>",
  "summary":        "<one sentence>",
  "recommendation": "block|rate_limit|monitor|ignore",
  "reasoning":      "<2-3 sentences on VoIP threat indicators>",
  "call_pattern":   "<observed SIP call behavior>"
}}""",

    "geo_intel": """\
You are a geographic threat intelligence analyst. Analyze this batch of {count} \
geo-enriched network events from the last {window}s. Identify:
- Coordinated multi-region attack campaigns
- Unusual or high-risk source countries
- Geographic anomalies vs expected traffic baseline
- Targeted vs opportunistic attack patterns

Events (country | src_ip | event_type | signature):
{events_text}

Respond ONLY with this JSON (no extra keys):
{{
  "severity":         "critical|high|medium|low|info",
  "confidence":       <float 0.0-1.0>,
  "threat_type":      "coordinated_attack|geo_anomaly|targeted_campaign|mass_scan|normal|unknown",
  "src_ip":           "<primary threat IP or empty>",
  "summary":          "<one sentence on geographic threat pattern>",
  "recommendation":   "geo_block|monitor|investigate|ignore",
  "reasoning":        "<2-3 sentences on geographic indicators>",
  "threat_countries": ["<ISO country codes>"]
}}""",

    "behavioral": """\
You are a behavioral security analyst. Review this IP's recent activity history \
and assess behavioral escalation, persistence, or reconnaissance patterns.

IP under analysis: {src_ip}
Recent activity ({event_count} events observed):
{history}

Current triggering event:
{event_json}

Respond ONLY with this JSON (no extra keys):
{{
  "severity":         "critical|high|medium|low|info",
  "confidence":       <float 0.0-1.0>,
  "threat_type":      "persistent_attacker|escalation|recon_sweep|brute_force|normal|unknown",
  "src_ip":           "{src_ip}",
  "summary":          "<one sentence behavioral profile>",
  "recommendation":   "block|monitor|investigate|ignore",
  "reasoning":        "<2-3 sentences on behavioral pattern and escalation>",
  "escalation_score": <float 0.0-1.0>
}}""",

    "malware_classifier": """\
You are a malware network traffic analyst. Analyze this event for malware indicators:
- C2 protocol fingerprints, DGA-generated domains, known malware ports
- Suspicious TLS/JA3 fingerprints, payload size patterns, keep-alive beaconing
- Known malware family network signatures

Event:
{event_json}

Respond ONLY with this JSON (no extra keys):
{{
  "severity":       "critical|high|medium|low|info",
  "confidence":     <float 0.0-1.0>,
  "threat_type":    "c2_traffic|dropper|ransomware|botnet|cryptominer|adware|normal|unknown",
  "src_ip":         "<source IP or empty>",
  "summary":        "<one sentence>",
  "recommendation": "block|isolate|monitor|ignore",
  "reasoning":      "<2-3 sentences on malware network indicators>",
  "malware_family": "<suspected family name or unknown>"
}}""",
}

# Role configuration — each entry becomes a daemon worker thread.
_ROLE_CONFIGS = [
    {
        "name":          "threat_hunter",
        "model":         SECONDARY_MODEL,   # matrix-ai: security-tuned
        "mode":          "immediate",
        "topics":        ["security.alerts", "alert.correlated"],
        "group_id":      "ai-analyst-threat-hunter",
        "severity_filter": None,            # analyze all severities
    },
    {
        "name":          "traffic_analyst",
        "model":         OLLAMA_MODEL,      # Ministral: fast pattern analysis
        "mode":          "batch",
        "topics":        ["netflow", "dpi.events"],
        "group_id":      "ai-analyst-traffic",
        "batch_window":  60,                # flush every 60s
    },
    {
        "name":          "incident_responder",
        "model":         SECONDARY_MODEL,   # matrix-ai: security reasoning
        "mode":          "immediate",
        "topics":        ["ai.analysis"],   # consumes other agents' output
        "group_id":      "ai-analyst-incident-responder",
        # Only respond to main analyst + threat_hunter critical/high findings
        "severity_filter": {"critical", "high"},
        "role_filter":   {None, "", "threat_hunter"},  # which agent_roles to accept
    },
    {
        "name":          "voip_guardian",
        "model":         OLLAMA_MODEL,      # Ministral: fast JSON
        "mode":          "immediate",
        "topics":        ["voip.events"],
        "group_id":      "ai-analyst-voip-guardian",
        "severity_filter": None,
    },
    {
        "name":          "geo_intel",
        "model":         SECONDARY_MODEL,   # matrix-ai: geopolitical reasoning
        "mode":          "batch",
        "topics":        ["geo.events"],
        "group_id":      "ai-analyst-geo-intel",
        "batch_window":  120,               # 2-minute geographic windows
    },
    {
        "name":          "behavioral",
        "model":         OLLAMA_MODEL,      # Ministral: per-IP profiling
        "mode":          "behavioral",      # special mode with IP history
        "topics":        ["security.alerts", "netflow"],
        "group_id":      "ai-analyst-behavioral",
        "trigger_count": 4,                 # events from same IP before analysis
        "history_max":   12,
    },
    {
        "name":          "malware_classifier",
        "model":         SECONDARY_MODEL,   # matrix-ai: malware domain knowledge
        "mode":          "immediate",
        "topics":        ["dpi.events", "security.alerts"],
        "group_id":      "ai-analyst-malware-classifier",
        "severity_filter": None,
    },
]

# Per-role stats — updated under _state_lock
_role_stats: dict = {cfg["name"]: {"analyzed": 0, "errors": 0} for cfg in _ROLE_CONFIGS}


def _make_role_analysis(raw: dict, topic: str, role_name: str,
                        original: dict = None, batch_size: int = 1) -> dict:
    """Build an analysis dict like _make_analysis but stamped with agent_role."""
    analysis = _make_analysis(raw, topic, original=original, batch_size=batch_size)
    analysis["agent_role"] = role_name
    # Carry through any role-specific extra fields
    for xkey in ("mitre_tactic", "mitre_technique", "playbook", "pattern",
                 "threat_countries", "escalation_score", "malware_family", "call_pattern"):
        if xkey in raw:
            analysis[xkey] = raw[xkey]
    return analysis


def _geo_format_event(e: dict) -> str:
    """Compact formatter for geo.events (has country/lat/lon fields)."""
    return (
        f"  {e.get('country','??')} | {e.get('src_ip','?')} -> {e.get('dst_ip','?')} "
        f"| {e.get('event_type','?')} | sig={e.get('signature', e.get('threat_type', ''))}"
    )


def role_worker(cfg: dict):
    """Generic sub-agent worker. Routes to specialized implementation by mode."""
    name   = cfg["name"]
    model  = cfg["model"]
    mode   = cfg["mode"]
    topics = cfg["topics"]

    log.info(f"[role:{name}] starting — mode={mode} model={model} topics={topics}")

    if mode == "behavioral":
        _behavioral_worker(cfg)
        return

    group_id        = cfg.get("group_id",        f"ai-analyst-{name}")
    batch_window    = cfg.get("batch_window",     BATCH_WINDOW_SECONDS)
    severity_filter = cfg.get("severity_filter")  # set/None
    role_filter     = cfg.get("role_filter")       # set/None (for incident_responder)

    # ── Batch state lives OUTSIDE the retry loop ─────────────────────────────
    # If the Kafka consumer times out (consumer_timeout_ms=5000) in a quiet
    # network, the for-loop exits but we must NOT lose accumulated events.
    # Moving state here ensures partial batches survive consumer reconnects.
    batch: list       = []
    last_flush: list  = [time.time()]   # 1-element list → mutable from inner scope

    def _flush_batch():
        """Analyze the current batch using fast rule-based analysis."""
        if not batch:
            return

        topic_used = batch[0][0] if batch else topics[0]
        events_only = [ev for _, ev in batch[:MAX_BATCH_SIZE]]
        results = [fast_analyze(ev, topic_used) for ev in events_only]

        if not results:
            batch.clear()
            last_flush[0] = time.time()
            return

        _order = ["critical", "high", "medium", "low", "info", "unknown"]
        results.sort(key=lambda r: _order.index(r.get("severity", "unknown")) if r.get("severity", "unknown") in _order else 99)
        best = results[0]
        threat_counts: dict = {}
        for r in results:
            tt = r.get("threat_type", "unknown")
            threat_counts[tt] = threat_counts.get(tt, 0) + 1
        top_threat = max(threat_counts, key=threat_counts.get)
        best["summary"] = f"[{name}] {len(batch)} events: top={top_threat}({threat_counts[top_threat]}), worst={best.get('severity','?')}"
        best["reasoning"] = f"Rule-based batch by {name}: {dict(list(threat_counts.items())[:5])}"

        analysis = _make_role_analysis(best, topic_used, name, batch_size=len(batch))
        record(analysis)
        with _state_lock:
            _role_stats[name]["analyzed"] += 1
        log.info(
            f"[role:{name}] batch={len(batch)} "
            f"{best.get('severity','?')} | {best.get('summary','')[:60]}"
        )

        batch.clear()
        last_flush[0] = time.time()

    # ── Retry loop ────────────────────────────────────────────────────────────
    while True:
        try:
            consumer = KafkaConsumer(
                *topics,
                bootstrap_servers=KAFKA_BOOTSTRAP,
                group_id=group_id,
                auto_offset_reset="latest",
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                enable_auto_commit=True,
                consumer_timeout_ms=5000,
            )
            log.info(f"[role:{name}] Kafka consumer connected")

            if mode == "immediate":
                for msg in consumer:
                    event = msg.value
                    topic = msg.topic

                    # incident_responder: only process approved upstream roles
                    if role_filter is not None:
                        if event.get("agent_role") not in role_filter:
                            continue
                    # severity gate
                    if severity_filter is not None:
                        if event.get("severity") not in severity_filter:
                            continue

                    raw = fast_analyze(event, topic)
                    if raw:
                        analysis = _make_role_analysis(raw, topic, name, original=event)
                        record(analysis)
                        with _state_lock:
                            _role_stats[name]["analyzed"] += 1
                        log.debug(
                            f"[role:{name}] {raw.get('severity','?')} "
                            f"| {raw.get('summary','')[:60]}"
                        )
                    else:
                        with _state_lock:
                            _role_stats[name]["errors"] += 1

            elif mode == "batch":
                for msg in consumer:
                    batch.append((msg.topic, msg.value))
                    if time.time() - last_flush[0] >= batch_window:
                        _flush_batch()

                # consumer_timeout_ms fired — flush if the window has elapsed
                # (handles quiet networks where no messages arrive for >5s)
                if time.time() - last_flush[0] >= batch_window:
                    _flush_batch()

        except Exception as e:
            log.error(f"[role:{name}] error: {e} — retrying in 5s")
            time.sleep(5)


def _behavioral_worker(cfg: dict):
    """Behavioral analyst — tracks per-IP event history, triggers on repeat offenders."""
    name         = cfg["name"]
    model        = cfg["model"]
    topics       = cfg["topics"]
    group_id     = cfg.get("group_id",      "ai-analyst-behavioral")
    trigger_count = cfg.get("trigger_count", 4)
    history_max  = cfg.get("history_max",   12)

    _ip_history: dict = {}   # { ip: [event_summary, ...] }
    _ip_analyzed: dict = {}  # { ip: last_analysis_ts } — cool-down tracker
    COOLDOWN_SECONDS = 300   # re-analyze same IP at most every 5 min

    while True:
        try:
            consumer = KafkaConsumer(
                *topics,
                bootstrap_servers=KAFKA_BOOTSTRAP,
                group_id=group_id,
                auto_offset_reset="latest",
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                enable_auto_commit=True,
                consumer_timeout_ms=5000,
            )
            log.info(f"[role:{name}] behavioral worker connected (trigger={trigger_count} events/IP)")

            for msg in consumer:
                event = msg.value
                topic = msg.topic

                # Extract IP from various event formats
                src_ip = (
                    event.get("src_ip") or
                    event.get("alert", {}).get("src_ip") or
                    (event.get("id") or {}).get("orig_h") or ""
                )
                if not src_ip:
                    continue

                # Update per-IP history
                history = _ip_history.setdefault(src_ip, [])
                history.append(f"[{topic}] {str(event)[:180]}")
                if len(history) > history_max:
                    history.pop(0)

                # Trigger only after enough events AND outside cool-down window
                if len(history) < trigger_count:
                    continue
                last_ts = _ip_analyzed.get(src_ip, 0)
                if time.time() - last_ts < COOLDOWN_SECONDS:
                    continue

                raw = fast_analyze(event, topic)
                # Boost severity for repeat offenders
                repeat_count = len(history)
                if repeat_count >= trigger_count * 2:
                    if raw.get("severity") == "low":
                        raw["severity"] = "medium"
                    elif raw.get("severity") == "medium":
                        raw["severity"] = "high"
                raw["reasoning"] = (
                    f"Behavioral: {src_ip} seen {repeat_count} times. "
                    + raw.get("reasoning", "")
                )
                raw["escalation_score"] = min(1.0, repeat_count / (trigger_count * 3))
                analysis = _make_role_analysis(raw, topic, name, original=event)
                record(analysis)
                _ip_analyzed[src_ip] = time.time()
                _ip_history[src_ip] = []
                with _state_lock:
                    _role_stats[name]["analyzed"] += 1
                log.info(
                    f"[role:{name}] {src_ip} → {raw.get('severity','?')} "
                    f"escalation={raw.get('escalation_score','?'):.2f}"
                )

        except Exception as e:
            log.error(f"[role:{name}] behavioral error: {e} — retrying in 5s")
            time.sleep(5)


# ---------------------------------------------------------------------------
# Flask API
# ---------------------------------------------------------------------------
app = Flask(__name__)


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "ollama": ollama_available(),
        "primary_model": OLLAMA_MODEL,
        "secondary_model": SECONDARY_MODEL,
        "topics": ANALYSIS_TOPICS,
    })


@app.route("/api/stats")
def stats():
    with _state_lock:
        return jsonify(dict(_stats))


@app.route("/api/recent")
def recent():
    with _state_lock:
        return jsonify(_recent_analyses[-10:])


@app.route("/api/roles")
def roles():
    """Active sub-agent roles, their models, modes, and live stats."""
    with _state_lock:
        stats = dict(_role_stats)
    return jsonify({
        "roles": [
            {
                "name":    cfg["name"],
                "model":   cfg["model"],
                "mode":    cfg["mode"],
                "topics":  cfg["topics"],
                "stats":   stats.get(cfg["name"], {}),
            }
            for cfg in _ROLE_CONFIGS
        ],
        "total_analyzed": sum(s.get("analyzed", 0) for s in stats.values()),
        "total_errors":   sum(s.get("errors",   0) for s in stats.values()),
    })


@app.route("/api/summary")
def summary():
    """Return the latest scheduled ThreatSummary, or live stats if none generated yet."""
    with _state_lock:
        scheduled = dict(_latest_summary)
        recent    = list(_recent_analyses)

    if scheduled:
        scheduled["type"] = "scheduled"
        return jsonify(scheduled)

    # Fallback: live stats from ring buffer until first scheduled summary fires
    if not recent:
        return jsonify({"type": "none", "narrative": "No analyses yet.", "count": 0})

    severities = [a["severity"] for a in recent]
    threat_types = list({
        a["threat_type"] for a in recent
        if a.get("threat_type") not in ("unknown", "normal", None)
    })
    return jsonify({
        "type":              "live",
        "count":             len(recent),
        "critical":          severities.count("critical"),
        "high":              severities.count("high"),
        "block_recommended": sum(1 for a in recent if a["recommendation"] == "block"),
        "threat_types_seen": threat_types,
        "next_scheduled_in": f"{SUMMARY_INTERVAL_MINUTES}min",
        "latest":            recent[-1],
    })


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    _PLACEHOLDER_VALUES = {"", "CHANGE_ME", "neo4jpassword"}
    if NEO4J_PASSWORD in _PLACEHOLDER_VALUES:
        raise SystemExit(
            "FATAL: NEO4J_PASSWORD is not configured or still set to default. "
            "Set NEO4J_PASSWORD in .env before starting."
        )
    log.info("AI Analyst starting")
    log.info(f"  Primary model  (triage/JSON): {OLLAMA_MODEL}")
    log.info(f"  Secondary model (narratives): {SECONDARY_MODEL}")
    log.info(f"  Topics: {ANALYSIS_TOPICS}")
    log.info(f"  Batch window: {BATCH_WINDOW_SECONDS}s | Immediate severity threshold: <={IMMEDIATE_SEVERITY}")
    log.info(f"  Sub-agent roles: {[c['name'] for c in _ROLE_CONFIGS]}")

    ensure_constraints()

    # Core workers
    core_workers = [
        ("immediate-worker", immediate_worker),
        ("batch-worker",     batch_worker),
        ("kafka-consumer",   kafka_consumer_worker),
        ("summarizer",       summarizer_worker),
    ]
    for wname, target in core_workers:
        t = threading.Thread(target=target, daemon=True, name=wname)
        t.start()
        log.info(f"Started core worker: {wname}")

    # Sub-agent role workers — each gets its own daemon thread
    for cfg in _ROLE_CONFIGS:
        t = threading.Thread(
            target=role_worker,
            args=(cfg,),
            daemon=True,
            name=f"role-{cfg['name']}",
        )
        t.start()
        log.info(f"Started sub-agent: {cfg['name']} [{cfg['mode']}] → {cfg['model']}")

    app.run(host="0.0.0.0", port=HTTP_PORT, debug=False, threaded=True)
