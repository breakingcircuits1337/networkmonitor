#!/usr/bin/env python3
import os
import json
import requests
import time
import threading
from flask import Flask, request, jsonify, Response
from kafka import KafkaConsumer

app = Flask(__name__)

KAFKA_BOOTSTRAP  = os.getenv('KAFKA_BOOTSTRAP',  'localhost:9092')
OLLAMA_URL       = os.getenv('OLLAMA_URL',       'http://host.docker.internal:11434')
OLLAMA_MODEL     = os.getenv('OLLAMA_MODEL',     'glm-5:cloud')
OLLAMA_FALLBACK  = os.getenv('OLLAMA_FALLBACK',  'aratan/Ministral-3-14B-Reasoning-2512')
AI_ANALYST_URL   = os.getenv('AI_ANALYST_URL',   'http://ai_analyst:5001')

# ---------------------------------------------------------------------------
# Ollama health check with TTL (re-checks every 30s instead of caching forever)
# ---------------------------------------------------------------------------
_ollama_status = {"available": None, "checked_at": 0}
OLLAMA_CHECK_TTL = 30

def check_ollama():
    now = time.time()
    if now - _ollama_status["checked_at"] > OLLAMA_CHECK_TTL:
        try:
            resp = requests.get(f"{OLLAMA_URL}/api/tags", timeout=3)
            _ollama_status["available"] = resp.status_code == 200
        except Exception:
            _ollama_status["available"] = False
        _ollama_status["checked_at"] = now
    return _ollama_status["available"]

# ---------------------------------------------------------------------------
# Rolling event cache — background thread keeps last N events per topic
# ---------------------------------------------------------------------------
_event_cache = {
    "security.alerts": [],
    "voip.events": [],
    "netflow": [],
}
_cache_lock = threading.Lock()
CACHE_MAX = 10  # events per topic


def _cache_worker():
    """Background thread: maintains a rolling window of recent Kafka events."""
    while True:
        try:
            consumer = KafkaConsumer(
                *list(_event_cache.keys()),
                bootstrap_servers=KAFKA_BOOTSTRAP,
                group_id="sarah-api-cache",
                auto_offset_reset="latest",
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                consumer_timeout_ms=5000,
                enable_auto_commit=True,
            )
            for msg in consumer:
                with _cache_lock:
                    cache = _event_cache[msg.topic]
                    cache.append(msg.value)
                    if len(cache) > CACHE_MAX:
                        cache.pop(0)
        except Exception as e:
            print(f"Cache worker error: {e}")
            time.sleep(5)


def get_cached_events(topic=None):
    with _cache_lock:
        if topic:
            return list(_event_cache.get(topic, []))
        return {k: list(v) for k, v in _event_cache.items()}


# ---------------------------------------------------------------------------
# Scheduled threat summary (fetched from ai_analyst)
# ---------------------------------------------------------------------------
_summary_cache = {"data": None, "ts": 0.0}
SUMMARY_CACHE_TTL = 120  # re-fetch at most every 2 minutes


def get_threat_summary() -> dict:
    """Fetch the latest ThreatSummary from ai_analyst, cached for TTL seconds."""
    now = time.time()
    if now - _summary_cache["ts"] < SUMMARY_CACHE_TTL and _summary_cache["data"]:
        return _summary_cache["data"]
    try:
        r = requests.get(f"{AI_ANALYST_URL}/api/summary", timeout=5)
        if r.status_code == 200:
            data = r.json()
            _summary_cache["data"] = data
            _summary_cache["ts"] = now
            return data
    except Exception:
        pass
    return {}


# ---------------------------------------------------------------------------
# Prompt building
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """You are Sarah, an AI network security analyst assistant.
You monitor a network (192.168.1.0/24) using Suricata IDS, Zeek DPI, traffic \
flow analysis, and VoIP monitoring. All data flows through Kafka and is stored in Neo4j.

Be concise and direct. When analyzing alerts focus on:
- What the threat is and its severity
- Which IPs are involved and whether they are internal or external
- Concrete recommended actions

Respond in plain English unless explicitly asked for structured data."""


def _build_context(alerts, voip_events, flows):
    """Build a rich context string from cached events for the LLM."""
    parts = []

    if alerts:
        lines = []
        for a in alerts[-5:]:
            sig = a.get("alert", {}).get("signature") or a.get("alert_signature", "Unknown")
            src = a.get("src_ip", "?")
            dst = a.get("dest_ip", "?")
            sev = a.get("alert", {}).get("severity") or a.get("severity", "?")
            lines.append(f"  [{sev}] {sig} | {src} -> {dst}")
        parts.append("Recent IDS alerts:\n" + "\n".join(lines))
    else:
        parts.append("No recent IDS alerts.")

    if voip_events:
        lines = []
        for v in voip_events[-3:]:
            lines.append(f"  {v.get('method','?')} from {v.get('src_ip','?')}")
        parts.append("Recent VoIP events:\n" + "\n".join(lines))

    if flows:
        top = sorted(flows[-10:], key=lambda f: f.get("bytes", 0), reverse=True)[:3]
        lines = [
            f"  {f.get('src_ip','?')} -> {f.get('dst_ip','?')}: {f.get('bytes',0)} bytes"
            for f in top
        ]
        if lines:
            parts.append("Top recent flows:\n" + "\n".join(lines))

    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# Ollama query functions
# ---------------------------------------------------------------------------
def _ollama_generate(model, payload, timeout=120):
    """Raw Ollama generate call — returns response text or None."""
    try:
        resp = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": model, **payload},
            timeout=timeout,
        )
        if resp.status_code == 200:
            return resp.json().get("response", "").strip()
    except Exception as e:
        print(f"Ollama [{model}] error: {e}")
    return None


def _ollama_stream(model, full_prompt, timeout=90):
    """Stream tokens from Ollama — yields text chunks."""
    payload = {
        "model":   model,
        "prompt":  full_prompt,
        "stream":  True,
        "options": {"temperature": 0.3, "num_predict": 200},
    }
    try:
        with requests.post(
            f"{OLLAMA_URL}/api/generate",
            json=payload, stream=True, timeout=timeout,
        ) as resp:
            if resp.status_code != 200:
                return
            for line in resp.iter_lines():
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                    token = chunk.get("response", "")
                    if token:
                        yield token
                    if chunk.get("done"):
                        return
                except Exception:
                    continue
    except Exception as e:
        print(f"Ollama stream [{model}] error: {e}")


def query_ollama(prompt, context=""):
    """Natural language response — tries primary model then fallback."""
    full_prompt = (
        f"{SYSTEM_PROMPT}\n\n"
        f"--- Current Network State ---\n{context}\n\n"
        f"--- User Query ---\n{prompt}"
    )
    payload = {"prompt": full_prompt, "stream": False,
               "options": {"temperature": 0.3, "num_predict": 200}}

    result = _ollama_generate(OLLAMA_MODEL, payload, timeout=60)
    if result:
        return result, OLLAMA_MODEL

    print(f"Primary model failed, trying fallback: {OLLAMA_FALLBACK}")
    result = _ollama_generate(OLLAMA_FALLBACK, payload, timeout=60)
    if result:
        return result, OLLAMA_FALLBACK

    return None, None


def query_ollama_json(prompt):
    """Structured JSON response — tries primary model then fallback."""
    payload = {"prompt": prompt, "stream": False, "format": "json",
               "options": {"temperature": 0.1, "num_predict": 512}}
    try:
        raw = _ollama_generate(OLLAMA_MODEL, payload, timeout=60)
        if not raw:
            raw = _ollama_generate(OLLAMA_FALLBACK, payload, timeout=60)
        if raw:
            return json.loads(raw)
    except Exception as e:
        print(f"Ollama JSON error: {e}")
    return None


# ---------------------------------------------------------------------------
# Fallback keyword responses (used when Ollama is unavailable)
# ---------------------------------------------------------------------------
FALLBACK_RESPONSES = {
    "status": "Network monitoring active. Check dashboard for live flows.",
    "help": "I can help with: network status, security alerts, VoIP calls, traffic analysis.",
    "alert": "Check the map for red alert markers. Detailed logs in Neo4j.",
    "voip": "VoIP monitored on SIP:5060, RTP:10000-20000. Check dashboard.",
    "traffic": "Traffic flows captured continuously. See heatmap on dashboard.",
    "default": "I'm Sarah, your network monitoring assistant. Ask about status, alerts, VoIP, or traffic!",
}


_SUMMARY_KEYWORDS = ("summary", "report", "happened", "overview", "brief", "digest", "last hour", "recap")


def get_response(message):
    msg = message.lower()

    if check_ollama():
        events = get_cached_events()
        context = _build_context(
            events.get("security.alerts", []),
            events.get("voip.events", []),
            events.get("netflow", []),
        )
        # Inject the scheduled summary narrative for report-type questions
        if any(kw in msg for kw in _SUMMARY_KEYWORDS):
            ts = get_threat_summary()
            narrative = ts.get("narrative", "")
            if narrative:
                ts_type = ts.get("type", "")
                period  = ts.get("period_minutes", "?")
                prefix  = (
                    f"Latest threat summary ({period}min window, {ts.get('total_analyzed',0)} events analyzed):\n"
                    f"{narrative}\n\n"
                )
                context = prefix + context
        result, model_used = query_ollama(message, context)
        if result:
            return result, model_used

    # Fallback keyword matching
    if any(w in msg for w in ["status", "how", "health", "doing"]):
        return FALLBACK_RESPONSES["status"], "fallback"
    elif any(w in msg for w in ["alert", "security", "threat", "attack"]):
        return FALLBACK_RESPONSES["alert"], "fallback"
    elif any(w in msg for w in ["voip", "sip", "call", "phone"]):
        return FALLBACK_RESPONSES["voip"], "fallback"
    elif any(w in msg for w in ["traffic", "flow", "packet"]):
        return FALLBACK_RESPONSES["traffic"], "fallback"
    elif any(w in msg for w in ["help", "what can"]):
        return FALLBACK_RESPONSES["help"], "fallback"
    else:
        return FALLBACK_RESPONSES["default"], "fallback"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/api/chat/stream", methods=["POST"])
def chat_stream():
    """Streaming chat — tokens SSE'd back as they generate."""
    data    = request.json
    message = data.get("message", "")

    if not check_ollama():
        resp, _ = get_response(message)
        def _fallback():
            yield f"data: {json.dumps({'token': resp, 'done': True, 'source': 'fallback'})}\n\n"
        return Response(_fallback(), mimetype="text/event-stream")

    events  = get_cached_events()
    context = _build_context(
        events.get("security.alerts", []),
        events.get("voip.events", []),
        events.get("netflow", []),
    )
    full_prompt = (
        f"{SYSTEM_PROMPT}\n\n"
        f"--- Current Network State ---\n{context}\n\n"
        f"--- User Query ---\n{message}"
    )

    def generate():
        model = OLLAMA_MODEL
        got_any = False
        for token in _ollama_stream(model, full_prompt):
            got_any = True
            yield f"data: {json.dumps({'token': token, 'done': False, 'model': model})}\n\n"
        if not got_any:
            # fallback to secondary
            model = OLLAMA_FALLBACK
            for token in _ollama_stream(model, full_prompt):
                yield f"data: {json.dumps({'token': token, 'done': False, 'model': model})}\n\n"
        yield f"data: {json.dumps({'token': '', 'done': True, 'model': model})}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"})


@app.route("/api/chat", methods=["POST"])
def chat():
    data = request.json
    message = data.get("message", "")

    alerts = get_cached_events("security.alerts")
    response, source = get_response(message)

    is_llm = source not in (None, "fallback")
    return jsonify({
        "response": response,
        "source": "ollama" if is_llm else "fallback",
        "model": source if is_llm else "fallback",
        "ollama_available": check_ollama(),
        "alerts_count": len(alerts),
    })


@app.route("/api/summary")
def summary():
    """Proxy to ai_analyst's scheduled ThreatSummary; falls back to live snapshot."""
    data = get_threat_summary()
    if data:
        return jsonify(data)

    # ai_analyst unreachable — generate a quick live snapshot from cached events
    events = get_cached_events()
    alerts = events.get("security.alerts", [])
    voip   = events.get("voip.events", [])
    flows  = events.get("netflow", [])
    context = _build_context(alerts, voip, flows)

    if not check_ollama():
        return jsonify({
            "type": "unavailable",
            "narrative": "AI analyst and Ollama are both unavailable.",
            "alerts_count": len(alerts),
        })

    prompt = (
        "Based on the network state below provide a 3-4 sentence threat summary. "
        "Cover: threat level, top concerns, recommended action.\n\n" + context
    )
    result = query_ollama(prompt, "")
    return jsonify({
        "type":         "live_fallback",
        "narrative":    result or "No significant threats detected.",
        "alerts_count": len(alerts),
        "voip_events":  len(voip),
    })


@app.route("/api/triage", methods=["POST"])
def triage():
    """Triage a specific alert — returns structured JSON analysis."""
    alert = request.json
    if not alert:
        return jsonify({"error": "No alert provided"}), 400

    if not check_ollama():
        return jsonify({"error": "Ollama unavailable"}), 503

    prompt = (
        f"Analyze this network security alert and respond with a JSON object.\n\n"
        f"Alert:\n{json.dumps(alert, indent=2)}\n\n"
        f"Respond with exactly this JSON structure:\n"
        f'{{\n'
        f'  "severity": "critical|high|medium|low|info",\n'
        f'  "confidence": <0.0-1.0>,\n'
        f'  "threat_type": "port_scan|c2_beacon|data_exfil|brute_force|voip_abuse|exploit|recon|unknown",\n'
        f'  "summary": "<one sentence>",\n'
        f'  "recommendation": "block|monitor|investigate|ignore",\n'
        f'  "reasoning": "<brief explanation>"\n'
        f"}}"
    )

    result = query_ollama_json(prompt)
    if result:
        return jsonify(result)
    return jsonify({"error": "Analysis failed"}), 500


@app.route("/api/status")
def status():
    return jsonify({
        "ollama_available": check_ollama(),
        "ollama_url": OLLAMA_URL,
        "model": OLLAMA_MODEL,
    })


@app.route("/events")
def events():
    def generate():
        try:
            consumer = KafkaConsumer(
                "security.alerts", "voip.events", "netflow",
                bootstrap_servers=KAFKA_BOOTSTRAP,
                auto_offset_reset="latest",
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                consumer_timeout_ms=10000,
            )
            for message in consumer:
                data = message.value
                data["topic"] = message.topic
                yield f"data: {json.dumps(data)}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
    return Response(generate(), mimetype="text/event-stream")


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "ollama": check_ollama(),
        "model": OLLAMA_MODEL,
    })


if __name__ == "__main__":
    t = threading.Thread(target=_cache_worker, daemon=True)
    t.start()
    print(f"Sarah API starting...")
    print(f"Ollama: {OLLAMA_URL} ({OLLAMA_MODEL})")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
