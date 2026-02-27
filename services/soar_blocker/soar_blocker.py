import os
import time
import json
import logging
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

    # LLM config — disabled by default
    llm_enabled          = get_env("LLM_BLOCK_ENABLED",    "false").lower() == "true"
    ollama_url           = get_env("OLLAMA_URL",           "http://host.docker.internal:11434")
    ollama_model         = get_env("OLLAMA_MODEL",         "qwen2.5:7b")
    llm_min_confidence   = float(get_env("LLM_BLOCK_CONFIDENCE", "0.8"))
    llm_fallback_block   = get_env("LLM_FALLBACK_BLOCK",  "true").lower() == "true"

    blocklist_topic = "blocklist.actions"
    anomaly_scores  = {}   # { ip: (score, expiry_ts) }
    blocked         = set()
    ttl_sec         = 600

    logger.info(
        f"SOAR Blocker starting — severity_threshold={severity_threshold} "
        f"anomaly_threshold={anomaly_threshold} "
        f"llm_enabled={llm_enabled} model={ollama_model if llm_enabled else 'N/A'}"
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
            # Clean expired anomaly scores
            if now() - last_check > check_interval:
                cutoff = now() - ttl_sec
                anomaly_scores = {
                    ip: (s, exp)
                    for ip, (s, exp) in anomaly_scores.items()
                    if exp > cutoff
                }
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

                score, _exp = anomaly_scores.get(src_ip, (1, now() + ttl_sec))

                # Suricata severity: 1=critical, 2=high, 3=medium, 4=low
                # Block only events with severity NUMBER <= threshold (most serious)
                # i.e. skip if severity is too mild (number too high) or unknown (0)
                if severity == 0 or severity > severity_threshold or score < anomaly_threshold:
                    continue
                if src_ip in blocked:
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

                # Execute block
                cmd = blocklist_cmd.format(ip=src_ip)
                try:
                    subprocess.run(cmd, shell=True, check=True)
                    logger.info(
                        f"Blocked {src_ip} severity={severity} anomaly={score} "
                        f"llm_reason={llm_result.get('reason', 'N/A')}"
                    )
                except Exception as e:
                    logger.error(f"Blocklist command failed for {src_ip}: {e}")

                blocked.add(src_ip)

                # Publish audit event
                audit = {
                    "ip":           src_ip,
                    "severity":     severity,
                    "anomaly_score": score,
                    "timestamp":    datetime.utcnow().isoformat() + "Z",
                    "cmd":          cmd,
                    "llm_enabled":  llm_enabled,
                    "llm_block":    llm_result.get("block"),
                    "llm_confidence": llm_result.get("confidence"),
                    "llm_reason":   llm_result.get("reason"),
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
