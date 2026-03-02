#!/usr/bin/env python3
"""
Credential & Dark-Web Monitor

Integrations:
  - HaveIBeenPwned (HIBP) v3 API — email breach checks (k-anonymity for password checks)
  - HIBP Paste API — paste site monitoring
  - Periodic re-check of all configured monitored addresses

Security notes:
  - Password hashes sent to HIBP use k-anonymity (only first 5 chars of SHA1 sent).
  - All email addresses stored via settings_api (encrypted at rest).
  - Breach notifications published to `credential.alerts` Kafka topic.
  - API keys fetched dynamically from settings_api so they survive rotation.
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
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from kafka import KafkaProducer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("credential_monitor")

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})
limiter = Limiter(get_remote_address, app=app, default_limits=["60/hour"])

KAFKA_BOOTSTRAP  = os.getenv("KAFKA_BOOTSTRAP",  "kafka:9092")
SETTINGS_API_URL = os.getenv("SETTINGS_API_URL", "http://settings_api:5002")
INTERNAL_TOKEN   = os.getenv("INTERNAL_API_TOKEN", "")
CRED_TOPIC       = "credential.alerts"
CHECK_INTERVAL   = int(os.getenv("CRED_CHECK_INTERVAL", "3600"))  # 1 hr default

_breach_cache: dict = {}   # { email: [breach_record, ...] }
_paste_cache: dict  = {}   # { email: [paste_record, ...] }
_cache_lock = threading.Lock()

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
            p.send(CRED_TOPIC, event)
        except Exception as e:
            log.warning(f"Kafka publish failed: {e}")


def _get_setting(key: str, env_fallback: str = "") -> str:
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


def _get_monitored_emails() -> list[str]:
    """Return list of email addresses to monitor from settings."""
    raw = _get_setting("monitored_emails", "MONITORED_EMAILS")
    if not raw:
        return []
    _email_re = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
    return [e.strip().lower() for e in raw.split(",") if _email_re.match(e.strip())]


# ── HIBP helpers ──────────────────────────────────────────────────────────────
_HIBP_BASE = "https://haveibeenpwned.com/api/v3"
_USER_AGENT = "NetworkMonitor-CredentialMonitor/1.0"


def _hibp_headers() -> dict:
    key = _get_setting("hibp_api_key", "HIBP_API_KEY")
    h = {"User-Agent": _USER_AGENT}
    if key:
        h["hibp-api-key"] = key
    return h


def _check_email_breaches(email: str) -> list[dict]:
    """Check an email against HIBP breach database."""
    try:
        r = requests.get(
            f"{_HIBP_BASE}/breachedaccount/{email}",
            headers=_hibp_headers(),
            params={"truncateResponse": "false"},
            timeout=15,
        )
        if r.status_code == 200:
            return r.json()
        if r.status_code == 404:
            return []
        log.warning(f"HIBP breaches HTTP {r.status_code} for {email}")
    except Exception as e:
        log.warning(f"HIBP breach check error for {email}: {e}")
    return []


def _check_email_pastes(email: str) -> list[dict]:
    """Check an email against HIBP paste database."""
    try:
        r = requests.get(
            f"{_HIBP_BASE}/pasteaccount/{email}",
            headers=_hibp_headers(),
            timeout=15,
        )
        if r.status_code == 200:
            return r.json()
        if r.status_code == 404:
            return []
        log.warning(f"HIBP pastes HTTP {r.status_code} for {email}")
    except Exception as e:
        log.warning(f"HIBP paste check error for {email}: {e}")
    return []


def _check_password_pwned(password: str) -> int:
    """
    Check if a password has been seen in breaches using k-anonymity.
    Returns count of times seen (0 = not found).
    Only the first 5 characters of the SHA1 hash are sent to HIBP.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        r = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
            timeout=10,
        )
        if r.status_code == 200:
            for line in r.text.splitlines():
                h, count = line.split(":")
                if h == suffix:
                    return int(count)
    except Exception as e:
        log.warning(f"HIBP password check error: {e}")
    return 0


# ── Monitor loop ──────────────────────────────────────────────────────────────
def _check_all_emails():
    emails = _get_monitored_emails()
    if not emails:
        log.debug("No monitored emails configured")
        return

    for email in emails:
        log.info(f"Checking credentials for: {email}")
        time.sleep(1.5)  # HIBP rate limit: 1 req/1.5s

        # Breach check
        breaches = _check_email_breaches(email)
        with _cache_lock:
            prev = _breach_cache.get(email, [])
            prev_names = {b.get("Name") for b in prev}
            new_breaches = [b for b in breaches if b.get("Name") not in prev_names]
            _breach_cache[email] = breaches

        for breach in new_breaches:
            event = {
                "alert_type":   "email_breach",
                "email":        email,
                "breach_name":  breach.get("Name", "Unknown"),
                "breach_date":  breach.get("BreachDate", ""),
                "data_classes": breach.get("DataClasses", []),
                "description":  breach.get("Description", ""),
                "is_verified":  breach.get("IsVerified", False),
                "pwn_count":    breach.get("PwnCount", 0),
                "severity":     "high" if "Passwords" in breach.get("DataClasses", []) else "medium",
                "timestamp":    datetime.now(timezone.utc).isoformat(),
            }
            log.warning(f"NEW BREACH for {email}: {breach.get('Name')} ({breach.get('BreachDate')})")
            _publish(event)

        time.sleep(1.5)

        # Paste check
        pastes = _check_email_pastes(email)
        with _cache_lock:
            prev_pastes = _paste_cache.get(email, [])
            prev_paste_ids = {p.get("Id") for p in prev_pastes}
            new_pastes = [p for p in pastes if p.get("Id") not in prev_paste_ids]
            _paste_cache[email] = pastes

        for paste in new_pastes:
            event = {
                "alert_type": "paste_exposure",
                "email":      email,
                "paste_id":   paste.get("Id", ""),
                "paste_src":  paste.get("Source", ""),
                "paste_date": paste.get("Date", ""),
                "title":      paste.get("Title", ""),
                "severity":   "high",
                "timestamp":  datetime.now(timezone.utc).isoformat(),
            }
            log.warning(f"NEW PASTE for {email}: {paste.get('Source')} — {paste.get('Title')}")
            _publish(event)


def _monitor_loop():
    """Continuous monitoring loop."""
    # Wait 30s on startup to let settings_api come up
    time.sleep(30)
    while True:
        try:
            _check_all_emails()
        except (requests.exceptions.RequestException, OSError) as e:
            log.error(f"Monitor loop error: {e}")
        time.sleep(CHECK_INTERVAL)


# ── Flask API ─────────────────────────────────────────────────────────────────
@app.route("/api/credentials/status")
def cred_status():
    emails = _get_monitored_emails()
    with _cache_lock:
        summary = {}
        for email in emails:
            breaches = _breach_cache.get(email, [])
            pastes   = _paste_cache.get(email, [])
            has_passwords = any("Passwords" in b.get("DataClasses", []) for b in breaches)
            summary[email] = {
                "breach_count": len(breaches),
                "paste_count":  len(pastes),
                "password_exposed": has_passwords,
                "most_recent_breach": max((b.get("BreachDate", "") for b in breaches), default=""),
            }
    return jsonify({"monitored": emails, "status": summary})


@app.route("/api/credentials/check-password", methods=["POST"])
@limiter.limit("10/minute")
def check_password():
    """k-anonymity password check — the actual password never leaves this service."""
    data = request.json or {}
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "password required"}), 400
    if len(password) > 256:
        return jsonify({"error": "password too long"}), 400
    count = _check_password_pwned(password)
    return jsonify({
        "pwned": count > 0,
        "count": count,
        "severity": "critical" if count > 100 else "high" if count > 0 else "none",
    })


@app.route("/api/credentials/refresh", methods=["POST"])
def refresh_now():
    threading.Thread(target=_check_all_emails, daemon=True, name="cred-refresh").start()
    return jsonify({"status": "refresh triggered"})


@app.route("/health")
def health():
    emails = _get_monitored_emails()
    with _cache_lock:
        total_breaches = sum(len(v) for v in _breach_cache.values())
    return jsonify({"status": "ok", "monitored_emails": len(emails), "total_breaches": total_breaches})


if __name__ == "__main__":
    log.info("Credential Monitor starting...")
    threading.Thread(target=_monitor_loop, daemon=True, name="monitor-loop").start()
    app.run(host="0.0.0.0", port=5004, debug=False, threaded=True)
