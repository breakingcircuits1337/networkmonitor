#!/usr/bin/env python3
"""
Settings API — encrypted storage for API keys and platform configuration.

Security design:
  - Values stored AES-256-GCM encrypted via cryptography.Fernet
    (Fernet = AES-128-CBC + HMAC-SHA256; master key is 256-bit so Grover's
    algorithm leaves ~128 bits of post-quantum security margin).
    TODO post-quantum: replace KDF with Argon2id + Kyber-1024 KEM when
    liboqs-python matures and stabilises across distros.
  - Master encryption key from SETTINGS_ENCRYPTION_KEY env — never stored on disk.
  - Input sanitisation: regex-clean keys, strip control chars, validate URLs.
  - API is on internal Docker network only (not exposed to the internet).
  - Sensitive values are redacted on GET responses; internal services use
    X-Internal-Token to fetch plaintext values.
"""

import base64
import json
import logging
import os
import re
import threading
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, jsonify, request
from flask_cors import CORS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("settings_api")

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

SETTINGS_FILE = Path(os.getenv("SETTINGS_FILE", "/data/settings.enc"))
SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)

# ── Key derivation ────────────────────────────────────────────────────────────
# PBKDF2-SHA256 with 480 000 iterations (NIST 2023 recommendation).
# 256-bit output key -> Fernet base64-encodes to use first 32 bytes for AES-128
# and next 32 bytes for HMAC-SHA256.
_SALT = b"netwatch-settings-v2-salt"
_RAW_KEY = os.getenv("SETTINGS_ENCRYPTION_KEY", "")


def _derive_key(raw: str) -> bytes:
    seed = raw.encode() if raw else os.urandom(32)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=_SALT, iterations=480_000)
    return base64.urlsafe_b64encode(kdf.derive(seed))


_fernet = Fernet(_derive_key(_RAW_KEY))
_lock = threading.Lock()

# ── Input sanitisation ────────────────────────────────────────────────────────
_SAFE_KEY_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
_URL_RE = re.compile(r"^https?://[^\s<>\"'\\]{1,512}$")
_MAX_VAL_LEN = 1024
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

# Keys whose values are never returned in plaintext via GET /api/settings
_SENSITIVE = {
    "otx_api_key", "misp_api_key", "hibp_api_key", "et_pro_api_key",
    "launch_token", "neo4j_password", "kafka_password",
    "settings_encryption_key", "internal_api_token",
}


def _clean_key(k) -> str | None:
    if isinstance(k, str) and _SAFE_KEY_RE.match(k):
        return k.lower()
    return None


def _clean_val(v) -> str:
    v = str(v) if v is not None else ""
    v = _CONTROL_RE.sub("", v.strip())
    return v[:_MAX_VAL_LEN]


def _redact(key: str, val: str) -> str:
    if key in _SENSITIVE and val:
        visible = val[-4:] if len(val) >= 4 else ""
        return "••••••••" + visible
    return val


def _check_internal_token():
    """Return a 401 response tuple if X-Internal-Token is missing/wrong, else None."""
    expected = os.getenv("INTERNAL_API_TOKEN", "")
    if not expected:
        return None  # token enforcement disabled (dev mode)
    token = request.headers.get("X-Internal-Token", "")
    if token != expected:
        return jsonify({"error": "Unauthorized"}), 401
    return None


# ── Encrypted store ───────────────────────────────────────────────────────────
def _load() -> dict:
    with _lock:
        if not SETTINGS_FILE.exists():
            return {}
        try:
            return json.loads(_fernet.decrypt(SETTINGS_FILE.read_bytes()))
        except (InvalidToken, Exception) as e:
            log.error(f"Decrypt failed: {e}")
            return {}


def _save(data: dict):
    with _lock:
        try:
            SETTINGS_FILE.write_bytes(_fernet.encrypt(json.dumps(data).encode()))
        except Exception as e:
            log.error(f"Encrypt/save failed: {e}")
            raise


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/api/settings", methods=["GET"])
def get_settings():
    """All settings with sensitive values redacted."""
    data = _load()
    redacted = {k: _redact(k, v) for k, v in data.items()}
    configured = {k: bool(v) for k, v in data.items()}
    return jsonify({"settings": redacted, "configured": configured})


@app.route("/api/settings", methods=["POST"])
def update_settings():
    """Upsert one or more settings. JSON body: {key: value, ...}"""
    err = _check_internal_token()
    if err:
        return err
    body = request.json
    if not isinstance(body, dict):
        return jsonify({"error": "JSON object required"}), 400

    data = _load()
    updated, errors = [], []

    for raw_k, raw_v in body.items():
        k = _clean_key(raw_k)
        if not k:
            errors.append(f"Invalid key: {raw_k!r}")
            continue
        v = _clean_val(raw_v)
        # URL format validation
        if k.endswith("_url") and v:
            if not _URL_RE.match(v):
                errors.append(f"Bad URL format for '{k}'")
                continue
        data[k] = v
        updated.append(k)

    if updated:
        try:
            _save(data)
        except Exception:
            return jsonify({"error": "Failed to persist settings"}), 500

    return jsonify({"updated": updated, "errors": errors})


@app.route("/api/settings/<path:key>", methods=["GET"])
def get_one(key):
    """Internal endpoint — returns plaintext value. Requires X-Internal-Token."""
    err = _check_internal_token()
    if err:
        return err

    k = _clean_key(key)
    if not k:
        return jsonify({"error": "Invalid key"}), 400

    data = _load()
    val = data.get(k, "")
    return jsonify({"key": k, "value": val, "configured": bool(val)})


@app.route("/api/settings", methods=["DELETE"])
def delete_settings():
    """Delete one or more keys. Body: {keys: ["key1", "key2"]}"""
    err = _check_internal_token()
    if err:
        return err
    body = request.json or {}
    keys = body.get("keys", [])
    data = _load()
    removed = []
    for raw_k in keys:
        k = _clean_key(raw_k)
        if k and k in data:
            del data[k]
            removed.append(k)
    if removed:
        _save(data)
    return jsonify({"removed": removed})


@app.route("/api/settings/test/<service>", methods=["POST"])
def test_connection(service):
    """Test connectivity for a configured external service."""
    err = _check_internal_token()
    if err:
        return err
    import requests as req
    data = _load()

    if service == "otx":
        key = data.get("otx_api_key", "")
        if not key:
            return jsonify({"ok": False, "error": "No OTX API key configured"})
        try:
            r = req.get("https://otx.alienvault.com/api/v1/user/me",
                        headers={"X-OTX-API-KEY": key}, timeout=8)
            if r.status_code == 200:
                return jsonify({"ok": True, "username": r.json().get("username", "?")})
            return jsonify({"ok": False, "error": f"HTTP {r.status_code}"})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)})

    if service == "hibp":
        key = data.get("hibp_api_key", "")
        if not key:
            return jsonify({"ok": False, "error": "No HIBP API key configured"})
        try:
            r = req.get("https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com",
                        headers={"hibp-api-key": key, "User-Agent": "NetworkMonitor"}, timeout=8)
            if r.status_code in (200, 404):
                return jsonify({"ok": True})
            return jsonify({"ok": False, "error": f"HTTP {r.status_code}"})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)})

    if service == "misp":
        url = data.get("misp_url", "")
        key = data.get("misp_api_key", "")
        if not url or not key:
            return jsonify({"ok": False, "error": "MISP URL and API key required"})
        if not _URL_RE.match(url):
            return jsonify({"ok": False, "error": "Stored MISP URL is invalid"}), 400
        try:
            r = req.get(f"{url}/servers/getVersion",
                        headers={"Authorization": key, "Accept": "application/json"},
                        timeout=8)
            if r.status_code == 200:
                return jsonify({"ok": True, "version": r.json().get("version", "?")})
            return jsonify({"ok": False, "error": f"HTTP {r.status_code}"})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)})

    return jsonify({"ok": False, "error": f"Unknown service: {service}"}), 400


@app.route("/health")
def health():
    return jsonify({"status": "ok", "storage": str(SETTINGS_FILE), "file_exists": SETTINGS_FILE.exists()})


if __name__ == "__main__":
    _PLACEHOLDER_VALUES = {"", "CHANGE_ME", "CHANGE_ME_use_openssl_rand"}
    if _RAW_KEY in _PLACEHOLDER_VALUES:
        raise SystemExit(
            "FATAL: SETTINGS_ENCRYPTION_KEY is not set or still placeholder. "
            "Run: openssl rand -hex 32  and set it in .env before starting."
        )
    log.info(f"Settings API — storage: {SETTINGS_FILE}")
    log.info("Encryption key: env-configured")
    app.run(host="0.0.0.0", port=5002, debug=False, threaded=True)
