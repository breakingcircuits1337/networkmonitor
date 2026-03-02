# NetworkMonitor v2 — Full Code Audit Report

**Date:** 2026-03-02
**Scope:** All services, sensors, stream processing, monitoring stack, Docker orchestration
**Codebase size:** ~5,980 Python lines across 18 service/sensor modules, 22+ Docker containers

---

## Executive Summary

NetworkMonitor v2 is architecturally sound — strong microservices separation, encrypted settings
storage, network segmentation, multi-source threat intel feeds, and a well-considered post-quantum
roadmap. However, the analysis identified **37 issues** across operational maturity, security,
completeness, and observability. Most are low-to-medium effort to fix. The platform should not be
exposed externally or run at scale until at minimum the Critical and High items are resolved.

**Issue breakdown by severity:**

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 7 |
| Medium | 18 |
| Low | 10 |

---

## Critical

### C-1 — No Resource Limits on Any Container
**Location:** `docker-compose.yml`, `docker-compose.monitoring.yml`

Not one of the 22+ containers defines CPU or memory limits. A single hung Ollama request or
runaway Kafka consumer can exhaust all system resources and cause cascading failures across the
entire stack.

Highest-risk containers: `ollama` (14B LLM, unbounded VRAM), `neo4j` (heap can grow to host
RAM), `ai_analyst` (one Semaphore(1) concurrency guard is the only throttle).

**Fix:** Add `deploy.resources.limits` to every service. Suggested minimums:

```yaml
# docker-compose.yml
ollama:
  deploy:
    resources:
      limits:
        cpus: '4.0'
        memory: 16G
      reservations:
        memory: 8G

kafka:
  deploy:
    resources:
      limits:
        cpus: '2.0'
        memory: 2G

ai_analyst:
  deploy:
    resources:
      limits:
        cpus: '2.0'
        memory: 4G

neo4j:
  deploy:
    resources:
      limits:
        cpus: '2.0'
        memory: 4G
```

---

### C-2 — No Restart Policies on Any Service
**Location:** `docker-compose.yml`

No container has a `restart` directive. Any crash — network timeout, OOM, Ollama hang — leaves
the service dead until manual `docker compose up`. Kafka lag silently grows with no notification.

**Fix:** Add `restart: unless-stopped` to all long-running services (sensors, processors, UI).
Use `restart: on-failure` with a `max_retries` cap for services that may fail on bad config.

```yaml
# Example
threat_intel:
  restart: unless-stopped

kafka:
  restart: on-failure
```

---

## High

### H-1 — All Containers Run as Root
**Location:** All Dockerfiles

No Dockerfile has a `USER` directive. Every container runs as UID 0. A container escape or RCE
grants full host access.

Sensors with `network_mode: host` and `cap_add: NET_RAW` (dns_monitor, packet_launcher,
traffic_analysis, voip_analysis) are especially high risk.

**Fix:** Add a non-root user to every Dockerfile that does not genuinely require root:

```dockerfile
# Most services (threat_intel, sarah_api, settings_api, etc.)
RUN useradd -m -u 1000 appuser
USER appuser

# Privileged sensors: keep CAP_NET_RAW but drop root
# docker-compose.yml:
#   user: "1000"
#   cap_add: [NET_RAW, NET_ADMIN]
```

---

### H-2 — No Graceful Shutdown in Most Services
**Location:** `services/geoip_enricher`, `services/sarah_api`, `services/settings_api`,
`sensors/traffic_analysis`, `sensors/dns_monitor` (partial), and others

Docker sends SIGTERM on `docker compose stop`. After 10 seconds it force-kills the container.
Services without SIGTERM handlers lose in-flight Kafka messages and leave DB connections dangling.

`topology_updater` and `ids_alert_forwarder` handle this correctly. Others do not.

**Fix:**

```python
import signal, sys

def _shutdown(sig, frame):
    logger.info("SIGTERM received — closing connections")
    consumer.close()
    producer.close()
    sys.exit(0)

signal.signal(signal.SIGTERM, _shutdown)
signal.signal(signal.SIGINT, _shutdown)
```

---

### H-3 — `tls.meta` Topic Is Produced but Never Consumed
**Location:** `sensors/encrypted_traffic_analysis/encrypted_traffic_analysis.py`,
`docker-compose.yml`

The encrypted traffic sensor captures JA3 fingerprints and SNI data and publishes them to
`tls.meta`. No service subscribes to this topic anywhere in the codebase. All TLS telemetry is
silently discarded. The sensor runs, consumes CPU and network, and produces zero actionable output.

**Fix (choose one):**
1. Subscribe `geoip_enricher` to `tls.meta` so events reach the UI globe
2. Add a ksqlDB stream to detect unusual JA3 patterns → `alert.correlated`
3. Remove `encrypted_traffic_analysis` if TLS analysis is not a current priority

---

### H-4 — `ueba.alerts` Topic Is Consumed but Never Produced
**Location:** `services/soar_blocker/soar_blocker.py`

`soar_blocker` subscribes to `ueba.alerts` (via `UEBA_TOPIC` env var) but no service in the
codebase produces events on this topic. The UEBA subscription is dead code, and the advertised
UEBA-triggered blocking capability does not exist.

**Fix:** Implement a `ueba_detector` service that baselines per-IP traffic volume and emits
`ueba.alerts` on statistical anomalies, or remove the subscription and env var until built.

---

### H-5 — TLS Certificate Validation Disabled for MISP
**Location:** `services/threat_intel/threat_intel.py`

```python
r = requests.post(url, headers={...}, timeout=20, verify=False)  # line ~307
```

`verify=False` disables server certificate validation for all MISP API calls. An attacker on
the same network can intercept the connection and steal the MISP API key.

**Fix:**

```python
# Option A — proper cert validation (default)
r = requests.post(url, headers={...}, timeout=20)  # verify=True is default

# Option B — self-signed MISP CA bundle
r = requests.post(url, headers={...}, timeout=20, verify="/path/to/misp-ca.crt")
```

---

### H-6 — No Alerting When Sensors Stop Sending Data
**Location:** `monitoring/prometheus/rules/kafka-alerts.yml`

Alerting rules cover Kafka consumer lag and container resource usage but not silent sensor
failure. A sensor could stop publishing events for hours (crashed thread, interface down,
Suricata hung) with no alert fired.

**Fix:** Add to `monitoring/prometheus/rules/kafka-alerts.yml`:

```yaml
- alert: SensorFeedSilent
  expr: |
    (time() - max by (topic) (
      kminion_kafka_topic_partition_high_water_mark{
        topic=~"netflow|security.alerts|dns.events|dpi.events"
      }
    )) > 300
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "No new messages on {{ $labels.topic }} for 5+ minutes"
    description: >
      Topic {{ $labels.topic }} high-water mark has not advanced for 5 minutes.
      The producing sensor may have crashed.
```

---

### H-7 — Kafka Data Volume Is Ephemeral
**Location:** `docker-compose.yml`, Kafka service definition

Kafka has no `volumes:` mount. Its data directory lives inside the container filesystem. A
container restart or `docker compose down` destroys all unprocessed messages and consumer offsets.

**Fix:**

```yaml
# docker-compose.yml
volumes:
  kafka_data: {}   # add to top-level volumes block

services:
  kafka:
    volumes:
      - kafka_data:/var/lib/kafka/data
```

---

## Medium

### M-1 — `BLOCKED_COUNTRIES` Env Var Defined but Never Used
**Location:** `env.template`, `services/soar_blocker/soar_blocker.py`

The `BLOCKED_COUNTRIES` variable is documented but `soar_blocker` never reads or applies it.
Geo-blocking is a documented feature that does not function.

**Fix:** In `soar_blocker.py`, load `BLOCKED_COUNTRIES`, resolve the alert source IP against
the bundled GeoIP DB, and trigger a block if the country code matches.

---

### M-2 — No Rate Limiting on Public API Endpoints
**Location:** `services/threat_intel`, `services/credential_monitor`, `services/sarah_api`

`/api/intel-chat`, `/api/intel/analyze`, `/api/credentials/check-password` have no rate limiting.
Repeated POSTs to `/api/intel-chat` will queue unbounded Ollama requests.

**Fix:**

```python
from flask_limiter import Limiter
limiter = Limiter(app, key_func=lambda: request.remote_addr, default_limits=["60/minute"])

@app.route("/api/intel-chat", methods=["POST"])
@limiter.limit("5/minute")
def intel_chat():
    ...
```

Add `flask-limiter` to the relevant `requirements.txt` files.

---

### M-3 — Hardcoded Credential Defaults in Dockerfiles
**Location:** `services/ai_analyst/Dockerfile`

```dockerfile
ENV NEO4J_PASSWORD=neo4jpassword
ENV NEO4J_USER=neo4j
```

These defaults are baked into the image layers and visible in `docker inspect` even when
overridden at runtime. Anyone who pulls the image from a registry sees these defaults.

**Fix:** Remove all credential `ENV` lines from Dockerfiles. Rely solely on the `docker-compose.yml`
environment block sourced from `.env`.

---

### M-4 — No Health Checks on Application Services
**Location:** `docker-compose.yml`

Infrastructure services (Kafka, Redis, Neo4j) have health checks. All 10+ application services
(threat_intel, sarah_api, settings_api, soar_blocker, geoip_enricher, ai_analyst, etc.) do not.
Docker cannot detect a hung Flask process or a deadlocked consumer.

**Fix:** All Flask services already serve HTTP — add a `/health` endpoint and a health check:

```yaml
threat_intel:
  healthcheck:
    test: ["CMD", "curl", "-sf", "http://localhost:5003/health"]
    interval: 30s
    timeout: 10s
    retries: 3
    start_period: 60s
```

---

### M-5 — Prometheus Scrape Config Missing Most Services
**Location:** `monitoring/prometheus/prometheus.yml`

Only 3 of 10+ application services are scraped (`geoip_enricher`, `ai_analyst`, `sarah_api`).
`threat_intel`, `settings_api`, `credential_monitor`, `dns_monitor`, and all sensors expose no
metrics and are not scraped.

**Fix (two parts):**
1. Add `prometheus_flask_exporter` to the missing Flask services
2. Add their targets to the Prometheus scrape config:

```yaml
- job_name: networkmonitor-extended
  static_configs:
    - targets: [threat_intel:5003]
      labels: {service: threat_intel}
    - targets: [settings_api:5002]
      labels: {service: settings_api}
    - targets: [credential_monitor:5004]
      labels: {service: credential_monitor}
```

---

### M-6 — Prometheus Scrape Labels Do Not Identify Services
**Location:** `monitoring/prometheus/prometheus.yml`

All three scraped services share a single `project: networkmonitor` label. There is no `service`
label, so Grafana panels cannot filter by service name without hardcoding port numbers.

**Fix:** Split the single static_configs block into per-service entries with a `service` label
(see M-5 fix above).

---

### M-7 — ksqlDB Materialized Tables Are Never Queried
**Location:** `stream_aggregation/init.sql`, all services

ksqlDB defines `assets_by_ip` and `dga_by_src` persistent tables backed by RocksDB. No
application service queries them. They consume state-store disk and compaction CPU for zero
benefit.

**Fix (choose one):**
1. Query `assets_by_ip` in `ai_analyst` to enrich alerts with asset context
2. Query `dga_by_src` in `soar_blocker` to auto-block IPs with repeated DGA hits
3. Expose both via the ksqlDB REST API (port 8088) and document them
4. Drop the tables if not planned for use

---

### M-8 — No Environment Variable Validation at Service Startup
**Location:** All services

Services accept placeholder values (`CHANGE_ME`, `neo4jpassword`) without complaint and fail
later during the first real operation. The error appears far from the root cause.

**Fix:** Add a validation block at the top of each service's `main()`:

```python
REQUIRED = {
    "NEO4J_PASSWORD": os.getenv("NEO4J_PASSWORD", ""),
    "INTERNAL_API_TOKEN": os.getenv("INTERNAL_API_TOKEN", ""),
}
FORBIDDEN_VALUES = {"", "CHANGE_ME", "neo4jpassword", "CHANGE_ME_use_openssl_rand"}

for name, val in REQUIRED.items():
    if val in FORBIDDEN_VALUES:
        raise SystemExit(f"FATAL: {name} is not configured. Set it in .env before starting.")
```

---

### M-9 — Sarah API Event Cache Is Missing Topics
**Location:** `services/sarah_api/sarah_api.py`

```python
_event_cache = {
    "security.alerts": [],
    "voip.events": [],
    "netflow": [],
}
```

`dpi.events`, `dns.events`, `credential.alerts`, and `ioc.feed` are not cached. Sarah has no
awareness of DPI or DNS findings unless specifically asked.

**Fix:** Subscribe the cache to all contextually relevant topics:

```python
_cache_topics = [
    "security.alerts", "voip.events", "netflow",
    "dpi.events", "dns.events", "credential.alerts", "ioc.feed",
]
_event_cache = {t: deque(maxlen=200) for t in _cache_topics}
```

---

### M-10 — Bare `except Exception` Throughout Codebase
**Location:** `services/threat_intel/threat_intel.py`, `sensors/traffic_analysis`,
`services/soar_blocker`, and others

Multiple try/except blocks catch the base `Exception` class and either silently `pass` or log
a warning without further action. Specific failure modes (connection timeout, JSON decode error,
Kafka auth failure) are indistinguishable in logs.

**Fix:** Replace broad catches with specific exception types:

```python
# Before
except Exception:
    pass

# After
except requests.Timeout:
    logger.warning("OTX request timed out — will retry next cycle")
except requests.ConnectionError as e:
    logger.error(f"OTX connection failed: {e}")
except json.JSONDecodeError as e:
    logger.error(f"Malformed JSON from OTX: {e}")
```

---

### M-11 — No Retry Logic for Kafka Publish Failures
**Location:** `services/threat_intel/threat_intel.py`, `services/soar_blocker`,
`services/credential_monitor`

IOC events, block actions, and credential alerts are published to Kafka with a single `send()`
call. If Kafka is temporarily unavailable, the message is silently dropped.

**Fix:** Wrap Kafka sends in a retry-with-backoff helper:

```python
def publish_with_retry(producer, topic, message, max_retries=3):
    for attempt in range(max_retries):
        try:
            future = producer.send(topic, message)
            future.get(timeout=5)
            return
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                logger.error(f"Kafka publish failed after {max_retries} attempts: {e}")
```

---

### M-12 — No Input Validation on Email Addresses in Credential Monitor
**Location:** `services/credential_monitor/credential_monitor.py`

```python
return [e.strip().lower() for e in raw.split(",") if "@" in e.strip()]
```

Accepts malformed addresses like `user@`, `@domain.com`, `foo@bar@baz`. These are forwarded to
the HIBP API, causing 400 errors and potentially exhausting the daily API rate limit.

**Fix:**

```python
import re
EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
return [e.strip().lower() for e in raw.split(",") if EMAIL_RE.match(e.strip())]
```

---

### M-13 — No API Key Expiration Tracking
**Location:** `services/settings_api/settings_api.py`

API keys for OTX, MISP, HIBP, and ET Pro are stored with no expiry metadata. HIBP keys require
annual renewal. There is no mechanism to warn before a key expires or detect a stale key.

**Fix:** Add `stored_at` and optional `expires_at` fields to each stored setting. Add a
`GET /api/settings/expiring` endpoint that returns keys expiring within 30 days.

---

### M-14 — Ollama Semaphore(1) Blocks All Analysis Requests
**Location:** `services/ai_analyst/ai_analyst.py`

```python
_ollama_sem = threading.Semaphore(1)
```

Only one Ollama call can run at a time. All other analysis requests block in queue. With a 14B
parameter model taking 30–120 seconds per request, high-severity alert storms will queue for
minutes.

**Fix:** Increase semaphore to match available hardware, or add a configurable env var:

```python
OLLAMA_CONCURRENCY = int(os.getenv("OLLAMA_CONCURRENCY", "1"))
_ollama_sem = threading.Semaphore(OLLAMA_CONCURRENCY)
```

---

### M-15 — SSE Clients That Fall Behind Lose Events Silently
**Location:** `services/geoip_enricher/geoip_enricher.py`

```python
except queue.Full:
    pass  # Drop event for slow SSE client
```

The oldest events are never dropped — it's always the newest event that is lost when a slow
client's queue fills. The UI may appear to stall or miss critical alert markers on the globe.

**Fix:** Use `collections.deque` with `maxlen` instead of `queue.Queue`, which automatically
drops oldest items:

```python
from collections import deque
client_queue = deque(maxlen=100)  # drop oldest on overflow
```

---

### M-16 — GeoLite2-City.mmdb Has No Automated Download Mechanism
**Location:** `README.md`, `services/geoip_enricher/geoip_enricher.py`

The database must be manually downloaded and placed in the repo root. If missing, `geoip_enricher`
raises `FileNotFoundError` on startup and the entire geolocation and map pipeline fails.

**Fix:** Add a `scripts/download_geoip.sh` that uses the MaxMind download API:

```bash
#!/usr/bin/env bash
# Usage: MAXMIND_LICENSE_KEY=xxx ./scripts/download_geoip.sh
curl -sL "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz" \
  | tar -xz --strip-components=1 --wildcards "*/GeoLite2-City.mmdb" -C .
echo "GeoLite2-City.mmdb downloaded."
```

Alternatively make `geoip_enricher` start in degraded mode (no geo data, no map) rather than
crashing.

---

### M-17 — No Token Budget or Rate Limiting for Ollama Requests
**Location:** `services/ai_analyst/ai_analyst.py`, `services/threat_intel/threat_intel.py`

Both services call Ollama with no accounting of tokens used, no daily budget cap, and no
circuit-breaker if Ollama becomes unresponsive. A sustained alert storm will fill the Ollama
request queue indefinitely.

**Fix:**
- Set `"num_predict": 512` on all requests (already done in ai_analyst; verify in threat_intel)
- Add a token-per-minute counter and reject new requests once a threshold is hit
- Add a circuit breaker: if the last 3 Ollama calls failed or timed out, skip LLM and fall back
  to rule-based analysis

---

### M-18 — Kafka Consumer Group IDs Are Hardcoded
**Location:** Multiple consumers

Consumer group IDs like `"soar-blocker"`, `"alert-sink"`, `"topology-updater"` are hardcoded.
Running a second instance of any service in parallel (e.g., for blue-green deployment) creates
invisible consumer group conflicts and duplicate processing.

**Fix:** Make group IDs configurable via env var with a sensible default:

```python
CONSUMER_GROUP = os.getenv("KAFKA_CONSUMER_GROUP", "soar-blocker")
consumer = KafkaConsumer(..., group_id=CONSUMER_GROUP)
```

---

## Low

### L-1 — README Documents Features That Are Partially or Not Implemented

| Feature | README claim | Reality |
|---------|-------------|---------|
| Geo-blocking | "auto-IP-blocking" | `BLOCKED_COUNTRIES` var never read |
| TLS fingerprinting | "JA3/SNI/TLS fingerprinting" | Captured but never analyzed |
| UEBA blocking | "LLM gate option" | `ueba.alerts` topic empty |
| Packet Launcher | Listed as production feature | Opt-in stub only |

**Fix:** Add status indicators to the README feature list (✅ complete, 🟡 partial, ❌ not yet).

---

### L-2 — DNS Monitor Daemon Threads Have No Shutdown Coordination
**Location:** `sensors/dns_monitor/dns_monitor.py`

The sniffer thread and each ephemeral tracer are started as daemon threads. If the process
receives SIGTERM while a trace is in progress, the trace is aborted mid-TTL without cleanup.

**Fix:** Use a `threading.Event` stop flag and join all threads before `sys.exit()`.

---

### L-3 — AI Analyst Returns Empty String on Total LLM Failure
**Location:** `services/ai_analyst/ai_analyst.py`

```python
except Exception as e:
    log.warning(f"Ollama [{OLLAMA_MODEL}] fallback error: {e}")
return ""  # ← empty string propagated as analysis result
```

Downstream consumers of `ai.analysis` Kafka topic receive an empty `analysis` field, which the
UI renders as a blank panel rather than an error state.

**Fix:** Return a structured fallback object instead of an empty string:

```python
return json.dumps({
    "summary": "Analysis unavailable — LLM offline",
    "severity": "unknown",
    "rule_based": True,
})
```

---

### L-4 — No DNS Query Deduplication
**Location:** `sensors/dns_monitor/dns_monitor.py`

Every individual DNS packet generates a Kafka event. Repeated queries to the same domain
(browser prefetch, TTL refresh, etc.) generate hundreds of identical events per minute per host,
inflating `dns.events` topic volume significantly.

**Fix:** Add an LRU cache (or time-bucketed dedup) in dns_monitor before publishing:

```python
from functools import lru_cache
import time

_seen = {}
DEDUP_WINDOW = 60  # seconds

def should_emit(src_ip, domain, qtype):
    key = f"{src_ip}:{domain}:{qtype}"
    now = time.monotonic()
    if key in _seen and now - _seen[key] < DEDUP_WINDOW:
        return False
    _seen[key] = now
    return True
```

---

### L-5 — No Neo4j Connection Pool Configuration
**Location:** `services/topology_updater`, `services/alert_sink_neo4j`, `services/ai_analyst`

The `GraphDatabase.driver()` call uses default pool settings (max 100 connections). Under high
event volume, connections are created and closed rapidly without explicit pool tuning.

**Fix:** Document recommended pool settings:

```python
driver = GraphDatabase.driver(
    neo4j_uri,
    auth=(user, password),
    max_connection_pool_size=50,
    max_connection_lifetime=3600,
    connection_acquisition_timeout=30,
)
```

---

### L-6 — No Audit Log for Settings Changes
**Location:** `services/settings_api/settings_api.py`

API key changes (PUT /api/settings/{key}) are not logged to Neo4j or any external audit trail.
There is no way to reconstruct when a key was last changed or by whom.

**Fix:** On each successful write, emit an event to a `settings.audit` Kafka topic or append
to a Neo4j audit node:

```python
driver.execute_query(
    "MERGE (a:AuditLog {id: randomUUID()}) SET a += $props",
    props={"action": "settings_update", "key": key_name, "at": datetime.utcnow().isoformat()}
)
```

---

### L-7 — soar_blocker Block Command Is a Stub
**Location:** `docker-compose.yml`

```yaml
BLOCKLIST_CMD: "echo 'iptables -A INPUT -s {ip} -j DROP'"
```

The default command only `echo`s the iptables rule — it never executes. Automatic IP blocking
silently does nothing unless the operator overrides `BLOCKLIST_CMD`.

**Fix:** Update the default to actually execute the rule (or document clearly that this must be
configured before blocking works):

```yaml
# For production (requires NET_ADMIN cap or external firewall API):
BLOCKLIST_CMD: "iptables -A INPUT -s {ip} -j DROP"

# OR document in README that the echo default is a dry-run placeholder
```

---

### L-8 — CHANGELOG Does Not Cover v1 → v2 Migration
**Location:** `CHANGELOG.md`

The file lists what was added in v2 but contains no information about breaking changes, removed
components, or upgrade steps for users coming from v1.

**Fix:** Add a "Upgrading from v1" section covering removed env vars, renamed topics, and any
required manual migration steps.

---

### L-9 — Ollama Model Name Mismatch in ai_analyst Dockerfile
**Location:** `services/ai_analyst/Dockerfile`

```dockerfile
ENV OLLAMA_MODEL=qwen2.5:7b
```

The README and docker-compose.yml specify `aratan/Ministral-3-14B-Reasoning-2512:latest` as the
primary model. The Dockerfile default points to a different model that will be pulled if
docker-compose.yml is not used.

**Fix:** Remove `ENV OLLAMA_MODEL` from the Dockerfile and rely solely on docker-compose.yml.

---

### L-10 — Post-Quantum Roadmap Has No Timeline or Milestone Tracking
**Location:** `README.md`, code comments

The post-quantum section has TODOs but no concrete acceptance criteria or timeline. Without
this, the roadmap is aspirational only.

**Fix:** Add a `POST_QUANTUM_ROADMAP.md` with specific milestones, the `python-oqs` version to
target, and a test harness plan for algorithm migration.

---

## Topic / Kafka Flow Map

| Topic | Producer | Consumer(s) | Status |
|-------|----------|-------------|--------|
| `netflow` | traffic_analysis | geoip_enricher, ksqlDB | ✅ |
| `raw.flows` | tshark_capture | geoip_enricher | ✅ |
| `security.alerts` | ids_alert_forwarder | ai_analyst, soar_blocker, geoip_enricher | ✅ |
| `dpi.events` | dpi_event_forwarder | ai_analyst, geoip_enricher | ✅ |
| `voip.events` | voip_analysis | ai_analyst, geoip_enricher | ✅ |
| `asset.discovery` | asset_discovery | topology_updater, ksqlDB | ✅ |
| `alert.correlated` | ksqlDB | alert_sink_neo4j, ai_analyst, geoip_enricher | ✅ |
| `ai.analysis` | ai_analyst | soar_blocker, geoip_enricher | ✅ |
| `blocklist.actions` | soar_blocker | geoip_enricher | ✅ |
| `ioc.feed` | threat_intel | geoip_enricher | ✅ |
| `credential.alerts` | credential_monitor | geoip_enricher | ✅ |
| `dns.events` | dns_monitor | geoip_enricher, ksqlDB | ✅ |
| `tls.meta` | encrypted_traffic_analysis | **(none)** | ❌ Dead topic |
| `ueba.alerts` | **(none)** | soar_blocker | ❌ Never populated |

---

## Priority Remediation Plan

### Week 1 — Stop the bleeding
1. **C-1** Add resource limits to all containers
2. **C-2** Add `restart: unless-stopped` to all services
3. **H-1** Add non-root USER to all Dockerfiles
4. **H-5** Fix `verify=False` in threat_intel MISP calls
5. **H-7** Mount Kafka data directory as a named volume
6. **M-3** Remove hardcoded credentials from ai_analyst Dockerfile

### Week 2 — Reliability
7. **H-2** Add SIGTERM handlers to geoip_enricher, sarah_api, settings_api
8. **M-4** Add `/health` endpoints + Docker healthchecks to all services
9. **M-8** Add env var validation at startup (fail fast)
10. **H-6** Add sensor-silence alerting rules to Prometheus

### Week 3 — Fill the gaps
11. **H-3** Decide on tls.meta: implement consumer or remove sensor
12. **H-4** Implement UEBA detector or remove ueba.alerts subscription
13. **M-1** Implement BLOCKED_COUNTRIES in soar_blocker
14. **M-7** Query ksqlDB tables or remove them
15. **L-7** Fix soar_blocker BLOCKLIST_CMD default or document it clearly

### Month 2 — Hardening
16. **M-2** Add rate limiting to all public Flask endpoints
17. **M-5/M-6** Add Prometheus metrics to missing services with per-service labels
18. **M-9** Expand Sarah API event cache to cover all relevant topics
19. **M-13** Add API key expiry metadata to settings_api
20. **M-16** Add GeoIP DB download script

---

## Conclusion

The platform has a strong foundation. The Critical and High issues are all fixable in under two
weeks of focused work, and most require only small, targeted changes rather than architectural
rewrites. The Medium issues improve operational maturity and should be addressed before any
production or multi-user deployment. The Low issues are quality-of-life improvements suitable for
a backlog.
