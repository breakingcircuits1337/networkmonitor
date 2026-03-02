# NetworkMonitor Changelog

---

## v2.0.0 — 2026-03-01

### New Features

#### Settings Page (GUI)
- Added `⚙` button to the top navbar — opens a full-screen settings modal without removing any existing UI
- **API Keys tab**: OTX AlienVault, MISP URL + key, Emerging Threats Pro, HaveIBeenPwned — all stored AES-256 encrypted
- **Credential Monitor tab**: configure email addresses to monitor, check interval, breach status view, password k-anonymity checker
- **DNS / Tracer tab**: DGA entropy threshold, NXDomain burst limit, RPZ domain list, ephemeral tracer manual trigger
- **Network tab**: home lat/lon, network range, trusted IPs, SOAR block thresholds (severity, min-alerts, TTL)
- **Security tab**: post-quantum roadmap display, internal API token, geo-blocking country codes, LLM model selection
- Input sanitisation: control-char stripping, length limits, URL format validation, `type="password"` fields with show/hide toggle
- Test buttons for OTX, MISP, and HIBP connections
- Save/Discard workflow with success/error banners

#### Threat Intelligence Panel (`🛡 INTEL` button)
- Right-side panel with 4 tabs: **Feed**, **Analyst Chat**, **Rules**, **Creds**
- **Feed tab**: live IOC cards (IP, domain, hash, CVE) with confidence, source badge, expandable detail + generated Suricata rule
- **Analyst Chat tab**: streaming LLM conversation (threat_intel's Ollama endpoint) grounded in current IOC feed; auto-extracts Suricata rules from responses
- **Rules tab**: all auto-generated Suricata rules from IOC feed, syntax-highlighted
- **Creds tab**: live breach status for all monitored email addresses

#### External IOC Feed Integration (`services/threat_intel`)
- New microservice polling: **OTX AlienVault** (15 min), **CISA KEV** (1 hr), **MISP** (30 min)
- API keys fetched dynamically from encrypted settings_api — survive rotation without rebuild
- IOCs published to `ioc.feed` Kafka topic; globe routes them as orange points
- **Auto-rule generation**: every IP/domain IOC generates a Suricata rule written to `/rules/netwatch-ioc.rules` (mounted into Suricata container as read-only)
- `/api/intel-chat` streaming endpoint: LLM analyst grounded in current feed
- `/api/ioc/refresh` POST to trigger immediate feed pull

#### Credential & Dark-Web Monitoring (`services/credential_monitor`)
- Checks configured email addresses against **HaveIBeenPwned** breach + paste databases hourly
- **k-anonymity** password check: only SHA1[0:5] sent to HIBP — actual password never leaves browser or service
- New breaches published to `credential.alerts` Kafka topic; globe shows dark-red points
- `/api/credentials/status` endpoint for breach summary
- `/api/credentials/check-password` endpoint for one-off password checks

#### DNS Threat Detection (`sensors/dns_monitor`)
- Passive raw-socket DNS sniffer (UDP port 53, no external library)
- **DGA Detection**: Shannon entropy + vowel/consonant ratio + digit ratio — configurable threshold (default 3.6 bits)
- **NXDomain burst tracking**: detects C2 domain-cycling behaviour (configurable burst limit)
- **RPZ blocklist**: domains in `RPZ_BLOCKED_DOMAINS` env or RPZ file trigger immediate alerts
- DNS events published to `dns.events` Kafka topic; DGA hits shown as red globe points, clean DNS as green
- **Ephemeral Path Tracer** (`ENABLE_EPHEMERAL_TRACER=true`): active ICMP traceroute to suspicious IPs using randomised RFC1918 source IP and random locally-administered MAC headers to reveal hop path without exposing sensor identity. Requires `CAP_NET_RAW` and explicit authorisation. Results published as `dns_trace` events.
- ksqlDB `dga_by_src` materialized table counts DGA detections per source IP

#### Encrypted Settings API (`services/settings_api`)
- Flask API backed by AES-256 (Fernet) encrypted file on Docker volume
- Key derived via PBKDF2-SHA256 (480,000 iterations) from `SETTINGS_ENCRYPTION_KEY` env var
- Sensitive keys (API keys, passwords) redacted in GET responses; plaintext only via internal `X-Internal-Token`
- `POST /api/settings/test/<service>` verifies OTX / HIBP / MISP connectivity
- Post-quantum note in code: upgrade path to Kyber-1024 + Argon2id documented

### Security Improvements

#### Credential Hardening
- **`.env.template`** added — all secrets moved out of `docker-compose.yml` into env vars
- `NEO4J_PASSWORD`, `SETTINGS_ENCRYPTION_KEY`, `INTERNAL_API_TOKEN` are now env-var references; `docker-compose.yml` contains no plaintext credentials

#### Docker Network Segmentation
- Four separate Docker networks: `sensor-net`, `processing-net`, `storage-net`, `frontend-net`
- **`storage-net`** (Neo4j + Redis): `internal: true` — no external access, not reachable from sensors
- **`processing-net`** (Kafka, ksqlDB, AI): `internal: true` — isolated from internet
- A compromised sensor container can no longer directly reach Neo4j or Redis

#### Redis Blocklist Persistence
- `soar_blocker` now connects to Redis (`redis://redis:6379`) on startup
- In-memory `blocked` set re-hydrated from Redis `netwatch:blocked_ips` on restart
- Alert rate counters use Redis `INCR` + `EXPIRE` — atomic and crash-safe
- Block TTL stored in Redis `SETEX` so auto-unblock fires even after container restart
- Graceful fallback to in-memory if Redis is unavailable (old behaviour preserved)
- Redis configured with AOF + RDB persistence, 256 MB memory limit, LRU eviction

#### ksqlDB State Persistence
- `KSQL_KSQL_STREAMS_STATE_DIR` mapped to `ksqldb_state` Docker volume
- RocksDB-backed state stores survive `docker compose restart`
- New streams: `dns_events`, `ioc_feed`, `credential_alerts`
- New materialized table: `dga_by_src` (DGA detection count per source IP)

#### Post-Quantum Cryptography Roadmap (documented)
- AES-256 (128-bit post-quantum security via Grover bound) for settings storage — **implemented**
- TLS 1.3 on all external HTTPS calls — **implemented** (requests default)
- Kafka SASL_SSL with TLS 1.3 — **env vars defined**, activation instructions in .env.template
- X25519Kyber768 cipher suite — **roadmapped** for when Confluent/Java adds support
- Kyber-1024 KEM + Argon2id KDF for settings API — **roadmapped** when liboqs-python stabilises

### Infrastructure

| Component | What changed |
|---|---|
| `docker-compose.yml` | 4 new services, 4 Docker networks, Redis volume, ksqlDB state volume, settings volume, IOC rules volume; all credentials via env vars |
| `ui/nginx.conf` | Added proxy routes for `/api/settings`, `/api/ioc/`, `/api/intel-chat`, `/api/credentials/`, `/api/dns/` |
| `services/geoip_enricher` | Now subscribes to `ioc.feed`, `dns.events`, `credential.alerts`; enriches and forwards to SSE globe |
| `sensors/soar_blocker` | `redis` dependency added; Redis-backed blocklist, rate counters, TTL expiry |
| `stream_aggregation/init.sql` | Added `dns_events`, `ioc_feed`, `credential_alerts` streams; `dga_by_src` table |
| `.env.template` | New — copy to `.env` and fill secrets |

### New Files

```
services/settings_api/
  settings_api.py          Encrypted API key store (AES-256/Fernet)
  requirements.txt
  Dockerfile

services/threat_intel/
  threat_intel.py          OTX + CISA KEV + MISP aggregator + LLM intel chat
  requirements.txt
  Dockerfile

services/credential_monitor/
  credential_monitor.py    HIBP breach + paste monitor, k-anon password check
  requirements.txt
  Dockerfile

sensors/dns_monitor/
  dns_monitor.py           Passive DNS sniffer, DGA detection, ephemeral tracer
  requirements.txt
  Dockerfile

ui/src/
  SettingsPage.jsx         Full settings modal (5 tabs, secure inputs)
  ThreatIntelPanel.jsx     Live IOC feed + analyst LLM chat + rules + creds

.env.template              Secret template (copy to .env before running)
CHANGELOG.md               This file
```

---

## v1.0.0 — Initial Release

- 22-container Docker Compose platform
- Suricata IDS + Zeek DPI + encrypted traffic analysis + VoIP monitoring
- Kafka event bus with ksqlDB stream processing
- Neo4j graph of assets and alerts
- AI analyst (7 sub-agent roles) with local Ollama LLMs
- SOAR auto-blocker with 6 firewall principles
- GeoIP enrichment with SSE broadcast to UI
- 3D Globe + 2D Map visualization (React + Globe.gl + Leaflet)
- Sarah AI chat assistant with voice I/O
