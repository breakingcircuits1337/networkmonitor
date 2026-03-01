# NetworkMonitor v2

A modular, microservices-based network visibility and threat detection platform. Real-time traffic analysis, IDS alerting, deep packet inspection, AI-powered triage, external threat intelligence feeds, credential monitoring, DNS threat detection, and a live 3D globe dashboard — all running locally with Docker Compose.

> See [CHANGELOG.md](CHANGELOG.md) for the full v2.0 upgrade notes.

---

## Features

- **Live 3D Globe** — protocol-colored traffic arcs, geo-enriched alert markers, IOC/DNS/credential event markers
- **Settings Page** — `⚙` button in navbar opens encrypted API key management (OTX, MISP, HIBP, ET Pro)
- **Threat Intel Panel** — `🛡 INTEL` button opens live IOC feed + LLM analyst chat + auto-generated Suricata rules
- **IDS Alerting** — Suricata with Emerging Threats rules + auto-generated IOC rules from live feeds
- **Deep Packet Inspection** — Zeek DPI engine, session analytics, application-layer visibility
- **DNS Threat Detection** — passive sniffer, DGA detection (Shannon entropy), NXDomain burst tracking, RPZ blocking
- **Ephemeral Path Tracer** — active traceroute with randomised source IP/MAC to reveal true hop paths (opt-in)
- **Credential Monitoring** — HaveIBeenPwned breach + paste monitoring, k-anonymity password check
- **External IOC Feeds** — OTX AlienVault, CISA KEV, MISP; auto-converts IOCs to Suricata rules
- **AI Analysis Engine** — 7-role sub-agent system with local Ollama LLMs
- **AI Chat Assistants** — Sarah (network ops) + Threat Intel Analyst (IOC-grounded)
- **SOAR Blocking** — Redis-persistent auto-IP-blocking with LLM gate option
- **VoIP Monitoring** — SIP/RTP session tracking and anomaly detection
- **Graph Database** — Neo4j asset topology, alert correlation, AI analysis history
- **Stream Processing** — ksqlDB with persistent RocksDB state stores

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         SENSORS (sensor-net)                             │
│  tshark  traffic_analysis  suricata  zeek  voip_analysis  dns_monitor   │
│  asset_discovery  encrypted_traffic_analysis  ids_alert_forwarder        │
└─────────────────────────────┬────────────────────────────────────────────┘
                              │ Kafka Topics
                              ▼
┌──────────────────────────────────────────────────────────────────────────┐
│              KAFKA MESSAGE BUS (processing-net, internal)                │
│  netflow · raw.flows · security.alerts · dpi.events · voip.events       │
│  tls.meta · asset.discovery · alert.correlated · ai.analysis            │
│  geo.events · blocklist.actions · ioc.feed · dns.events                 │
│  credential.alerts · ueba.alerts                                         │
└──────────┬───────────────────┬────────────────────┬──────────────────────┘
           │                   │                    │
    ┌──────▼──────┐    ┌───────▼──────┐   ┌────────▼─────────┐
    │ geoip_       │    │  ai_analyst  │   │  ksqlDB          │
    │ enricher     │    │  (7 roles)   │   │  (correlation +  │
    │ → geo.events │    │ → ai.analysis│   │   DGA table)     │
    └──────┬──────┘    └──────┬───────┘   └────────┬─────────┘
           │                  │                     │
           └──────────────────┴─────────────────────┘
                              │
           ┌──────────────────┼────────────────────────────┐
           ▼                  ▼                            ▼
   ┌──────────────┐  ┌──────────────────┐  ┌─────────────────────────┐
   │ NEO4J GRAPH  │  │  REDIS (storage-  │  │   NEW SERVICES          │
   │ Assets/Alerts│  │  net, internal)   │  │  threat_intel :5003     │
   │ AIAnalysis   │  │  Persistent block │  │  credential_monitor :5004│
   └──────────────┘  │  list + counters  │  │  settings_api :5002     │
                     └──────────────────┘  │  dns_monitor :5005       │
                                           └─────────────────────────┘
                              │
                              ▼
                     ┌─────────────────────────────────────┐
                     │  UI (React) — Port 8080             │
                     │  Globe · Map · Settings ⚙ · Intel 🛡│
                     │  Sarah Chat · Threat Intel Panel     │
                     └─────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Docker & Docker Compose v2+
- [Ollama](https://ollama.com) installed on the host
- [GeoLite2-City.mmdb](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) in repo root

### 1. Install Ollama and pull models

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull cybersecserver/matrix-ai
ollama pull aratan/Ministral-3-14B-Reasoning-2512
```

### 2. Configure environment

```bash
cp .env.template .env
# Fill in .env — at minimum set:
#   NEO4J_PASSWORD     (generate with: openssl rand -base64 24)
#   SETTINGS_ENCRYPTION_KEY  (generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
#   INTERNAL_API_TOKEN  (generate with: openssl rand -hex 32)
```

### 3. Start the stack

```bash
docker compose up -d
```

### 4. Configure API keys in the UI

Open `http://localhost:8080`, click **⚙** in the top bar, then add your:
- **OTX API key** (free at otx.alienvault.com)
- **HIBP API key** (haveibeenpwned.com)
- **MISP URL + key** (if you run a MISP instance)

### 5. Access

| Service | URL |
|---------|-----|
| UI Dashboard | http://localhost:8080 |
| Neo4j Browser | http://localhost:7474 |
| AI Chat API | http://localhost:5000 |
| AI Analyst API | http://localhost:5001 |
| Threat Intel API | http://localhost:8080/api/ioc/feed |
| ksqlDB | http://localhost:8088 |

---

## Configuration

Copy `.env.template` → `.env` and fill in values. Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `NEO4J_PASSWORD` | _(required)_ | Neo4j auth password |
| `SETTINGS_ENCRYPTION_KEY` | _(required)_ | AES-256 master key for API key storage |
| `INTERNAL_API_TOKEN` | _(required)_ | Service-to-service auth token |
| `OTX_API_KEY` | _(empty)_ | OTX AlienVault threat feeds |
| `HIBP_API_KEY` | _(empty)_ | HaveIBeenPwned breach monitoring |
| `MISP_URL` / `MISP_API_KEY` | _(empty)_ | MISP threat sharing platform |
| `ET_PRO_API_KEY` | _(empty)_ | Emerging Threats Pro rules |
| `NETWORK_RANGE` | `192.168.1.0/24` | Asset discovery range |
| `OLLAMA_MODEL` | `aratan/Ministral-3-14B-Reasoning-2512:latest` | Primary LLM |
| `SECONDARY_MODEL` | `cybersecserver/matrix-ai:latest` | Security-tuned LLM |
| `SEVERITY_THRESHOLD` | `2` | SOAR auto-block threshold (1=critical) |
| `MIN_ALERTS_TO_BLOCK` | `3` | Alerts required before auto-block |
| `BLOCK_TTL_SECONDS` | `3600` | Auto-unblock after N seconds |
| `ENABLE_PACKET_LAUNCHER` | `false` | Manual packet TX (lab only) |
| `ENABLE_EPHEMERAL_TRACER` | `false` | Active traceroute with spoofed headers |
| `REDIS_URL` | `redis://redis:6379/0` | Redis for persistent blocklist |

---

## Services

### Sensors

| Service | Topic | Description |
|---------|-------|-------------|
| `traffic_analysis` | `netflow` | Per-flow stats from live interface |
| `tshark_capture` | `raw.flows` | All-protocol raw flow extraction |
| `asset_discovery` | `asset.discovery` | Active/passive network scanning |
| `suricata` | → `eve.json` | IDS/IPS — ET rules + auto-generated IOC rules |
| `ids_alert_forwarder` | `security.alerts` | Suricata EVE forwarder |
| `encrypted_traffic_analysis` | `tls.meta` | JA3/SNI/TLS fingerprinting |
| `zeek` | → logs | Deep packet inspection |
| `dpi_event_forwarder` | `dpi.events` | Zeek log forwarder |
| `voip_analysis` | `voip.events` | SIP/RTP session monitoring |
| `dns_monitor` (**NEW**) | `dns.events` | Passive DNS, DGA detection, ephemeral tracer |

### Processing Services

| Service | Port | Description |
|---------|------|-------------|
| `geoip_enricher` | 5000 (internal) | GeoIP enrichment + SSE broadcast |
| `ai_analyst` | 5001 | 7-role sub-agent analysis engine |
| `sarah_api` | 5000 | Streaming AI chat with network context |
| `soar_blocker` | — | Redis-persistent auto-IP-blocking |
| `topology_updater` | — | Asset discovery → Neo4j |
| `alert_sink_neo4j` | — | Correlated alerts → Neo4j |
| `settings_api` (**NEW**) | 5002 | Encrypted API key storage (AES-256) |
| `threat_intel` (**NEW**) | 5003 | OTX + CISA KEV + MISP + LLM analyst chat |
| `credential_monitor` (**NEW**) | 5004 | HIBP breach + paste monitoring |
| `packet_launcher` | 7000 | Manual packet TX (opt-in, lab only) |

---

## Security Architecture

### Network Segmentation

```
sensor-net      → sensors (some use host-mode for raw packet access)
processing-net  → Kafka, ksqlDB, AI services (internal: true)
storage-net     → Neo4j, Redis (internal: true — most restricted)
frontend-net    → UI, geoip_enricher, new APIs
```

A compromised sensor container cannot directly reach Neo4j or Redis.

### Secrets Management

- All secrets in `.env` file (not committed to git)
- API keys stored AES-256 encrypted by `settings_api` on a dedicated Docker volume
- Sensitive values redacted in all GET API responses

### Post-Quantum Cryptography Roadmap

| Component | Status | Algorithm |
|-----------|--------|-----------|
| Settings storage | ✅ Implemented | AES-256 (128-bit PQ margin via Grover) |
| External HTTPS | ✅ Implemented | TLS 1.3 (requests default) |
| Kafka transport | 🔶 Env vars ready | SASL_SSL + TLS 1.3 (activate via KAFKA_SSL_*) |
| Key exchange | 🔲 Roadmap | X25519Kyber768 (pending Confluent/Java support) |
| KDF | 🔲 Roadmap | Argon2id + Kyber-1024 (pending liboqs-python) |

---

## Threat Intelligence

### IOC Feeds

| Feed | Auth | Update Interval | IOC Types |
|------|------|-----------------|-----------|
| OTX AlienVault | API key | 15 min | IP, domain, hash |
| CISA KEV | None | 1 hr | CVE |
| MISP | API key + URL | 30 min | IP, domain, hash |

IOCs are auto-converted to Suricata rules and written to `/rules/netwatch-ioc.rules` which is mounted into the Suricata container.

### DNS Threat Detection

- **DGA scoring**: Shannon entropy + vowel/consonant ratio + digit ratio
- **NXDomain burst**: detects C2 domain cycling (e.g. fast-flux)
- **RPZ**: custom blocked-domain list with immediate alerting
- **Ephemeral tracer**: requires `ENABLE_EPHEMERAL_TRACER=true` in `.env`

---

## DNS Ephemeral Path Tracer

The tracer sends ICMP probes with incrementing TTL to map the hop path to a suspicious IP. Each probe uses:
- A randomised RFC1918 source IP
- A randomised locally-administered MAC address

Results reveal the true network path without exposing the sensor's real identity.

> **Legal notice**: Only use on networks you own or have written authorization to test. Spoofing source IPs/MACs may be illegal without authorisation. Requires `ENABLE_EPHEMERAL_TRACER=true` and `CAP_NET_RAW`.

---

## Packet Launcher

An opt-in REST endpoint for manual packet transmission (ICMP/TCP/UDP).

> **Legal notice**: Must not be used without proper authorization. Restricted to lab/test environments. Requires `ENABLE_PACKET_LAUNCHER=true` and a `LAUNCH_TOKEN`.

---

## GeoIP Setup

Download the free [MaxMind GeoLite2-City](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) database and place `GeoLite2-City.mmdb` in the repository root before starting.

---

## License

MIT
