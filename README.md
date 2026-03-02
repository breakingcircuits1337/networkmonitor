# NetworkMonitor v2

A modular, microservices-based network visibility and threat detection platform. Real-time traffic analysis, IDS alerting, deep packet inspection, AI-powered triage, external threat intelligence feeds, credential monitoring, DNS threat detection, and a live 3D globe dashboard — all running locally with Docker Compose.

![Dashboard](ui/public/img/earth-night.jpg)

> See [CHANGELOG.md](CHANGELOG.md) for the full v2.0 upgrade notes.

---

## Features

| Feature | Status |
|---------|--------|
| **Live 3D Globe** — protocol-colored traffic arcs, geo-enriched alert markers, IOC/DNS/credential event markers | ✅ Complete |
| **Settings Page** — `⚙` button opens encrypted API key management (OTX, MISP, HIBP, ET Pro) | ✅ Complete |
| **Threat Intel Panel** — live IOC feed + LLM analyst chat + auto-generated Suricata rules | ✅ Complete |
| **IDS Alerting** — Suricata with Emerging Threats rules + auto-generated IOC rules from live feeds | ✅ Complete |
| **Deep Packet Inspection** — Zeek DPI engine, session analytics, application-layer visibility | ✅ Complete |
| **DNS Threat Detection** — passive sniffer, DGA detection (Shannon entropy), NXDomain burst tracking, RPZ blocking | ✅ Complete |
| **Credential Monitoring** — HaveIBeenPwned breach + paste monitoring, k-anonymity password check | ✅ Complete |
| **External IOC Feeds** — OTX AlienVault, CISA KEV, MISP; auto-converts IOCs to Suricata rules | ✅ Complete |
| **AI Analysis Engine** — 7-role sub-agent system with local Ollama LLMs | ✅ Complete |
| **AI Chat Assistants** — Sarah (network ops) + Threat Intel Analyst (IOC-grounded) | ✅ Complete |
| **SOAR Blocking** — Redis-persistent auto-IP-blocking with LLM gate option | ✅ Complete |
| **VoIP Monitoring** — SIP/RTP session tracking and anomaly detection | ✅ Complete |
| **Graph Database** — Neo4j asset topology, alert correlation, AI analysis history | ✅ Complete |
| **Stream Processing** — ksqlDB with persistent RocksDB state stores | ✅ Complete |
| **Ephemeral Path Tracer** — active traceroute with randomised source IP/MAC (opt-in) | ✅ Complete (opt-in) |
| **TLS Fingerprinting** — JA3/SNI capture, JA3 diversity anomaly detection, alerts wired to globe + SOAR | ✅ Complete |
| **Geo-blocking** — auto-block IPs by country code via `BLOCKED_COUNTRIES` env var | ✅ Complete |
| **UEBA** — per-IP behavioural baseline + z-score anomaly scoring, feeds soar_blocker | ✅ Complete |
| **Packet Launcher** — manual packet TX via REST | ✅ Opt-in (requires `ENABLE_PACKET_LAUNCHER=true`) |

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
#   NEO4J_PASSWORD           (generate: openssl rand -base64 24)
#   SETTINGS_ENCRYPTION_KEY  (generate: openssl rand -hex 32)
#   INTERNAL_API_TOKEN       (generate: openssl rand -hex 32)
```

> **Note:** `settings_api` and `ai_analyst` will refuse to start if these are left as placeholders.
> This is intentional — running with default credentials would expose your data.

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

## Observability & Monitoring Stack

An optional Docker Compose overlay (`docker-compose.monitoring.yml`) that adds full metrics collection, dashboards, and alerting to the NetworkMonitor platform.

**No extra downloads required.** All components are standard Docker images pulled automatically on first run. No agents, plugins, or SDKs need to be installed on the host.

### Components pulled automatically

| Image | Version | Role |
|-------|---------|------|
| `redpandadata/kminion` | latest | Kafka consumer lag + broker metrics |
| `prom/prometheus` | v2.51.0 | Metrics store (30-day TSDB retention) |
| `grafana/grafana` | 10.4.0 | Dashboard UI |
| `prom/alertmanager` | v0.27.0 | Alert routing |
| `prom/node-exporter` | v1.8.0 | Host CPU / memory / disk metrics |
| `gcr.io/cadvisor/cadvisor` | v0.49.1 | Per-container resource metrics |

### Required configuration (one step)

Set `GRAFANA_PASSWORD` in your `.env` file before starting:

```bash
# in .env
GRAFANA_PASSWORD=your_secure_password_here
```

That is the only required change. Everything else starts with working defaults.

> **Port availability**: the overlay uses ports 3000, 8082, 8083, 9090, 9093, and 9100. Make sure these are free on the host before starting.

### Start the monitoring stack

```bash
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d
```

### Access

| Service | URL | Credentials |
|---------|-----|-------------|
| Grafana dashboards | http://localhost:3000 | `admin` / `GRAFANA_PASSWORD` |
| Prometheus (PromQL) | http://localhost:9090 | none |
| Alertmanager | http://localhost:9093 | none |
| KMinion raw metrics | http://localhost:8082/metrics | none |
| node-exporter raw metrics | http://localhost:9100/metrics | none |
| cAdvisor raw metrics | http://localhost:8083/metrics | none |

### Are the Grafana dashboards pre-configured?

**Yes — fully.** On first boot Grafana automatically:

1. Connects to Prometheus (the datasource is provisioned from `monitoring/grafana/provisioning/datasources/prometheus.yml` — no manual setup in the UI needed).
2. Loads two dashboards from `monitoring/grafana/dashboards/` into a **NetworkMonitor** folder:

| Dashboard | Panels |
|-----------|--------|
| **Kafka Consumer Lag** | Total lag by consumer group · Lag growth rate · Per-partition lag table · Topic high-water marks · Broker log-dir size |
| **Docker Container Overview** | CPU per container · Memory working-set · Network RX/TX rate · Seconds-since-last-seen uptime table |

Both dashboards have drop-down filters for consumer group, topic, and container name that populate automatically from live label data — nothing needs to be edited.

To import additional community dashboards, go to **Dashboards → Import** in the Grafana UI and enter one of these IDs:

| ID | Description |
|----|-------------|
| 14013 | KMinion Topics (official) |
| 18136 | Kafka Consumer Offsets |
| 11963 | Kafka Lag |

### Alerting rules (active out of the box)

Rules live in `monitoring/prometheus/rules/kafka-alerts.yml` and fire into Alertmanager automatically.

| Alert | Condition | Severity |
|-------|-----------|----------|
| `KafkaConsumerLagWarning` | Lag > 5,000 messages for 5 min | warning |
| `KafkaConsumerLagCritical` | Lag > 50,000 messages for 5 min | critical |
| `KafkaConsumerLagGrowing` | Lag steadily increasing for 15 min | warning |
| `ContainerDown` | Container not seen for > 30 s | critical |
| `ContainerHighMemory` | > 85% memory limit for 5 min | warning |
| `ContainerHighCPU` | > 80% CPU for 10 min | warning |
| `HostHighLoad` | Load avg > 1.5× CPU count for 10 min | warning |
| `HostLowDiskSpace` | Root FS < 10% free for 5 min | critical |
| `HostMemoryPressure` | Available RAM < 10% for 5 min | critical |
| `SensorFeedSilent` | No new messages on `netflow`/`security.alerts`/`dns.events`/`dpi.events` for 5 min | critical |
| `ThreatIntelFeedStale` | No new IOCs on `ioc.feed` for 2 hours | warning |

By default alerts are logged by Alertmanager. To route them to **Slack or PagerDuty**, uncomment and fill in the receiver block in `monitoring/alertmanager/alertmanager.yml` — no restart needed, just reload:

```bash
curl -X POST http://localhost:9093/-/reload
```

To reload Prometheus rules without a restart:

```bash
curl -X POST http://localhost:9090/-/reload
```

### Monitoring directory layout

```
monitoring/
├── prometheus/
│   ├── prometheus.yml              # Scrape targets: KMinion, cAdvisor, node-exporter, services
│   └── rules/
│       └── kafka-alerts.yml        # All alerting rules
├── alertmanager/
│   └── alertmanager.yml            # Alert routing — add Slack/PagerDuty receivers here
└── grafana/
    ├── provisioning/
    │   ├── datasources/
    │   │   └── prometheus.yml      # Auto-connects Grafana → Prometheus
    │   └── dashboards/
    │       └── default.yml         # Tells Grafana where to load dashboard JSON from
    └── dashboards/
        ├── kafka-consumer-lag.json # Kafka lag dashboard
        └── docker-overview.json    # Container resource dashboard
```

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
| `GRAFANA_PASSWORD` | _(required for monitoring)_ | Grafana `admin` account password |

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
| `encrypted_traffic_analysis` | `tls.meta` | JA3/SNI/TLS fingerprinting; JA3 diversity anomalies wired to `security.alerts` via ksqlDB |
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

```bash
# Quick download with a MaxMind license key (free tier):
MAXMIND_LICENSE_KEY=your_key_here
curl -sL "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz" \
  | tar -xz --strip-components=1 --wildcards "*/GeoLite2-City.mmdb" -C .
```

> If the file is missing the globe will not display geo data but the rest of the stack will still start.

---

## License

MIT
