# NetworkMonitor

A modular, microservices-based network visibility and threat detection platform. Real-time traffic analysis, IDS alerting, deep packet inspection, AI-powered triage, and a live 3D globe dashboard — all running locally with Docker Compose.

![Dashboard](ui/public/img/earth-night.jpg)

---

## Features

- **Live 3D Globe** — protocol-colored traffic arcs, geo-enriched alert markers, country heatmap
- **IDS Alerting** — Suricata-based intrusion detection with real-time alert forwarding
- **Deep Packet Inspection** — Zeek DPI engine, session analytics, application-layer visibility
- **AI Analysis Engine** — 7-role sub-agent system (threat hunter, behavioral, geo-intel, etc.) with rule-based triage + Ollama LLM narratives
- **AI Chat Assistant** — streaming chat interface with network context awareness
- **SOAR Blocking** — automated IP blocking on threshold-triggered alerts
- **VoIP Monitoring** — SIP/RTP session tracking and anomaly detection
- **Raw Flow Capture** — tshark-based all-protocol flow extraction
- **Graph Database** — Neo4j asset topology and alert correlation
- **Stream Processing** — ksqlDB for real-time alert correlation and enrichment

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          SENSORS                                │
│  tshark_capture  traffic_analysis  suricata  zeek  voip_analysis│
│  asset_discovery  encrypted_traffic_analysis                    │
└──────────────────────────┬──────────────────────────────────────┘
                           │ Kafka Topics
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                     KAFKA MESSAGE BUS                           │
│  netflow · raw.flows · security.alerts · dpi.events             │
│  voip.events · tls.meta · asset.discovery · alert.correlated    │
│  ai.analysis · geo.events · blocklist.actions                   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
          ┌────────────────┼────────────────────┐
          ▼                ▼                    ▼
   ┌─────────────┐  ┌─────────────┐   ┌──────────────────┐
   │ geoip_       │  │ ai_analyst  │   │  ksqlDB          │
   │ enricher     │  │ (7 roles)   │   │  (correlation)   │
   │ → geo.events │  │ → ai.analysis│  │  → alert.correlated│
   └──────┬──────┘  └──────┬──────┘   └────────┬─────────┘
          │                │                    │
          ▼                ▼                    ▼
   ┌─────────────────────────────────────────────────┐
   │              NEO4J GRAPH DATABASE               │
   │  Assets · Alerts · AIAnalysis · ThreatSummary   │
   └─────────────────────────────────────────────────┘
          │
          ▼
   ┌─────────────┐   ┌──────────────┐   ┌──────────────┐
   │  UI (React) │   │  sarah_api   │   │ soar_blocker │
   │  Port 8080  │   │  Port 5000   │   │ auto-block   │
   └─────────────┘   └──────────────┘   └──────────────┘
```

---

## Quick Start

### Prerequisites

- Docker & Docker Compose v2+
- [Ollama](https://ollama.com) installed on the host (for AI features)
- [GeoLite2-City.mmdb](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) — free MaxMind database, place in repo root

### 1. Install Ollama and pull models

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull cybersecserver/matrix-ai   # security-tuned 6.7B (recommended)
ollama pull aratan/Ministral-3-14B-Reasoning-2512  # optional, larger model
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env — set NEO4J_PASSWORD, NETWORK_RANGE, and optionally ET_PRO_API_KEY
```

### 3. Start the stack

```bash
docker compose up -d
```

### 4. Access

| Service | URL |
|---------|-----|
| UI Dashboard | http://localhost:8080 |
| Neo4j Browser | http://localhost:7474 |
| AI Chat API | http://localhost:5000 |
| AI Analyst API | http://localhost:5001 |
| ksqlDB | http://localhost:8088 |

---

## Configuration

All configuration is via environment variables. See `docker-compose.yml` for the full list. Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `NETWORK_RANGE` | `192.168.1.0/24` | Network range to scan |
| `NEO4J_PASSWORD` | `neo4jpassword` | **Change in production** |
| `OLLAMA_MODEL` | `aratan/Ministral-3-14B-Reasoning-2512:latest` | Primary LLM |
| `SECONDARY_MODEL` | `cybersecserver/matrix-ai:latest` | Security-tuned LLM |
| `ET_PRO_API_KEY` | _(empty)_ | Emerging Threats Pro key (optional) |
| `ENABLE_PACKET_LAUNCHER` | `false` | Enable manual packet TX (lab only) |
| `SEVERITY_THRESHOLD` | `2` | SOAR auto-block severity level |

> **Security note:** Change `NEO4J_PASSWORD` from the default before exposing any port externally.

---

## Services

### Sensors

| Service | Description |
|---------|-------------|
| `traffic_analysis` | Captures per-flow stats from live interface, publishes to `netflow` |
| `tshark_capture` | All-protocol raw flow extraction → `raw.flows` (protocol-colored globe arcs) |
| `asset_discovery` | Active/passive network scanning → `asset.discovery` |
| `suricata` | IDS/IPS using Emerging Threats rules → `eve.json` |
| `ids_alert_forwarder` | Reads Suricata EVE, forwards to `security.alerts` |
| `encrypted_traffic_analysis` | JA3/SNI/TLS fingerprinting → `tls.meta` |
| `zeek` | Deep packet inspection → JSON logs → `dpi.events` |
| `voip_analysis` | SIP/RTP session monitoring → `voip.events` |

### Services

| Service | Description |
|---------|-------------|
| `geoip_enricher` | GeoIP-enriches all events, broadcasts SSE stream to UI |
| `ai_analyst` | 7-role sub-agent analysis engine with Ollama integration |
| `sarah_api` | Streaming AI chat API with network context |
| `soar_blocker` | Threshold-based auto-IP-blocking with optional LLM gate |
| `topology_updater` | Writes asset discovery results to Neo4j graph |
| `alert_sink_neo4j` | Writes correlated alerts to Neo4j |
| `packet_launcher` | Manual packet transmission REST API (opt-in, lab only) |

### AI Analyst Sub-Agents

The `ai_analyst` service runs 7 specialized daemon threads:

| Role | Model | Topics | Mode |
|------|-------|--------|------|
| `threat_hunter` | matrix-ai | security.alerts, alert.correlated | immediate |
| `traffic_analyst` | Ministral | netflow, dpi.events | batch 60s |
| `incident_responder` | matrix-ai | ai.analysis (critical/high) | immediate |
| `voip_guardian` | Ministral | voip.events | immediate |
| `geo_intel` | matrix-ai | geo.events | batch 120s |
| `behavioral` | Ministral | security.alerts, netflow | per-IP history |
| `malware_classifier` | matrix-ai | dpi.events, security.alerts | immediate |

All roles produce structured JSON to the `ai.analysis` topic and write `AIAnalysis` nodes to Neo4j.

---

## Stream Aggregation (ksqlDB)

Asset and alert data are joined in real time:

```sql
-- Correlated alerts with asset context
SELECT * FROM correlated_alerts EMIT CHANGES;
```

See `stream_aggregation/init.sql` for full correlation logic.

---

## Packet Launcher

An opt-in REST endpoint for manual packet transmission (ICMP/TCP/UDP) using Scapy.

> **Legal notice:** Must not be used without proper authorization. Restricted to lab/test environments. Requires `ENABLE_PACKET_LAUNCHER=true` and a `LAUNCH_TOKEN`.

---

## GeoIP Setup

Download the free [MaxMind GeoLite2-City](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) database (registration required) and place `GeoLite2-City.mmdb` in the repository root before starting the stack.

---

## License

MIT
