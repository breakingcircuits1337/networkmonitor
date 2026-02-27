# NetworkMonitor - Project CLAUDE.md

## Project Overview
Modular microservices-based network visibility and threat detection platform.
All services communicate via **Kafka**. **Neo4j** is the graph database. **Ollama** provides local LLM intelligence.

## Architecture

```
Sensors → Kafka Topics → Services → Neo4j / UI
                              ↓
                        Ollama (AI Analysis)
```

## Kafka Topics

| Topic | Producer | Consumer(s) | Description |
|-------|----------|-------------|-------------|
| `asset.discovery` | asset_discovery | topology_updater, ksqlDB | Asset scan results |
| `netflow` | traffic_analysis | geoip_enricher | Raw flow summaries |
| `tls.meta` | encrypted_traffic_analysis | - | JA3/SNI/TLS fingerprints |
| `security.alerts` | ids_alert_forwarder | soar_blocker, sarah_api, **ai_analyst** | Suricata EVE alerts |
| `alert.correlated` | ksqlDB | alert_sink_neo4j, **ai_analyst** | Alerts enriched with asset data |
| `dpi.events` | dpi_event_forwarder | geoip_enricher | Zeek DPI logs |
| `voip.events` | voip_analysis | sarah_api | SIP/RTP events |
| `voip.packets` | tshark_capture | - | Raw pcap metadata |
| `geo.events` | geoip_enricher | UI (SSE) | GeoIP-enriched events |
| `ueba.alerts` | (future) | soar_blocker | UEBA anomaly scores |
| `blocklist.actions` | soar_blocker | - | IP block audit log |
| `ai.analysis` | **ai_analyst** | sarah_api, alert_sink_neo4j | LLM triage results |

## Service Inventory

| Service | Port | Description |
|---------|------|-------------|
| kafka | 9092 | Message bus |
| neo4j | 7474/7687 | Graph DB (neo4j/neo4jpassword) |
| sarah_api | 5000 | Chat API + SSE event stream |
| geoip_enricher | 5000 (internal) | GeoIP enrichment + SSE for UI |
| ui | 8080 | React dashboard |
| ksqldb-server | 8088 | Stream SQL engine |
| packet_launcher | 7000 | Manual packet transmission (opt-in) |
| soar_blocker | - | Automated IP blocking |
| ai_analyst | - | **NEW: Ollama analysis worker** |

## Ollama Setup

- **URL**: `http://host.docker.internal:11434` (from containers)
- **Recommended model**: `qwen2.5:7b` (~5.2-5.5GB) — best JSON + security reasoning
- **Fallback**: `mistral:7b` (~5GB) — fastest inference
- **Avoid**: `deepseek-r1` — 100% jailbreak success rate, unsafe for security tools
- **Install**: `bash install-ollama.sh` (then change model to qwen2.5:7b)
- **Structured output**: Use Ollama's JSON format mode + `temperature: 0.1` for reliable JSON

## Ollama Integration Pattern

All Ollama calls should use structured JSON output:
```python
resp = requests.post(f"{OLLAMA_URL}/api/generate", json={
    "model": OLLAMA_MODEL,
    "prompt": prompt,
    "stream": False,
    "format": "json",           # enforces JSON output
    "options": {"temperature": 0.1, "num_predict": 512}
})
```

## Key Files

- `docker-compose.yml` — full stack definition
- `services/sarah_api/sarah_api.py` — chat API + Ollama gateway
- `services/soar_blocker/soar_blocker.py` — threshold-based IP blocking
- `services/ai_analyst/ai_analyst.py` — **NEW: LLM analysis worker**
- `stream_aggregation/init.sql` — ksqlDB correlation queries
- `ui/src/SarahChatWidget.jsx` — React chat widget (hardcoded to 192.168.1.115:5000)
- `common/` — shared Python utilities
- `install-ollama.sh` — Ollama install script

## Coding Conventions

- Python services: Flask for HTTP, `kafka-python-ng` for Kafka, standard logging
- Env vars for all config (never hardcode credentials)
- Docker build context is always repo root (`.`)
- Dockerfile paths: `./services/<name>/Dockerfile`
- New services added to `docker-compose.yml` with `depends_on: [kafka]`

## Important Notes

- `SarahChatWidget.jsx` uses relative URLs via nginx proxy — works from any host
- `sarah_api` uses `OLLAMA_AVAILABLE` as a module-level cached flag — reset on restart
- SOAR blocker `BLOCKLIST_CMD` default is an echo (safe no-op) — enable carefully
- `packet_launcher` requires `ENABLE_PACKET_LAUNCHER=true` — lab use only
- ksqlDB init SQL runs once at startup via `ksqldb-cli` container

## AI Analyst Service (Target Architecture)

The `ai_analyst` service should:
1. Consume: `alert.correlated`, `security.alerts`, `netflow`, `dpi.events`, `voip.events`
2. For each event, build a context-rich prompt and query Ollama with `format: "json"`
3. Produce structured triage results to `ai.analysis` topic:
   ```json
   {
     "event_id": "...",
     "severity": "critical|high|medium|low|info",
     "confidence": 0.0-1.0,
     "threat_type": "...",
     "summary": "...",
     "recommendation": "block|monitor|investigate|ignore",
     "reasoning": "..."
   }
   ```
4. Write results to Neo4j as `AIAnalysis` nodes linked to alerts/assets
5. Expose `/summary` HTTP endpoint for latest analysis digest
