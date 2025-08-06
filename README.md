# Unified Network Visibility Platform

This repository implements a modular, microservices-based network visibility and threat detection platform.  
**Key components:**
- **sensors/asset_discovery**: Automated asset discovery microservice (active/passive scans, produces asset records to Kafka).
- **services/topology_updater**: (Placeholder) Consumes asset events and updates Neo4j network graph.
- **common/**: Shared Python utilities.
- **configs/**: Centralized config files/environment templates.
- **ui/**: Web dashboard frontend (to be implemented).
- **working network alert.py**: (Legacy, will be deprecated).

## Architecture at a Glance

```
+------------+        +-------------+        +-------------+
| Asset      | -----> |  Kafka      | -----> | Topology    |
| Discovery  |        |  Broker     |        | Updater     |
| Sensor     |        |             |        | (Neo4j)     |
+------------+        +-------------+        +-------------+
      |
      v
+-------------+
| (Future:    |
| UI, SIEM,   |
| SOAR, etc.) |
+-------------+
```

- **Asset Discovery** microservice scans the local network, identifies assets, and publishes results to Kafka.
- **Kafka** acts as the message bus.
- **Topology Updater** (coming soon) consumes asset data and updates the live network graph in Neo4j.
- **UI** and other integrations will consume data via API.

## Local Development (Docker Compose)

**Requirements:**  
- Docker & Docker Compose (v2+)

**Quick Start:**
```sh
docker-compose up --build
```

- Access Neo4j at [http://localhost:7474](http://localhost:7474) (user: neo4j / password: neo4jpassword)
- Kafka broker is available at `localhost:9092`
- Asset discovery logs will appear in the compose output
- Topology Updater service will automatically consume asset records and update the Neo4j graph in real time
- Traffic Analysis sensor (host-mode container) sniffs interface traffic, summarizes flows, and publishes to Kafka topic `netflow` every 30 seconds
- **Encrypted Traffic Analysis Sensor**: (host-mode container) monitors TLS handshakes, extracts JA3/JA3S/SNI/fingerprint metadata, and publishes to Kafka topic `tls.meta`.
- **Suricata IDS/IPS**: Monitors all traffic for known threats, outputs alerts to `eve.json`.
- **IDS Alert Forwarder**: Reads Suricata EVE alerts and forwards them to Kafka topic `security.alerts`.

**Viewing Suricata Alerts in Neo4j:**
- Future feature: Security alerts from `security.alerts` topic will be correlated with asset and flow data in Neo4j, enabling rich threat hunting and investigation workflows. (Work in progress.)

**Stream Aggregation & Alert Correlation (ksqlDB):**
- The stack includes [ksqlDB](https://ksqldb.io/) for real-time stream processing and enrichment.
- Asset discovery and security alerts are joined in ksqlDB to produce a `correlated_alerts` stream (Kafka topic `alert.correlated`).
- You can interactively query ksqlDB at [http://localhost:8088](http://localhost:8088) or with `docker exec -it ksqldb-cli ksql http://ksqldb-server:8088`.
- To see joined alerts:
  ```sql
  SELECT * FROM correlated_alerts EMIT CHANGES;
  ```
- See `stream_aggregation/init.sql` for the correlation logic.

**Alert Sink Neo4j Integration:**
- The `alert_sink_neo4j` service consumes correlated alerts from Kafka and writes them to Neo4j, creating relationships from source asset to alert (and to target asset if present).
- This enables security analysts to query and visualize incidents, attack paths, and asset-alert relationships directly in Neo4j.

**Deep Packet Inspection (Zeek DPI Engine):**
- The stack integrates [Zeek](https://zeek.org/) as a DPI engine, running in host mode and capturing detailed protocol and session logs in JSON format.
- The `dpi_event_forwarder` service tails Zeek's JSON logs and publishes each event to the Kafka topic `dpi.events`.
- This enables real-time application-layer visibility and session analytics for the platform.

## Live Geo Heatmap & World Map

- The stack includes a **GeoIP enrichment micro-service** that consumes network flow events, adds country and lat/lon, republishes to Kafka, and exposes a real-time SSE stream for browsers.
- The **UI** (React + Leaflet) displays live heatmap and marker visualizations of flow sources on a world map.
- Access the UI at [http://localhost:8080](http://localhost:8080).
- **GeoIP database required**: Download [GeoLite2-City.mmdb](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data?lang=en) (free with registration) and place it in the repo root before starting the stack.

**Environment Variables:**  
- See `sensors/asset_discovery/asset_discovery.py`, `services/topology_updater/topology_updater.py`, `sensors/traffic_analysis/traffic_analysis.py`, `sensors/encrypted_traffic_analysis/encrypted_traffic_analysis.py`, and `sensors/ids_alert_forwarder/ids_alert_forwarder.py` for configurable parameters.

**Note:**  
No real secrets or credentials are stored in this repository.  
See `.gitignore` for ignored files.