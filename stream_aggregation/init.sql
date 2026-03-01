-- ksqlDB initialization script v2
-- State stores are backed by RocksDB (KSQL_KSQL_STREAMS_STATE_DIR volume-mounted)
-- so materialized tables survive container restarts.

-- STREAM of asset discovery events
CREATE STREAM asset_stream (
  timestamp VARCHAR,
  ip VARCHAR,
  mac VARCHAR,
  hostname VARCHAR,
  ports ARRAY<STRUCT<port INT, proto VARCHAR, state VARCHAR, service VARCHAR>>
) WITH (
  KAFKA_TOPIC='asset.discovery',
  VALUE_FORMAT='JSON',
  TIMESTAMP='timestamp',
  TIMESTAMP_FORMAT='yyyy-MM-dd HH:mm:ss'
);

-- MATERIALIZED TABLE keyed by IP for latest asset state
CREATE TABLE assets_by_ip AS
  SELECT ip,
         LATEST_BY_OFFSET(mac) AS mac,
         LATEST_BY_OFFSET(hostname) AS hostname,
         LATEST_BY_OFFSET(ports) AS ports,
         LATEST_BY_OFFSET(timestamp) AS last_seen
  FROM asset_stream
  GROUP BY ip
  EMIT CHANGES;

-- STREAM of Suricata alerts
CREATE STREAM ids_alerts_raw (
  src_ip VARCHAR,
  dest_ip VARCHAR,
  alert STRUCT<signature VARCHAR, category VARCHAR, severity INT>
) WITH (
  KAFKA_TOPIC='security.alerts',
  VALUE_FORMAT='JSON'
);

-- Enrich alerts with asset info
CREATE STREAM correlated_alerts WITH (KAFKA_TOPIC='alert.correlated', VALUE_FORMAT='JSON') AS
  SELECT ia.src_ip,
         ia.dest_ip,
         ia.alert.signature AS signature,
         ia.alert.category AS category,
         ia.alert.severity AS severity,
         a.hostname AS src_hostname,
         a.mac AS src_mac,
         a.ports AS src_ports,
         ia.*
  FROM ids_alerts_raw ia
  LEFT JOIN assets_by_ip a ON ia.src_ip = a.ip
  EMIT CHANGES;

-- ── DNS events stream (v2) ────────────────────────────────────────────────────
CREATE STREAM IF NOT EXISTS dns_events (
  src_ip      VARCHAR,
  query       VARCHAR,
  query_type  INT,
  is_response BOOLEAN,
  is_nxdomain BOOLEAN,
  is_dga      BOOLEAN,
  dga_score   DOUBLE,
  dga_reason  VARCHAR,
  is_rpz_hit  BOOLEAN,
  nx_burst    BOOLEAN,
  timestamp   VARCHAR
) WITH (
  KAFKA_TOPIC='dns.events',
  VALUE_FORMAT='JSON'
);

-- Materialized table of DGA/suspicious domains seen per source IP
CREATE TABLE IF NOT EXISTS dga_by_src AS
  SELECT src_ip,
         COUNT(*) AS dga_count,
         LATEST_BY_OFFSET(query) AS last_dga_domain,
         LATEST_BY_OFFSET(dga_score) AS last_score
  FROM dns_events
  WHERE is_dga = TRUE
  GROUP BY src_ip
  EMIT CHANGES;

-- ── IOC feed stream (v2) ──────────────────────────────────────────────────────
CREATE STREAM IF NOT EXISTS ioc_feed (
  ioc_type    VARCHAR,
  indicator   VARCHAR,
  threat_type VARCHAR,
  source      VARCHAR,
  confidence  DOUBLE,
  timestamp   VARCHAR
) WITH (
  KAFKA_TOPIC='ioc.feed',
  VALUE_FORMAT='JSON'
);

-- ── Credential alert stream (v2) ──────────────────────────────────────────────
CREATE STREAM IF NOT EXISTS credential_alerts (
  alert_type   VARCHAR,
  email        VARCHAR,
  breach_name  VARCHAR,
  breach_date  VARCHAR,
  severity     VARCHAR,
  timestamp    VARCHAR
) WITH (
  KAFKA_TOPIC='credential.alerts',
  VALUE_FORMAT='JSON'
);