-- ksqlDB initialization script for alert correlation

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
  TIMESTAMP='timestamp'
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