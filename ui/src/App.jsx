import React, { useEffect, useRef, useState } from "react";
import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import HeatMapLayer from "./HeatMapLayer.jsx";
import ChoroplethLayer from "./ChoroplethLayer.jsx";
import ClusterLayer from "./ClusterLayer.jsx";

const EVENT_URL = "http://geoip_enricher:5000/events";
const MAX_FLOWS = 2000, MAX_ALERTS = 500, MIN_RETENTION = 30, MAX_RETENTION = 600;

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function parseTS(ts) {
  if (!ts) return 0;
  if (typeof ts === "number") return ts;
  // Try ISO8601 or float string
  const d = Date.parse(ts);
  if (!isNaN(d)) return Math.floor(d / 1000);
  const num = parseFloat(ts);
  if (!isNaN(num)) return Math.floor(num);
  return 0;
}

export default function App() {
  // state
  const [flows, setFlows] = useState([]);
  const [idsAlerts, setIdsAlerts] = useState([]);
  const [dpiEvents, setDpiEvents] = useState([]);
  const [showFlows, setShowFlows] = useState(true);
  const [showIds, setShowIds] = useState(true);
  const [showDpi, setShowDpi] = useState(true);
  const [retentionSec, setRetentionSec] = useState(300);

  // main event handler
  useEffect(() => {
    const ev = new window.EventSource(EVENT_URL);
    ev.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        const ts = parseTS(data.timestamp);
        if (!data.event_type) {
          setFlows((prev) => {
            const next = [...prev, { ...data, _ts: ts }];
            return next.length > MAX_FLOWS ? next.slice(next.length - MAX_FLOWS) : next;
          });
        } else if (data.event_type === "flow") {
          setFlows((prev) => {
            const next = [...prev, { ...data, _ts: ts }];
            return next.length > MAX_FLOWS ? next.slice(next.length - MAX_FLOWS) : next;
          });
        } else if (data.event_type === "ids_alert") {
          setIdsAlerts((prev) => {
            const next = [...prev, { ...data, _ts: ts }];
            return next.length > MAX_ALERTS ? next.slice(next.length - MAX_ALERTS) : next;
          });
        } else if (data.event_type === "dpi_event") {
          setDpiEvents((prev) => {
            const next = [...prev, { ...data, _ts: ts }];
            return next.length > MAX_ALERTS ? next.slice(next.length - MAX_ALERTS) : next;
          });
        }
      } catch {}
    };
    return () => ev.close();
  }, []);

  // Filtering by retention window
  const cutoff = nowSec() - retentionSec;
  const filteredFlows = flows.filter(f => f._ts >= cutoff && f.lat && f.lon);
  const filteredIds = idsAlerts.filter(f => f._ts >= cutoff && f.lat && f.lon);
  const filteredDpi = dpiEvents.filter(f => f._ts >= cutoff && f.lat && f.lon);

  // Country counts for flows (choropleth)
  const countryCounts = {};
  for (const f of filteredFlows) {
    if (f.country) countryCounts[f.country] = (countryCounts[f.country] || 0) + 1;
  }

  // Neo4j asset link
  const assetLink = ip => `http://localhost:7474/browser/?cmd=play&arg=MATCH%20(a:Asset%20{ip:%20'${encodeURIComponent(ip)}'})%20RETURN%20a`;

  return (
    <div style={{ height: "100vh", width: "100vw" }}>
      <MapContainer
        center={[20, 0]}
        zoom={2}
        scrollWheelZoom={true}
        style={{ height: "100%", width: "100%" }}
        preferCanvas={true}
      >
        <TileLayer
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          attribution="&copy; OpenStreetMap contributors"
        />
        <ChoroplethLayer countryCounts={countryCounts} />
        {showFlows && <HeatMapLayer points={filteredFlows} />}
        <ClusterLayer points={filteredFlows} show={showFlows} />
        {/* IDS Alerts - red circle */}
        {showIds && filteredIds.map((p, idx) =>
          p.lat && p.lon ? (
            <CircleMarker
              key={`ids-${idx}`}
              center={[p.lat, p.lon]}
              radius={6}
              fillOpacity={0.8}
              color="#e53935"
              stroke={false}
            >
              <Popup>
                <div>
                  <b>IDS Alert</b>
                  <br />
                  {p.signature && <span>Signature: {p.signature}<br /></span>}
                  {p.category && <span>Category: {p.category}<br /></span>}
                  {p.severity !== undefined && <span>Severity: {p.severity}<br /></span>}
                  <span>IP: {p.src_ip}</span>
                  <br />
                  <a href={assetLink(p.src_ip)} target="_blank" rel="noopener noreferrer">Open in Neo4j</a>
                </div>
              </Popup>
            </CircleMarker>
          ) : null
        )}
        {/* DPI Events - purple circle */}
        {showDpi && filteredDpi.map((p, idx) =>
          p.lat && p.lon ? (
            <CircleMarker
              key={`dpi-${idx}`}
              center={[p.lat, p.lon]}
              radius={5}
              fillOpacity={0.7}
              color="#7c51a1"
              stroke={false}
            >
              <Popup>
                <div>
                  <b>DPI Event</b>
                  <br />
                  {p.protocol && <span>Proto: {p.protocol}<br /></span>}
                  <span>IP: {p.src_ip}</span>
                  <br />
                  <a href={assetLink(p.src_ip)} target="_blank" rel="noopener noreferrer">Open in Neo4j</a>
                </div>
              </Popup>
            </CircleMarker>
          ) : null
        )}
      </MapContainer>
      {/* Controls overlay */}
      <div style={{
        position: "absolute", top: 10, left: 10, background: "rgba(255,255,255,0.95)", padding: "12px 16px",
        borderRadius: 10, minWidth: 270, boxShadow: "0 1px 6px #9992"
      }}>
        <h3 style={{ margin: 0, marginBottom: 6 }}>Network Geo Heatmap</h3>
        <div style={{marginBottom:8, fontSize:14}}>
          <label>
            <input type="checkbox" checked={showFlows} onChange={e => setShowFlows(e.target.checked)} />{" "}
            <span style={{ color: "#34c9eb" }}>●</span> Flows
          </label>{" "}
          <label>
            <input type="checkbox" checked={showIds} onChange={e => setShowIds(e.target.checked)} />{" "}
            <span style={{ color: "#e53935" }}>●</span> IDS Alerts
          </label>{" "}
          <label>
            <input type="checkbox" checked={showDpi} onChange={e => setShowDpi(e.target.checked)} />{" "}
            <span style={{ color: "#7c51a1" }}>●</span> DPI Events
          </label>
        </div>
        <div style={{marginBottom:8}}>
          <label>Retention: {retentionSec}s
            <input
              style={{ verticalAlign: "middle", marginLeft: 8 }}
              type="range"
              min={MIN_RETENTION}
              max={MAX_RETENTION}
              value={retentionSec}
              onChange={e => setRetentionSec(Number(e.target.value))}
            />
          </label>
        </div>
        <div style={{fontSize:13, color: "#222"}}>
          {showFlows && <span><span style={{ color: "#34c9eb" }}>●</span> Flows ({filteredFlows.length})&nbsp;&nbsp;</span>}
          {showIds && <span><span style={{ color: "#e53935" }}>●</span> IDS Alerts ({filteredIds.length})&nbsp;&nbsp;</span>}
          {showDpi && <span><span style={{ color: "#7c51a1" }}>●</span> DPI Events ({filteredDpi.length})</span>}
        </div>
        <div style={{marginTop:4, fontSize:12}}>
          Blue = flow (clusters show flow counts), Red = IDS alert, Purple = DPI event.<br />
          Retention controls fade-out by time (sec).
        </div>
      </div>
    </div>
  );
}