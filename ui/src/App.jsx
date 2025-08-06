import React, { useEffect, useRef, useState } from "react";
import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import HeatMapLayer from "./HeatMapLayer.jsx";
import ChoroplethLayer from "./ChoroplethLayer.jsx";
import ClusterLayer from "./ClusterLayer.jsx";

const EVENT_URL = "http://geoip_enricher:5000/events";
const MAX_FLOWS = 2000, MAX_ALERTS = 500, MIN_WINDOW = 10, MAX_WINDOW = 600, DEFAULT_WINDOW = 60;

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

function fmtTime(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  return d.toLocaleString();
}

export default function App() {
  // state
  const [flows, setFlows] = useState([]);
  const [idsAlerts, setIdsAlerts] = useState([]);
  const [dpiEvents, setDpiEvents] = useState([]);
  const [showFlows, setShowFlows] = useState(true);
  const [showIds, setShowIds] = useState(true);
  const [showDpi, setShowDpi] = useState(true);
  const [windowSec, setWindowSec] = useState(DEFAULT_WINDOW);
  const [timelinePos, setTimelinePos] = useState(nowSec());
  const [play, setPlay] = useState(false);

  // Buffer updates and timelinePos logic
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
        // Whenever new data comes in, advance timelinePos if live or if new max
        setTimelinePos((curr) => {
          const allTs = [
            ...flows, ...idsAlerts, ...dpiEvents,
            { _ts: ts }
          ].map(f => f._ts || 0);
          const maxTs = Math.max(...allTs, 0);
          if (play || curr === undefined || curr < maxTs - 2) return maxTs;
          return curr;
        });
      } catch {}
    };
    return () => ev.close();
    // eslint-disable-next-line
  }, []);

  // Timeline min/max
  const allTsArr = [...flows, ...idsAlerts, ...dpiEvents].map(f => f._ts || 0).filter(Boolean);
  const minTs = allTsArr.length ? Math.min(...allTsArr) : nowSec() - 600;
  const maxTs = allTsArr.length ? Math.max(...allTsArr) : nowSec();

  // Playback effect
  useEffect(() => {
    if (!play) return;
    if (timelinePos >= maxTs) {
      setPlay(false);
      return;
    }
    const t = setInterval(() => {
      setTimelinePos((tp) => {
        if (tp < maxTs) return tp + 1;
        setPlay(false);
        return tp;
      });
    }, 500);
    return () => clearInterval(t);
    // eslint-disable-next-line
  }, [play, timelinePos, maxTs]);

  // Filter events by timeline window
  const windowStart = timelinePos - windowSec;
  const windowEnd = timelinePos;
  const filteredFlows = flows.filter(f => f._ts >= windowStart && f._ts <= windowEnd && f.lat && f.lon);
  const filteredIds = idsAlerts.filter(f => f._ts >= windowStart && f._ts <= windowEnd && f.lat && f.lon);
  const filteredDpi = dpiEvents.filter(f => f._ts >= windowStart && f._ts <= windowEnd && f.lat && f.lon);

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
        position: "absolute", top: 10, left: 10, background: "rgba(255,255,255,0.97)", padding: "14px 18px",
        borderRadius: 10, minWidth: 340, boxShadow: "0 1px 6px #9992"
      }}>
        <h3 style={{ margin: 0, marginBottom: 6 }}>Network Geo Heatmap</h3>
        <div style={{marginBottom:10, fontSize:15}}>
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
        <div style={{marginBottom:10, display:"flex", alignItems: "center"}}>
          <button
            style={{
              marginRight: 12, fontWeight: 600,
              background: play ? "#eee" : "#fff",
              border: "1px solid #aaa", borderRadius: 6, minWidth: 40, height: 34, cursor: "pointer"
            }}
            onClick={() => setPlay(pl => !pl)}
            title={play ? "Pause" : "Play"}
          >
            {play ? "⏸️" : "▶️"}
          </button>
          <input
            type="range"
            min={minTs}
            max={maxTs}
            value={timelinePos}
            onChange={e => {
              setPlay(false);
              setTimelinePos(Number(e.target.value));
            }}
            style={{ flex: 1, marginRight: 10 }}
          />
          <span style={{ fontFamily: "monospace", fontSize: 13, minWidth: 120 }}>
            {fmtTime(timelinePos)}
          </span>
        </div>
        <div style={{marginBottom:10, fontSize:14}}>
          <label>
            Window:{" "}
            <input
              type="number"
              min={MIN_WINDOW}
              max={MAX_WINDOW}
              value={windowSec}
              onChange={e => setWindowSec(Number(e.target.value))}
              style={{ width: 60, marginRight: 6 }}
            />
            seconds
          </label>
        </div>
        <div style={{fontSize:13, color: "#222"}}>
          {showFlows && <span><span style={{ color: "#34c9eb" }}>●</span> Flows ({filteredFlows.length})&nbsp;&nbsp;</span>}
          {showIds && <span><span style={{ color: "#e53935" }}>●</span> IDS Alerts ({filteredIds.length})&nbsp;&nbsp;</span>}
          {showDpi && <span><span style={{ color: "#7c51a1" }}>●</span> DPI Events ({filteredDpi.length})</span>}
        </div>
        <div style={{marginTop:4, fontSize:12}}>
          Blue = flow (clusters show flow counts), Red = IDS alert, Purple = DPI event.<br />
          Timeline window controls event visibility by time.
        </div>
      </div>
    </div>
  );
}