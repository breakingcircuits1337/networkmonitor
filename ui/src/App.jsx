import React, { useEffect, useRef, useState } from "react";
import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import HeatMapLayer from "./HeatMapLayer.jsx";
import ChoroplethLayer from "./ChoroplethLayer.jsx";
import ClusterLayer from "./ClusterLayer.jsx";
import { MapContainer, TileLayer, CircleMarker, Popup, useMap } from "react-leaflet";
import React, { useEffect, useRef, useState } from "react";

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

  // UI/UX
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [darkMode, setDarkMode] = useState(false);
  const mapRef = useRef();

  // Responsive mode
  const [isMobile, setIsMobile] = useState(window.innerWidth <= 600);
  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth <= 600);
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  // Add/remove dark class to body
  useEffect(() => {
    if (darkMode) document.body.classList.add("dark");
    else document.body.classList.remove("dark");
  }, [darkMode]);

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
        style={{
          height: "100%",
          width: "100%",
          transition: "margin-left 0.33s",
          marginLeft: !isMobile && sidebarOpen ? 270 : 0,
          filter: sidebarOpen ? "brightness(0.98)" : undefined,
          opacity: sidebarOpen && !isMobile ? 0.95 : 1
        }}
        preferCanvas={true}
        ref={mapRef}
      >
        <TileLayer
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          attribution="&copy; OpenStreetMap contributors"
        />
        <ChoroplethLayer countryCounts={countryCounts} />
        {showFlows && <HeatMapLayer points={filteredFlows} />}
        <ClusterLayer points={filteredFlows} show={showFlows} darkMode={darkMode} />
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
      {/* Sidebar / Controls */}
      <div
        className={`sidebar${sidebarOpen ? " open" : ""}${darkMode ? " dark" : ""}${isMobile ? " mobile" : ""}`}
        style={{
          transition: "all 0.33s cubic-bezier(.4,1.2,.6,1)",
          ...(sidebarOpen
            ? (isMobile
                ? { left: 0, top: 0, width: "100vw", height: 240, borderRadius: "0 0 18px 18px" }
                : { left: 0, top: 0, width: 270, height: "100vh", borderRadius: "0 18px 18px 0" })
            : (isMobile
                ? { left: 0, top: 0, width: "100vw", height: 44 }
                : { left: 0, top: 0, width: 54, height: 54, borderRadius: "0 0 18px 0" })
          )
        }}
      >
        {!sidebarOpen ? (
          <button
            className="sidebar-btn"
            style={{ margin: 6, fontSize: 28, background: "none", border: "none", cursor: "pointer", color: darkMode ? "#eee" : "#222" }}
            onClick={() => setSidebarOpen(true)}
            title="Open controls"
          >
            ☰
          </button>
        ) : (
          <div style={{ padding: isMobile ? "12px 18px 6px 18px" : "16px 18px 6px 18px" }}>
            <div style={{display:"flex", alignItems:"center", justifyContent:"space-between"}}>
              <h3 style={{ margin: 0, fontWeight: 600 }}>Network Geo Heatmap</h3>
              <button
                className="sidebar-btn"
                style={{ fontSize: 24, background: "none", border: "none", cursor: "pointer", color: darkMode ? "#eee" : "#222", marginLeft: 10 }}
                onClick={() => setSidebarOpen(false)}
                title="Close controls"
              >
                ✕
              </button>
            </div>
            <div style={{marginTop:8, marginBottom:10, fontSize:15, display:"flex", flexWrap:"wrap", gap:8}}>
              <label>
                <input type="checkbox" checked={showFlows} onChange={e => setShowFlows(e.target.checked)} />{" "}
                <span style={{ color: darkMode ? "#ffea00" : "#34c9eb" }}>●</span> Flows
              </label>
              <label>
                <input type="checkbox" checked={showIds} onChange={e => setShowIds(e.target.checked)} />{" "}
                <span style={{ color: "#e53935" }}>●</span> IDS Alerts
              </label>
              <label>
                <input type="checkbox" checked={showDpi} onChange={e => setShowDpi(e.target.checked)} />{" "}
                <span style={{ color: "#7c51a1" }}>●</span> DPI Events
              </label>
            </div>
            <div style={{marginBottom:10, display:"flex", alignItems: "center"}}>
              <button
                style={{
                  marginRight: 10, fontWeight: 600,
                  background: play ? "#eee" : "#fff",
                  border: "1px solid #aaa", borderRadius: 6, minWidth: 34, height: 34, cursor: "pointer"
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
            <div style={{fontSize:13, color: darkMode ? "#eee" : "#222"}}>
              {showFlows && <span><span style={{ color: darkMode ? "#ffea00" : "#34c9eb" }}>●</span> Flows ({filteredFlows.length})&nbsp;&nbsp;</span>}
              {showIds && <span><span style={{ color: "#e53935" }}>●</span> IDS Alerts ({filteredIds.length})&nbsp;&nbsp;</span>}
              {showDpi && <span><span style={{ color: "#7c51a1" }}>●</span> DPI Events ({filteredDpi.length})</span>}
            </div>
            <div style={{marginTop:4, fontSize:12, color: darkMode ? "#ccc" : "#333"}}>
              <span style={{ color: darkMode ? "#ffea00" : "#34c9eb" }}>●</span> = flow (clusters show flow counts), <span style={{ color: "#e53935" }}>●</span> IDS alert, <span style={{ color: "#7c51a1" }}>●</span> DPI event.<br />
              Timeline window controls event visibility by time.
            </div>
            <div style={{marginTop:10, display: "flex", alignItems: "center", gap: 10}}>
              <button
                className="sidebar-btn"
                style={{
                  fontWeight: 600, borderRadius: 6, border: "1px solid #aaa",
                  background: darkMode ? "#252525" : "#f7f7f7",
                  color: darkMode ? "#ffea00" : "#333",
                  padding: "5px 12px", fontSize: 15, cursor: "pointer"
                }}
                onClick={() => setDarkMode(dm => !dm)}
                title="Toggle dark/light mode"
              >
                {darkMode ? "🌙" : "☀️"} {darkMode ? "Dark" : "Light"}
              </button>
              <button
                className="sidebar-btn"
                style={{
                  fontWeight: 600, borderRadius: 6, border: "1px solid #aaa",
                  background: darkMode ? "#252525" : "#f7f7f7",
                  color: darkMode ? "#ffea00" : "#333",
                  padding: "5px 12px", fontSize: 15, cursor: "pointer"
                }}
                onClick={() => {
                  if (mapRef.current) {
                    const map = mapRef.current;
                    if (map.flyTo) map.flyTo([20, 0], 2, { animate: true, duration: 1.1 });
                    else if (map._leaflet_map) map._leaflet_map.flyTo([20, 0], 2, { animate: true, duration: 1.1 });
                  }
                }}
                title="Reset map view"
              >
                ⟳ Reset Map
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}