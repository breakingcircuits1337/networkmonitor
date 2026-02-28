import React, {
  useEffect, useRef, useState, useCallback, useMemo,
} from "react";
import Globe from "react-globe.gl";
import { MapContainer, TileLayer, CircleMarker, Polyline, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import SarahChatWidget from "./SarahChatWidget.jsx";

// Role display metadata
const ROLE_META = {
  threat_hunter:      { icon: "🎯", color: "#e53935" },
  traffic_analyst:    { icon: "📈", color: "#00e5ff" },
  incident_responder: { icon: "🚨", color: "#FF6F00" },
  voip_guardian:      { icon: "📞", color: "#00BCD4" },
  geo_intel:          { icon: "🌍", color: "#7c51a1" },
  behavioral:         { icon: "🧠", color: "#FFC107" },
  malware_classifier: { icon: "🦠", color: "#e53935" },
};

// All URLs are relative — nginx proxies to backend. Works from any LAN machine.
const EVENTS_URL = "/events";

const MAX_FLOWS = 2000, MAX_ALERTS = 500;
const MIN_WINDOW = 10, MAX_WINDOW = 3600, DEFAULT_WINDOW = 600;

// Arc target — home base (change to your sensor's physical location)
const HOME_LAT = 38.9, HOME_LNG = -77.0;

// Protocol number → arc color
const PROTO_COLOR = {
  1:  "#FF6F00",  // ICMP  — amber
  6:  "#00e5ff",  // TCP   — cyan
  17: "#00e676",  // UDP   — green
  47: "#CE93D8",  // GRE   — purple
  50: "#FF8A65",  // ESP   — orange
  58: "#FFF176",  // ICMPv6 — yellow
};
const protoColor = (p) => PROTO_COLOR[p?.protocol] || "#546E7A";

const AI_SEV_COLOR = {
  critical: "#7b0000",
  high:     "#e53935",
  medium:   "#FF6F00",
  low:      "#FFC107",
  info:     "#42A5F5",
  unknown:  "#9E9E9E",
};

const THREAT_COLOR = {
  CRITICAL: "#e53935",
  HIGH:     "#FF6F00",
  ELEVATED: "#FFC107",
  NORMAL:   "#00e676",
};

function nowSec() { return Math.floor(Date.now() / 1000); }

function parseTS(ts) {
  if (!ts) return 0;
  if (typeof ts === "number") return ts;
  const d = Date.parse(ts);
  if (!isNaN(d)) return Math.floor(d / 1000);
  const n = parseFloat(ts);
  if (!isNaN(n)) return Math.floor(n);
  return 0;
}

function fmtTime(ts) {
  if (!ts) return "";
  return new Date(ts * 1000).toLocaleString();
}

function assetLink(ip) {
  const host = window.location.hostname;
  const cmd  = encodeURIComponent(`MATCH (a:Asset {ip: '${ip}'}) RETURN a`);
  return `http://${host}:7474/browser/?cmd=play&arg=${cmd}`;
}

// lng helper — geoip_enricher emits `lon`, globe.gl needs `lng`
const toLng = p => p.lng ?? p.lon ?? 0;

export default function App() {
  const [flows,      setFlows]      = useState([]);
  const [idsAlerts,  setIdsAlerts]  = useState([]);
  const [dpiEvents,  setDpiEvents]  = useState([]);
  const [voipEvents, setVoipEvents] = useState([]);
  const [aiEvents,   setAiEvents]   = useState([]);

  const [showFlows, setShowFlows] = useState(true);
  const [showIds,   setShowIds]   = useState(true);
  const [showDpi,   setShowDpi]   = useState(true);
  const [showVoip,  setShowVoip]  = useState(true);
  const [showAi,    setShowAi]    = useState(true);
  const [showArcs,  setShowArcs]  = useState(true);

  const [windowSec,   setWindowSec]   = useState(DEFAULT_WINDOW);
  const [timelinePos, setTimelinePos] = useState(nowSec());
  const [play,        setPlay]        = useState(false);
  const [connected,   setConnected]   = useState(false);
  const [sidebarOpen,    setSidebarOpen]    = useState(false);
  const [roles,          setRoles]          = useState([]);
  const [viewMode,       setViewMode]       = useState("globe"); // "globe" or "map"
  const [selectedPoint,  setSelectedPoint]  = useState(null);

  // Globe size — needs explicit px for Three.js renderer
  const [globeW, setGlobeW] = useState(window.innerWidth);
  const [globeH, setGlobeH] = useState(window.innerHeight);

  const globeRef = useRef();

  useEffect(() => {
    const h = () => { setGlobeW(window.innerWidth); setGlobeH(window.innerHeight); };
    window.addEventListener("resize", h);
    return () => window.removeEventListener("resize", h);
  }, []);

  // Poll sub-agent role stats every 15s
  useEffect(() => {
    const fetchRoles = () =>
      fetch("/api/roles", { signal: AbortSignal.timeout(5000) })
        .then(r => r.ok ? r.json() : null)
        .then(d => { if (d?.roles) setRoles(d.roles); })
        .catch(() => {});
    fetchRoles();
    const t = setInterval(fetchRoles, 15000);
    return () => clearInterval(t);
  }, []);

  // Auto-rotate on mount
  useEffect(() => {
    if (!globeRef.current) return;
    const ctrl = globeRef.current.controls();
    ctrl.autoRotate      = true;
    ctrl.autoRotateSpeed = 0.35;
    globeRef.current.pointOfView({ altitude: 2.5 }, 0);
  }, []);

  // Route an incoming SSE event into the correct state bucket
  const routeEvent = useCallback((data) => {
    const topic     = data.topic || "";
    const eventType = data.event_type || "";
    const ts        = parseTS(data.timestamp);
    const ev        = { ...data, _ts: ts };

    const push = (setter, max) =>
      setter(prev => {
        const next = [...prev, ev];
        return next.length > max ? next.slice(next.length - max) : next;
      });

    if (topic === "netflow" || topic === "raw.flows" || eventType === "flow" || eventType === "raw_flow" || (!topic && !eventType)) {
      push(setFlows, MAX_FLOWS);
    } else if (
      topic === "security.alerts" || topic === "alert.correlated" || eventType === "ids_alert"
    ) {
      push(setIdsAlerts, MAX_ALERTS);
    } else if (topic === "dpi.events" || eventType === "dpi_event") {
      push(setDpiEvents, MAX_ALERTS);
    } else if (topic === "voip.events" || eventType === "voip") {
      push(setVoipEvents, MAX_ALERTS);
    } else if (topic === "ai.analysis") {
      push(setAiEvents, MAX_ALERTS);
    }

    setTimelinePos(curr => Math.max(curr, ts));
  }, [play]);

  // SSE connection
  useEffect(() => {
    let ev;
    const connect = () => {
      ev = new EventSource(EVENTS_URL);
      ev.onopen    = () => setConnected(true);
      ev.onerror   = () => { setConnected(false); ev.close(); setTimeout(connect, 5000); };
      ev.onmessage = (e) => { try { routeEvent(JSON.parse(e.data)); } catch {} };
    };
    connect();
    return () => ev && ev.close();
  }, [routeEvent]);

  // Timeline bounds
  const allTs = [...flows, ...idsAlerts, ...dpiEvents, ...voipEvents, ...aiEvents]
    .map(f => f._ts || 0).filter(Boolean);
  const minTs = allTs.length ? Math.min(...allTs) : nowSec() - 600;
  const maxTs = allTs.length ? Math.max(...allTs) : nowSec();

  // Playback
  useEffect(() => {
    if (!play) return;
    if (timelinePos >= maxTs) { setPlay(false); return; }
    const t = setInterval(() => {
      setTimelinePos(tp => { if (tp < maxTs) return tp + 1; setPlay(false); return tp; });
    }, 500);
    return () => clearInterval(t);
  }, [play, maxTs]); // eslint-disable-line

  const ws = timelinePos - windowSec;
  const we = timelinePos;
  const inWindow = arr => arr.filter(f => f._ts >= ws && f._ts <= we);
  const onGlobe  = arr => inWindow(arr).filter(f => f.lat && (f.lon || f.lng));

  const filteredFlows  = onGlobe(flows);
  const filteredIds    = onGlobe(idsAlerts);
  const filteredDpi    = onGlobe(dpiEvents);
  const filteredVoip   = onGlobe(voipEvents);
  const filteredAi     = onGlobe(aiEvents);
  const aiCritical     = filteredAi.filter(
    a => a.severity === "critical" || a.severity === "high"
  ).length;

  // Threat level badge
  const threatLevel = aiCritical > 5 ? "CRITICAL"
    : aiCritical > 0 ? "HIGH"
    : filteredIds.length > 10 ? "ELEVATED"
    : "NORMAL";

  // ── Globe data sets ────────────────────────────────────────────────────────

  // Hex-bin columns for network flows
  const hexPoints = useMemo(() => !showFlows ? [] :
    filteredFlows.map(f => ({
      lat: f.lat,
      lng: toLng(f),
      weight: Math.log(1 + (f.bytes || 1)),
    })),
  [filteredFlows, showFlows]); // eslint-disable-line

  // Combined event points for all enabled layers
  const allPoints = useMemo(() => {
    const pts = [];
    if (showIds)  filteredIds.forEach(p  => pts.push({ ...p, lng: toLng(p), _col: "#e53935",                              _r: 0.38 }));
    if (showDpi)  filteredDpi.forEach(p  => pts.push({ ...p, lng: toLng(p), _col: "#7c51a1",                              _r: 0.28 }));
    if (showVoip) filteredVoip.forEach(p => pts.push({ ...p, lng: toLng(p), _col: "#00BCD4",                              _r: 0.32 }));
    if (showAi)   filteredAi.forEach(p  => pts.push({ ...p, lng: toLng(p), _col: AI_SEV_COLOR[p.severity] || "#9E9E9E",  _r: 0.42 }));
    return pts;
  }, [filteredIds, filteredDpi, filteredVoip, filteredAi, showIds, showDpi, showVoip, showAi]); // eslint-disable-line

  // Arcs — IDS alerts (red) + raw flows (protocol color)
  const arcs = useMemo(() => {
    if (!showArcs) return [];
    const out = [];
    filteredIds.filter(p => p.lat && (p.lon || p.lng)).slice(-40).forEach(p => out.push({
      startLat: p.lat, startLng: toLng(p), endLat: HOME_LAT, endLng: HOME_LNG,
      color: ["rgba(229,57,53,0.9)", "rgba(255,87,34,0.04)"],
      _label: p,
    }));
    filteredFlows.filter(p => p.lat && (p.lon || p.lng) &&
      !(p.lat === HOME_LAT && toLng(p) === HOME_LNG)  // skip pure-LAN arcs
    ).slice(-80).forEach(p => {
      const c = protoColor(p);
      out.push({
        startLat: p.lat, startLng: toLng(p), endLat: HOME_LAT, endLng: HOME_LNG,
        color: [`${c}cc`, `${c}08`],
        _label: p,
      });
    });
    return out;
  }, [filteredIds, filteredFlows, showArcs]); // eslint-disable-line

  // HTML tooltip for event points
  const pointLabel = useCallback((p) => {
    const topic = p.topic || p.event_type || "EVENT";
    const col   = p._col || "#00e5ff";
    return `
      <div style="background:rgba(0,8,20,0.9);border:1px solid ${col}55;border-radius:6px;
                  padding:8px 12px;font-family:monospace;font-size:12px;color:#e8e8e8;max-width:220px;
                  box-shadow:0 0 12px ${col}33">
        <b style="color:${col}">${topic.toUpperCase()}</b><br/>
        ${p.src_ip        ? `<b>src:</b> ${p.src_ip}${p.src_port ? `:${p.src_port}` : ""}<br/>` : ""}
        ${p.dst_ip        ? `<b>dst:</b> ${p.dst_ip}${p.dst_port ? `:${p.dst_port}` : ""}<br/>` : ""}
        ${p.proto_name || p.protocol !== undefined ? `<b>proto:</b> ${p.proto_name || p.protocol}<br/>` : ""}
        ${p.bytes         ? `<b>bytes:</b> ${p.bytes.toLocaleString()}<br/>`  : ""}
        ${p.packets       ? `<b>pkts:</b>  ${p.packets}<br/>`                 : ""}
        ${p.signature     ? `<b>sig:</b> ${p.signature}<br/>`         : ""}
        ${p.severity !== undefined ? `<b>sev:</b> ${p.severity}<br/>` : ""}
        ${p.summary       ? `<b>ai:</b>  ${p.summary}<br/>`           : ""}
        ${p.country       ? `<b>cc:</b>  ${p.country}<br/>`           : ""}
        ${p._ts           ? `<small style="opacity:.55">${fmtTime(p._ts)}</small><br/>` : ""}
        ${p.src_ip        ? `<a href="${assetLink(p.src_ip)}" target="_blank"
                               style="color:#00e5ff;font-size:11px">Neo4j →</a>` : ""}
      </div>`;
  }, []);

  return (
    <div style={{ position: "relative", width: "100vw", height: "100vh", overflow: "hidden", background: "#000010" }}>
      {/* CRT scanline + grid overlays (defined in index.html) */}
      <div className="scanline" />
      <div className="grid-overlay" />

      {/* 3D Globe — fills full viewport */}
      <Globe
        ref={globeRef}
        width={globeW}
        height={globeH}

        // Textures
        globeImageUrl="/img/earth-night.jpg"
        backgroundImageUrl="/img/night-sky.png"

        // Atmosphere — faint cyan glow
        atmosphereColor="rgba(0,229,255,0.18)"
        atmosphereAltitude={0.22}

        // ── Hex-bin layer — network flow volume ──────────────────────────────
        hexBinPointsData={hexPoints}
        hexBinPointLat="lat"
        hexBinPointLng="lng"
        hexBinPointWeight="weight"
        hexBinResolution={4}
        hexTopColor={() => "rgba(0,229,255,0.88)"}
        hexSideColor={() => "rgba(0,229,255,0.18)"}
        hexAltitude={d => d.sumWeight * 0.0006}
        hexBinMerge={true}
        hexLabel={d =>
          `<div style="font-family:monospace;font-size:11px;color:#00e5ff;
                       background:rgba(0,8,20,.85);padding:4px 8px;border-radius:4px">
             flows: ${d.points?.length ?? 0}
           </div>`
        }

        // ── Points layer — all event types ───────────────────────────────────
        pointsData={allPoints}
        pointLat="lat"
        pointLng="lng"
        pointColor="_col"
        pointRadius="_r"
        pointAltitude={0.015}
        pointLabel={pointLabel}
        onPointClick={p => {
          setSelectedPoint(p);
          if (globeRef.current) {
            globeRef.current.pointOfView(
              { lat: p.lat, lng: toLng(p), altitude: 0.4 },
              1200
            );
            globeRef.current.controls().autoRotate = false;
          }
        }}

        // ── Arcs layer — IDS attack paths ─────────────────────────────────────
        arcsData={arcs}
        arcStartLat="startLat"
        arcStartLng="startLng"
        arcEndLat="endLat"
        arcEndLng="endLng"
        arcColor="color"
        arcAltitude={null}
        arcStroke={0.6}
        arcDashLength={0.4}
        arcDashGap={0.2}
        arcDashAnimateTime={1500}
      />

      {/* 2D Map fallback (Leaflet) */}
      {viewMode === "map" && (
        <MapContainer
          center={[20, 0]}
          zoom={2}
          style={{ width: "100vw", height: "100vh", background: "#000010" }}
          worldCopyJump={true}
        >
          <TileLayer
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
          />
          {filteredFlows.map((f, i) => (
            <CircleMarker
              key={`flow-${i}`}
              center={[f.lat, toLng(f)]}
              radius={Math.log(1 + (f.bytes || 1)) * 2}
              pathOptions={{ color: "#00e5ff", fillColor: "#00e5ff", fillOpacity: 0.4 }}
            />
          ))}
          {filteredIds.map((p, i) => (
            <CircleMarker
              key={`ids-${i}`}
              center={[p.lat, toLng(p)]}
              radius={6}
              pathOptions={{ color: "#e53935", fillColor: "#e53935", fillOpacity: 0.8 }}
            >
              <Popup>
                <div style={{ color: "#000" }}>
                  <b>IDS Alert</b><br/>{p.src_ip} → {p.dest_ip}<br/>{p.signature}
                </div>
              </Popup>
            </CircleMarker>
          ))}
          {filteredDpi.map((p, i) => (
            <CircleMarker
              key={`dpi-${i}`}
              center={[p.lat, toLng(p)]}
              radius={5}
              pathOptions={{ color: "#7c51a1", fillColor: "#7c51a1", fillOpacity: 0.8 }}
            />
          ))}
          {showArcs && filteredIds.slice(-40).map((p, i) => (
            <Polyline
              key={`arc-${i}`}
              positions={[[p.lat, toLng(p)], [HOME_LAT, HOME_LNG]]}
              pathOptions={{ color: "#e53935", weight: 1, opacity: 0.6 }}
            />
          ))}
        </MapContainer>
      )}

      {/* ── Top status bar ────────────────────────────────────────────────── */}
      <div style={{
        position: "fixed", top: 0, left: 0, right: 0, zIndex: 2000,
        height: 46,
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "0 16px",
        background: "rgba(0,8,20,0.78)",
        backdropFilter: "blur(14px)",
        WebkitBackdropFilter: "blur(14px)",
        borderBottom: "1px solid rgba(0,229,255,0.18)",
        boxShadow: "0 0 24px rgba(0,229,255,0.08)",
      }}>
        {/* Left: hamburger + branding */}
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <button
            onClick={() => setSidebarOpen(o => !o)}
            style={{
              background: "none", border: "none", cursor: "pointer",
              color: "#00e5ff", fontSize: 22, lineHeight: 1, padding: 0,
            }}
          >
            ☰
          </button>
          <span style={{
            fontFamily: "'Share Tech Mono', monospace",
            fontSize: 18, letterSpacing: 4,
            color: "#00e5ff", textShadow: "0 0 14px rgba(0,229,255,0.55)",
            userSelect: "none",
          }}>
            NETWATCH
          </span>
          <span style={{
            fontFamily: "'Share Tech Mono', monospace",
            fontSize: 10, letterSpacing: 2,
            color: "rgba(0,229,255,0.38)", marginTop: 1,
          }}>
            // NETWORK INTELLIGENCE
          </span>
          <button
            onClick={() => setViewMode(m => m === "globe" ? "map" : "globe")}
            style={{
              marginLeft: 12, padding: "4px 8px",
              background: "rgba(0,229,255,0.1)", border: "1px solid rgba(0,229,255,0.3)",
              borderRadius: 4, color: "#00e5ff", cursor: "pointer",
              fontFamily: "'Share Tech Mono', monospace", fontSize: 10,
            }}
          >
            {viewMode === "globe" ? "2D MAP" : "3D GLOBE"}
          </button>
        </div>

        {/* Centre: threat level */}
        <div style={{
          display: "flex", alignItems: "center", gap: 8,
          fontFamily: "'Share Tech Mono', monospace", fontSize: 12,
        }}>
          <span style={{ color: "rgba(0,229,255,0.45)", letterSpacing: 1 }}>THREAT:</span>
          <span style={{
            color: THREAT_COLOR[threatLevel],
            fontWeight: 700, letterSpacing: 3,
            textShadow: `0 0 10px ${THREAT_COLOR[threatLevel]}99`,
            ...(threatLevel === "CRITICAL" ? {
              animation: "glow-pulse 1.4s ease-in-out infinite",
            } : {}),
          }}>
            {threatLevel}
          </span>
        </div>

        {/* Right: connection + clock */}
        <div style={{
          display: "flex", alignItems: "center", gap: 16,
          fontFamily: "'Share Tech Mono', monospace", fontSize: 11,
        }}>
          <span style={{
            color: connected ? "#00e676" : "#e53935",
            textShadow: `0 0 8px ${connected ? "#00e67699" : "#e5393599"}`,
          }}>
            {connected ? "● LIVE" : "● OFFLINE"}
          </span>
          <LiveClock />
        </div>
      </div>

      {/* ── Slide-in sidebar ─────────────────────────────────────────────── */}
      <GlobeSidebar
        open={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
        showFlows={showFlows}  setShowFlows={setShowFlows}
        showIds={showIds}      setShowIds={setShowIds}
        showDpi={showDpi}      setShowDpi={setShowDpi}
        showVoip={showVoip}    setShowVoip={setShowVoip}
        showAi={showAi}        setShowAi={setShowAi}
        showArcs={showArcs}    setShowArcs={setShowArcs}
        play={play}            setPlay={setPlay}
        minTs={minTs}          maxTs={maxTs}
        timelinePos={timelinePos} setTimelinePos={setTimelinePos}
        windowSec={windowSec}  setWindowSec={setWindowSec}
        filteredFlows={filteredFlows}
        filteredIds={filteredIds}
        filteredDpi={filteredDpi}
        filteredVoip={filteredVoip}
        filteredAi={filteredAi}
        aiCritical={aiCritical}
        globeRef={globeRef}
        roles={roles}
      />

      {/* ── AI Chat widget ───────────────────────────────────────────────── */}
      <SarahChatWidget darkMode={true} />

      {/* ── Threat detail modal (globe click) ────────────────────────────── */}
      {selectedPoint && (
        <ThreatModal
          point={selectedPoint}
          onClose={() => {
            setSelectedPoint(null);
            if (globeRef.current) globeRef.current.controls().autoRotate = true;
          }}
        />
      )}
    </div>
  );
}

// ─── Live clock component ────────────────────────────────────────────────────
function LiveClock() {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <span style={{ color: "rgba(0,229,255,0.38)" }}>
      {now.toLocaleTimeString([], { hour12: false })}
    </span>
  );
}

// ─── Sidebar ─────────────────────────────────────────────────────────────────
function GlobeSidebar({
  open, onClose,
  showFlows, setShowFlows, showIds, setShowIds,
  showDpi, setShowDpi, showVoip, setShowVoip,
  showAi, setShowAi, showArcs, setShowArcs,
  play, setPlay, minTs, maxTs, timelinePos, setTimelinePos,
  windowSec, setWindowSec,
  filteredFlows, filteredIds, filteredDpi, filteredVoip, filteredAi, aiCritical,
  globeRef, roles,
}) {
  return (
    <div style={{
      position: "fixed", top: 0, left: 0, bottom: 0, zIndex: 1500,
      width: open ? 300 : 0,
      overflow: "hidden",
      transition: "width 0.28s cubic-bezier(.4,1,.6,1)",
    }}>
      {/* Glassmorphism panel — styles come from index.html .glass class */}
      <div className="glass" style={{
        width: 300, height: "100%",
        overflowY: "auto", overflowX: "hidden",
        padding: "58px 16px 24px",
        display: "flex", flexDirection: "column", gap: 14,
        borderRadius: 0,
      }}>
        {/* Close button */}
        <button onClick={onClose} style={{
          position: "sticky", top: -42, alignSelf: "flex-end",
          background: "none", border: "none", cursor: "pointer",
          color: "#00e5ff", fontSize: 18, padding: "2px 6px",
          marginBottom: -30,
        }}>✕</button>

        {/* ── Layer toggles ── */}
        <SectionLabel>// LAYERS</SectionLabel>
        <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
          {[
            [showFlows, setShowFlows, "#00e5ff", "Flows (hex-bin)"],
            [showIds,   setShowIds,   "#e53935", "IDS Alerts"],
            [showDpi,   setShowDpi,   "#7c51a1", "DPI Events"],
            [showVoip,  setShowVoip,  "#00BCD4", "VoIP"],
            [showAi,    setShowAi,    "#FF6F00", "AI Analysis"],
            [showArcs,  setShowArcs,  "#e53935", "Attack Arcs"],
          ].map(([val, setter, col, label]) => (
            <label key={label} style={{
              display: "flex", alignItems: "center", gap: 8, cursor: "pointer",
              padding: "5px 8px", borderRadius: 6,
              border: `1px solid ${val ? col + "44" : "rgba(0,229,255,0.10)"}`,
              background: val ? col + "10" : "transparent",
              transition: "all 0.15s",
            }}>
              <input type="checkbox" checked={val} onChange={e => setter(e.target.checked)}
                style={{ accentColor: col, width: 14, height: 14 }} />
              <span style={{ color: col, fontSize: 12 }}>●</span>
              <span style={{
                color: "#e8e8e8", fontSize: 12,
                fontFamily: "'Share Tech Mono', monospace", letterSpacing: 0.5,
              }}>
                {label}
              </span>
            </label>
          ))}
        </div>

        <Divider />

        {/* ── Stats grid ── */}
        <SectionLabel>// STATS</SectionLabel>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
          {[
            ["FLOWS",   filteredFlows.length, "#00e5ff"],
            ["IDS",     filteredIds.length,   "#e53935"],
            ["DPI",     filteredDpi.length,   "#7c51a1"],
            ["VOIP",    filteredVoip.length,  "#00BCD4"],
            ["AI",      filteredAi.length,    "#FF6F00"],
            ["HI/CRIT", aiCritical,           aiCritical > 0 ? "#e53935" : "rgba(0,229,255,0.25)"],
          ].map(([label, count, col]) => (
            <div key={label} style={{
              background: "rgba(0,229,255,0.03)",
              border: "1px solid rgba(0,229,255,0.1)",
              borderRadius: 6, padding: "6px 10px",
            }}>
              <div style={{
                fontFamily: "'Share Tech Mono', monospace",
                color: "rgba(0,229,255,0.45)", fontSize: 9, letterSpacing: 1.5,
                marginBottom: 2,
              }}>
                {label}
              </div>
              <div style={{
                fontFamily: "'Share Tech Mono', monospace",
                fontWeight: 700, fontSize: 22, color: col,
                textShadow: count > 0 ? `0 0 8px ${col}66` : "none",
              }}>
                {count}
              </div>
            </div>
          ))}
        </div>

        <Divider />

        {/* ── Timeline ── */}
        <SectionLabel>// TIMELINE</SectionLabel>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <button onClick={() => setPlay(p => !p)} style={{
            width: 34, height: 34, borderRadius: 6, flexShrink: 0,
            border: "1px solid rgba(0,229,255,0.25)",
            background: play ? "rgba(0,229,255,0.12)" : "transparent",
            color: "#00e5ff", cursor: "pointer", fontSize: 15,
          }}>
            {play ? "⏸" : "▶"}
          </button>
          <span style={{
            fontFamily: "'Share Tech Mono', monospace",
            fontSize: 10, color: "rgba(0,229,255,0.55)", flex: 1,
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
          }}>
            {fmtTime(timelinePos)}
          </span>
        </div>
        <input type="range" min={minTs} max={maxTs} value={timelinePos}
          onChange={e => { setPlay(false); setTimelinePos(Number(e.target.value)); }}
          style={{ width: "100%", accentColor: "#00e5ff" }} />
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{
            fontFamily: "monospace", fontSize: 11,
            color: "rgba(0,229,255,0.5)", letterSpacing: 1,
          }}>WINDOW:</span>
          <input type="number" min={MIN_WINDOW} max={MAX_WINDOW} value={windowSec}
            onChange={e => setWindowSec(Number(e.target.value))}
            style={{
              width: 64, padding: "3px 7px",
              background: "rgba(0,229,255,0.05)", color: "#e8e8e8",
              border: "1px solid rgba(0,229,255,0.2)", borderRadius: 4,
              fontSize: 12, fontFamily: "monospace",
            }} />
          <span style={{ fontFamily: "monospace", fontSize: 11, color: "rgba(0,229,255,0.4)" }}>sec</span>
        </div>

        {/* Globe reset view */}
        <button onClick={() => {
          if (globeRef.current) {
            globeRef.current.pointOfView({ lat: 20, lng: 0, altitude: 2.5 }, 1200);
          }
        }} style={{
          padding: "7px 0",
          border: "1px solid rgba(0,229,255,0.22)",
          borderRadius: 6, background: "transparent",
          color: "#00e5ff", cursor: "pointer",
          fontFamily: "'Share Tech Mono', monospace",
          fontSize: 11, letterSpacing: 2,
          transition: "background 0.15s",
        }}>
          ⟳ RESET VIEW
        </button>

        <Divider />

        {/* ── Packet Launcher ── */}
        <SectionLabel style={{ color: "#e53935" }}>// PACKET LAUNCHER</SectionLabel>
        <div style={{
          fontFamily: "monospace", fontSize: 10,
          color: "rgba(229,57,53,0.65)", marginTop: -8, letterSpacing: 0.5,
        }}>
          LAB USE ONLY — ENSURE AUTHORISATION
        </div>
        <PacketLauncherForm />

        <Divider />

        {/* ── IP Trace ── */}
        <SectionLabel style={{ color: "#00e676" }}>// IP TRACE</SectionLabel>
        <IpTraceForm />

        <Divider />

        {/* ── Sub-agent roles ── */}
        <SectionLabel>// AI SUB-AGENTS</SectionLabel>
        {roles.length === 0 ? (
          <div style={{ fontFamily: "monospace", fontSize: 10, color: "rgba(0,229,255,0.35)" }}>
            Connecting to ai_analyst…
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {roles.map(role => {
              const meta  = ROLE_META[role.name] || { icon: "🤖", color: "#00e5ff" };
              const count = role.stats?.analyzed ?? 0;
              const errs  = role.stats?.errors   ?? 0;
              return (
                <div key={role.name} style={{
                  display: "flex", alignItems: "center", gap: 8,
                  padding: "4px 8px", borderRadius: 5,
                  background: "rgba(0,229,255,0.03)",
                  border: `1px solid ${meta.color}22`,
                }}>
                  <span style={{ fontSize: 14 }}>{meta.icon}</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{
                      fontFamily: "'Share Tech Mono', monospace",
                      fontSize: 10, color: meta.color, letterSpacing: 0.5,
                      textTransform: "uppercase", overflow: "hidden",
                      textOverflow: "ellipsis", whiteSpace: "nowrap",
                    }}>
                      {role.name.replace(/_/g, " ")}
                    </div>
                    <div style={{
                      fontFamily: "monospace", fontSize: 9,
                      color: "rgba(0,229,255,0.35)",
                    }}>
                      {role.mode} · {role.topics.join(", ").slice(0, 28)}
                    </div>
                  </div>
                  <div style={{ textAlign: "right", flexShrink: 0 }}>
                    <div style={{
                      fontFamily: "'Share Tech Mono', monospace",
                      fontSize: 13, fontWeight: 700,
                      color: count > 0 ? meta.color : "rgba(0,229,255,0.25)",
                      textShadow: count > 0 ? `0 0 6px ${meta.color}88` : "none",
                    }}>
                      {count}
                    </div>
                    {errs > 0 && (
                      <div style={{ fontSize: 9, color: "#e5393588" }}>{errs}err</div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        <Divider />

        {/* ── Legend ── */}
        <SectionLabel>// LEGEND</SectionLabel>
        <div style={{
          display: "flex", flexWrap: "wrap", gap: "4px 12px",
          fontFamily: "monospace", fontSize: 11,
        }}>
          {[
            ["#00e5ff", "flows"],
            ["#e53935", "IDS"],
            ["#7c51a1", "DPI"],
            ["#00BCD4", "VoIP"],
            ["#FF6F00", "AI-med"],
            ["#e53935", "AI-high"],
            ["#7b0000", "AI-crit"],
          ].map(([col, label]) => (
            <span key={label} style={{ color: "rgba(0,229,255,0.6)" }}>
              <span style={{ color: col }}>●</span> {label}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Small reusable components ───────────────────────────────────────────────
function SectionLabel({ children, style }) {
  return (
    <div style={{
      fontFamily: "'Share Tech Mono', monospace",
      color: "#00e5ff", fontSize: 11, letterSpacing: 2,
      opacity: 0.8,
      ...style,
    }}>
      {children}
    </div>
  );
}

function Divider() {
  return <hr style={{ border: "none", borderTop: "1px solid rgba(0,229,255,0.1)", margin: "2px 0" }} />;
}

// ─── Packet Launcher Form ────────────────────────────────────────────────────
function PacketLauncherForm() {
  const [ip,       setIp]       = useState("");
  const [protocol, setProtocol] = useState("ICMP");
  const [size,     setSize]     = useState(64);
  const [rate,     setRate]     = useState(1);
  const [count,    setCount]    = useState(1);
  const [result,   setResult]   = useState("");
  const [loading,  setLoading]  = useState(false);

  async function handleLaunch(e) {
    e.preventDefault();
    setResult(""); setLoading(true);
    try {
      const res = await fetch("/launch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, protocol, size: +size, rate: +rate, count: +count }),
      });
      const data = await res.json();
      setResult(res.ok ? (data.detail || "Launched.") : (data.error || "Error"));
    } catch {
      setResult("Network error.");
    } finally { setLoading(false); }
  }

  const inp = {
    background: "rgba(0,229,255,0.04)", color: "#e8e8e8",
    border: "1px solid rgba(0,229,255,0.2)", borderRadius: 4,
    padding: "4px 7px", fontSize: 12, fontFamily: "monospace",
    outline: "none",
  };

  const isErr = result.toLowerCase().includes("error") || result.toLowerCase().includes("network");

  return (
    <form onSubmit={handleLaunch} style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      <div style={{ display: "flex", gap: 5 }}>
        <input type="text" value={ip} onChange={e => setIp(e.target.value)}
          placeholder="Target IP" required style={{ ...inp, flex: 1 }} />
        <select value={protocol} onChange={e => setProtocol(e.target.value)}
          style={{ ...inp, width: 66 }}>
          <option>ICMP</option><option>TCP</option><option>UDP</option>
        </select>
      </div>
      <div style={{ display: "flex", gap: 5 }}>
        <input type="number" value={size}  onChange={e => setSize(e.target.value)}
          placeholder="Bytes" min={1} max={1500} style={{ ...inp, flex: 1 }} />
        <input type="number" value={rate}  onChange={e => setRate(e.target.value)}
          placeholder="Rate"  min={1} max={100}  style={{ ...inp, flex: 1 }} />
        <input type="number" value={count} onChange={e => setCount(e.target.value)}
          placeholder="Cnt"   min={1} max={1000} style={{ ...inp, flex: 1 }} />
      </div>
      <button type="submit" disabled={loading} style={{
        background: loading
          ? "rgba(229,57,53,0.25)"
          : "rgba(229,57,53,0.75)",
        color: "#fff",
        border: "1px solid rgba(229,57,53,0.5)",
        borderRadius: 5, padding: "7px 0",
        cursor: loading ? "wait" : "pointer",
        fontFamily: "'Share Tech Mono', monospace",
        fontSize: 11, letterSpacing: 2,
        transition: "background 0.2s",
      }}>
        {loading ? "LAUNCHING…" : "LAUNCH"}
      </button>
      {result && (
        <div style={{
          fontFamily: "monospace", fontSize: 11,
          padding: "5px 8px", borderRadius: 4,
          background: isErr ? "rgba(229,57,53,0.12)" : "rgba(0,230,118,0.1)",
          color:      isErr ? "#e53935"               : "#00e676",
          border:    `1px solid ${isErr ? "rgba(229,57,53,0.3)" : "rgba(0,230,118,0.3)"}`,
        }}>
          {result}
        </div>
      )}
    </form>
  );
}

// ─── IP Trace Form ────────────────────────────────────────────────────────────
function IpTraceForm() {
  const [ip,     setIp]     = useState("");
  const [maxTtl, setMaxTtl] = useState(30);
  const [hops,   setHops]   = useState(null);
  const [error,  setError]  = useState("");
  const [loading, setLoading] = useState(false);

  async function handleTrace(e) {
    e.preventDefault();
    setHops(null); setError(""); setLoading(true);
    try {
      const res = await fetch("/trace", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, max_ttl: +maxTtl, timeout: 1 }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Error");
      } else {
        setHops(data.hops || []);
      }
    } catch {
      setError("Network error.");
    } finally { setLoading(false); }
  }

  const inp = {
    background: "rgba(0,229,255,0.04)", color: "#e8e8e8",
    border: "1px solid rgba(0,229,255,0.2)", borderRadius: 4,
    padding: "4px 7px", fontSize: 12, fontFamily: "monospace",
    outline: "none",
  };

  return (
    <form onSubmit={handleTrace} style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      <div style={{ display: "flex", gap: 5 }}>
        <input type="text" value={ip} onChange={e => setIp(e.target.value)}
          placeholder="Target IP" required style={{ ...inp, flex: 1 }} />
        <input type="number" value={maxTtl} onChange={e => setMaxTtl(e.target.value)}
          placeholder="Max TTL" min={1} max={64} style={{ ...inp, width: 66 }} />
      </div>
      <button type="submit" disabled={loading} style={{
        background: loading
          ? "rgba(0,230,118,0.15)"
          : "rgba(0,230,118,0.5)",
        color: "#fff",
        border: "1px solid rgba(0,230,118,0.4)",
        borderRadius: 5, padding: "7px 0",
        cursor: loading ? "wait" : "pointer",
        fontFamily: "'Share Tech Mono', monospace",
        fontSize: 11, letterSpacing: 2,
        transition: "background 0.2s",
      }}>
        {loading ? "TRACING…" : "TRACE"}
      </button>
      {error && (
        <div style={{
          fontFamily: "monospace", fontSize: 11,
          padding: "5px 8px", borderRadius: 4,
          background: "rgba(229,57,53,0.12)", color: "#e53935",
          border: "1px solid rgba(229,57,53,0.3)",
        }}>
          {error}
        </div>
      )}
      {hops && hops.length > 0 && (
        <div style={{
          fontFamily: "monospace", fontSize: 11,
          background: "rgba(0,230,118,0.05)",
          border: "1px solid rgba(0,230,118,0.2)",
          borderRadius: 4, padding: "6px 8px",
          maxHeight: 180, overflowY: "auto",
          display: "flex", flexDirection: "column", gap: 2,
        }}>
          {hops.map(h => (
            <div key={h.hop} style={{ display: "flex", gap: 8, color: h.ip === "*" ? "rgba(0,230,118,0.35)" : "#00e676" }}>
              <span style={{ width: 20, textAlign: "right", flexShrink: 0 }}>{h.hop}</span>
              <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {h.ip}
              </span>
              <span style={{ flexShrink: 0, color: "rgba(0,230,118,0.6)" }}>
                {h.rtt_ms !== null ? `${h.rtt_ms}ms` : "* * *"}
              </span>
            </div>
          ))}
        </div>
      )}
    </form>
  );
}

// ─── Threat Detail Modal (click-to-zoom + Street View) ───────────────────────
function ThreatModal({ point, onClose }) {
  const lat = point.lat;
  const lng = toLng(point);
  const col   = point._col || "#00e5ff";
  const topic = (point.topic || point.event_type || "EVENT").toUpperCase();

  // Google Maps satellite embed — no API key required for the classic embed URL
  const mapsEmbedUrl =
    `https://maps.google.com/maps?q=${lat},${lng}&z=16&t=k&output=embed`;

  // Google Maps street-level URL that opens Street View mode
  const streetViewUrl =
    `https://www.google.com/maps/@${lat},${lng},3a,75y,0h,90t/data=!3m1!1e1`;

  return (
    <div
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}
      style={{
        position: "fixed", inset: 0, zIndex: 3000,
        display: "flex", alignItems: "center", justifyContent: "center",
        background: "rgba(0,0,0,0.65)",
        backdropFilter: "blur(5px)",
      }}
    >
      <div style={{
        background: "rgba(0,8,20,0.97)",
        border: `1px solid ${col}44`,
        borderRadius: 10,
        width: 540, maxWidth: "95vw",
        maxHeight: "88vh",
        display: "flex", flexDirection: "column",
        boxShadow: `0 0 48px ${col}22, 0 0 120px rgba(0,0,0,0.8)`,
        overflow: "hidden",
      }}>

        {/* ── Header ── */}
        <div style={{
          display: "flex", alignItems: "center",
          justifyContent: "space-between",
          padding: "12px 16px",
          borderBottom: `1px solid ${col}22`,
          flexShrink: 0,
        }}>
          <span style={{
            fontFamily: "'Share Tech Mono', monospace",
            color: col, fontSize: 12, letterSpacing: 2,
            textShadow: `0 0 8px ${col}66`,
          }}>
            ⚠ {topic} · {point.src_ip || `${lat.toFixed(3)},${lng.toFixed(3)}`}
          </span>
          <button onClick={onClose} style={{
            background: "none", border: "none",
            color: "rgba(255,255,255,0.45)", cursor: "pointer",
            fontSize: 18, padding: "0 4px", lineHeight: 1,
          }}>✕</button>
        </div>

        {/* ── Intel fields ── */}
        <div style={{
          padding: "10px 16px",
          fontFamily: "monospace", fontSize: 11, color: "#ccc",
          display: "flex", flexWrap: "wrap", gap: "3px 18px",
          flexShrink: 0,
          borderBottom: `1px solid ${col}11`,
        }}>
          {point.src_ip     && <span><b style={{ color: col }}>src </b>{point.src_ip}{point.src_port ? `:${point.src_port}` : ""}</span>}
          {point.dst_ip     && <span><b style={{ color: col }}>dst </b>{point.dst_ip}</span>}
          {point.signature  && <span style={{ width: "100%" }}><b style={{ color: col }}>sig </b>{point.signature}</span>}
          {point.severity !== undefined && <span><b style={{ color: col }}>sev </b>{point.severity}</span>}
          {point.country    && <span><b style={{ color: col }}>cc  </b>{point.country}</span>}
          {point.summary    && <span style={{ width: "100%" }}><b style={{ color: col }}>ai  </b>{point.summary}</span>}
          <span><b style={{ color: col }}>geo </b>{lat.toFixed(4)}, {lng.toFixed(4)}</span>
          {point._ts        && <span style={{ opacity: 0.45 }}>{fmtTime(point._ts)}</span>}
        </div>

        {/* ── Embedded satellite map ── */}
        <div style={{ flex: 1, minHeight: 260, position: "relative", background: "#111" }}>
          <iframe
            title="threat-location-map"
            src={mapsEmbedUrl}
            width="100%"
            height="100%"
            style={{ border: "none", display: "block" }}
            loading="lazy"
            referrerPolicy="no-referrer-when-downgrade"
          />
        </div>

        {/* ── Footer actions ── */}
        <div style={{
          display: "flex", gap: 8, padding: "10px 16px",
          borderTop: `1px solid ${col}22`,
          flexShrink: 0,
        }}>
          <a
            href={streetViewUrl}
            target="_blank" rel="noreferrer"
            style={{
              flex: 1, textAlign: "center", padding: "7px 0",
              background: "rgba(66,133,244,0.15)",
              border: "1px solid rgba(66,133,244,0.4)",
              borderRadius: 5, color: "#4285f4",
              fontFamily: "'Share Tech Mono', monospace",
              fontSize: 11, letterSpacing: 1, textDecoration: "none",
            }}
          >
            STREET VIEW ↗
          </a>
          {point.src_ip && (
            <a
              href={assetLink(point.src_ip)}
              target="_blank" rel="noreferrer"
              style={{
                flex: 1, textAlign: "center", padding: "7px 0",
                background: "rgba(0,229,255,0.08)",
                border: "1px solid rgba(0,229,255,0.3)",
                borderRadius: 5, color: "#00e5ff",
                fontFamily: "'Share Tech Mono', monospace",
                fontSize: 11, letterSpacing: 1, textDecoration: "none",
              }}
            >
              NEO4J ↗
            </a>
          )}
        </div>
      </div>
    </div>
  );
}
