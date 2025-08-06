import React, { useEffect, useRef, useState } from "react";
import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import HeatMapLayer from "./HeatMapLayer.jsx";

// Use the backend service name for compose
const EVENT_URL = "http://geoip_enricher:5000/events";

export default function App() {
  // three buckets: flows, idsAlerts, dpiEvents
  const [flows, setFlows] = useState([]);
  const [idsAlerts, setIdsAlerts] = useState([]);
  const [dpiEvents, setDpiEvents] = useState([]);

  useEffect(() => {
    const ev = new window.EventSource(EVENT_URL);
    ev.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (!data.event_type) {
          // fallback: treat as flow
          setFlows((prev) => {
            const next = [...prev, data];
            return next.length > 2000 ? next.slice(next.length - 2000) : next;
          });
        } else if (data.event_type === "flow") {
          setFlows((prev) => {
            const next = [...prev, data];
            return next.length > 2000 ? next.slice(next.length - 2000) : next;
          });
        } else if (data.event_type === "ids_alert") {
          setIdsAlerts((prev) => {
            const next = [...prev, data];
            return next.length > 500 ? next.slice(next.length - 500) : next;
          });
        } else if (data.event_type === "dpi_event") {
          setDpiEvents((prev) => {
            const next = [...prev, data];
            return next.length > 500 ? next.slice(next.length - 500) : next;
          });
        }
      } catch {}
    };
    return () => ev.close();
  }, []);

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
        <HeatMapLayer points={flows} />
        {/* Flows - blue circle */}
        {flows.slice(-200).map((p, idx) =>
          p.lat && p.lon ? (
            <CircleMarker
              key={`flow-${idx}`}
              center={[p.lat, p.lon]}
              radius={4}
              fillOpacity={0.7}
              color="#34c9eb"
              stroke={false}
            />
          ) : null
        )}
        {/* IDS Alerts - red circle */}
        {idsAlerts.map((p, idx) =>
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
                </div>
              </Popup>
            </CircleMarker>
          ) : null
        )}
        {/* DPI Events - purple circle */}
        {dpiEvents.map((p, idx) =>
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
                </div>
              </Popup>
            </CircleMarker>
          ) : null
        )}
      </MapContainer>
      <div style={{ position: "absolute", top: 10, left: 10, background: "rgba(255,255,255,0.85)", padding: "8px 12px", borderRadius: 8, minWidth: 200 }}>
        <h3 style={{ margin: 0 }}>Network Geo Heatmap</h3>
        <small>
          <span style={{ color: "#34c9eb" }}>●</span> Flows ({flows.length})&nbsp;&nbsp;
          <span style={{ color: "#e53935" }}>●</span> IDS Alerts ({idsAlerts.length})&nbsp;&nbsp;
          <span style={{ color: "#7c51a1" }}>●</span> DPI Events ({dpiEvents.length})
        </small>
        <div style={{marginTop:4, fontSize:12}}>
          Blue = flow, Red = IDS alert, Purple = DPI event
        </div>
      </div>
    </div>
  );
}