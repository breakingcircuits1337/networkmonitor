import React, { useEffect, useRef, useState } from "react";
import { MapContainer, TileLayer, CircleMarker, useMap } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import HeatMapLayer from "./HeatMapLayer.jsx";

// Use the backend service name for compose
const EVENT_URL = "http://geoip_enricher:5000/events";

export default function App() {
  const [points, setPoints] = useState([]);

  useEffect(() => {
    const ev = new window.EventSource(EVENT_URL);
    ev.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        setPoints((prev) => {
          const next = [...prev, data];
          return next.length > 2000 ? next.slice(next.length - 2000) : next;
        });
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
        <HeatMapLayer points={points} />
        {points.slice(-200).map((p, idx) =>
          p.lat && p.lon ? (
            <CircleMarker
              key={idx}
              center={[p.lat, p.lon]}
              radius={4}
              fillOpacity={0.7}
              color="#34c9eb"
              stroke={false}
            >
            </CircleMarker>
          ) : null
        )}
      </MapContainer>
      <div style={{ position: "absolute", top: 10, left: 10, background: "rgba(255,255,255,0.8)", padding: "6px 10px", borderRadius: 8 }}>
        <h3 style={{ margin: 0 }}>Network Geo Heatmap</h3>
        <small>Live flow sources (max 2000 pts) | <b>{points.length}</b> events</small>
      </div>
    </div>
  );
}