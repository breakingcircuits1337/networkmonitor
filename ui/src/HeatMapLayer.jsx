import { useEffect } from "react";
import { useMap } from "react-leaflet";
import "leaflet.heat";

export default function HeatMapLayer({ points }) {
  const map = useMap();
  useEffect(() => {
    if (!map || !window.L.heatLayer) return;
    // Remove existing
    if (map._heatLayer) {
      map.removeLayer(map._heatLayer);
    }
    // Only plot points with coordinates
    const heatPoints = points
      .filter((p) => p.lat !== undefined && p.lon !== undefined)
      .map((p) => [p.lat, p.lon, Math.max(0.2, Math.log(1 + (p.bytes || 1))/10)]);
    if (heatPoints.length === 0) return;
    const heat = window.L.heatLayer(heatPoints, {
      radius: 18,
      blur: 18,
      maxZoom: 6,
      gradient: { 0.2: "#08f", 0.4: "#0ff", 0.7: "#f3f", 1.0: "#f00" }
    }).addTo(map);
    map._heatLayer = heat;
    return () => {
      if (map._heatLayer) map.removeLayer(map._heatLayer);
    };
  }, [points, map]);
  return null;
}