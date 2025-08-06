import { useEffect } from "react";
import { GeoJSON, useMap } from "react-leaflet";
import countries from "./assets/countries.json";

function getColor(count) {
  if (count > 100) return "#d73027";
  if (count > 30) return "#fc8d59";
  if (count > 10) return "#fee08b";
  if (count > 0) return "#d9ef8b";
  return "#eee";
}

export default function ChoroplethLayer({ countryCounts }) {
  const map = useMap();

  function style(feature) {
    const iso = feature.properties.iso_a2;
    const count = countryCounts[iso] || 0;
    return {
      fillColor: getColor(count),
      weight: 1,
      opacity: 1,
      color: "#888",
      fillOpacity: count > 0 ? 0.5 : 0.15
    };
  }

  return (
    <GeoJSON
      key={Object.keys(countryCounts).join(",")}
      data={countries}
      style={style}
      interactive={false}
    />
  );
}