import { useEffect } from "react";
import { useMap } from "react-leaflet";
import L from "leaflet";
import "leaflet.markercluster";

function makeBlueIcon() {
  return L.divIcon({
    html: '<div style="background:#34c9eb;width:10px;height:10px;border-radius:50%;border:2px solid white;"></div>',
    className: "",
    iconSize: [14, 14]
  });
}

export default function ClusterLayer({ points, show }) {
  const map = useMap();

  useEffect(() => {
    if (!map || !show) return;
    const clusterGroup = L.markerClusterGroup();
    points.forEach((p) => {
      if (p.lat && p.lon) {
        const marker = L.marker([p.lat, p.lon], {
          icon: makeBlueIcon(),
          keyboard: false,
          interactive: false
        });
        clusterGroup.addLayer(marker);
      }
    });
    map.addLayer(clusterGroup);

    // Store ref for cleanup
    map._flowClusterLayer = clusterGroup;
    return () => {
      if (map._flowClusterLayer) {
        map.removeLayer(map._flowClusterLayer);
        map._flowClusterLayer = null;
      }
    };
  }, [map, points, show]);

  return null;
}