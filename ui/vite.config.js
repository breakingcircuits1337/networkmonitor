import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  optimizeDeps: {
    include: ["react-globe.gl"],
  },
  server: {
    port: 5173,
    proxy: {
      "/events":  "http://localhost:5000",
      "/api":     "http://localhost:5000",
      "/health":  "http://localhost:5000",
      "/analyst": "http://localhost:5001",
      "/launch":  "http://localhost:7000",
    },
  },
});
