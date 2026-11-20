import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The API has no CORS and runs on :8000. In dev we proxy /api/* to it so the
// browser talks same-origin to Vite on :5173 — no change to the API surface.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ""),
      },
    },
  },
});
