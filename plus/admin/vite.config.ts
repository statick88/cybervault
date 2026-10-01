import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 3002,
    proxy: {
      "/api": {
        // The Vite dev server runs on the host, so it proxies to the host
        // port Compose publishes for Plus (3003) — not the container port.
        target: "http://localhost:3003",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});