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
    // Host-port allocation (Compose defaults): 3001 swagger, 3002 adminer
    // (profile `dev`), 3003 plus, 3010 api, with 3000 the core default —
    // 3002 collided with adminer, so the admin console takes 3004, the first
    // free port in the stack's 30xx block.
    port: 3004,
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