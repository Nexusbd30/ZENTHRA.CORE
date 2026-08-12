// =============================================================
// âš™ï¸ vite.config.js â€” ConfiguraciÃ³n principal de VAELQORIX.XDR_COMMAND
// =============================================================
// - Plugin React
// - Alias "@/..."
// - Code splitting de vendors para reducir el chunk principal
// =============================================================

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [react()],

  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },

  server: {
    host: "0.0.0.0",
    port: 5173,
    strictPort: true,
    open: false,
  },

  build: {
    chunkSizeWarningLimit: 1500,
    rollupOptions: {
      output: {
        manualChunks: {
          react: ["react", "react-dom", "react-router-dom"],
          ui: ["framer-motion", "lucide-react"],
          charts: ["recharts"],
          axios: ["axios"],
        },
      },
    },
  },
});
