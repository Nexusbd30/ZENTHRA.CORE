// =============================================================
// ⚙️ vite.config.js — Configuración principal de ZENTHRA.CORE_SECURITY
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
    port: 5173,
    open: true,
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
