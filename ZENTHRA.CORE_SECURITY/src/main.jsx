// =============================================================
// 💠 main.jsx — Punto de entrada de ZENTHRA.CORE_SECURITY
// =============================================================
// - Inicializa la aplicación React (Vite).
// - Activa TailwindCSS globalmente.
// - Integra el sistema de notificaciones ZENTHRA.
// =============================================================

import React, { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import App from "./App.jsx";
import "./index.css";

// 🧩 Sistema de notificaciones global (ZENTHRA)
import { NotificationProvider } from "@/components/NotificationProvider.jsx";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      gcTime: 5 * 60_000,
      retry: 1,
      refetchOnWindowFocus: false,
    },
    mutations: {
      retry: 0,
    },
  },
});

createRoot(document.getElementById("root")).render(
  <StrictMode>
    {/* 🧱 Proveedor global de notificaciones */}
    <QueryClientProvider client={queryClient}>
      <NotificationProvider>
        <App />
      </NotificationProvider>
    </QueryClientProvider>
  </StrictMode>
);
