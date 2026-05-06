// =============================================================
// 💠 main.jsx — Punto de entrada de ZENTHRA.CORE_SECURITY
// =============================================================
// - Inicializa la aplicación React (Vite).
// - Activa TailwindCSS globalmente.
// - Integra el sistema de notificaciones ZENTHRA.
// =============================================================

import React, { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import "./index.css";

// 🧩 Sistema de notificaciones global (ZENTHRA)
import { NotificationProvider } from "@/components/NotificationProvider.jsx";

createRoot(document.getElementById("root")).render(
  <StrictMode>
    {/* 🧱 Proveedor global de notificaciones */}
    <NotificationProvider>
      <App />
    </NotificationProvider>
  </StrictMode>
);
