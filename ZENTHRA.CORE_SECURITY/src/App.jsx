// =============================================================
// 💠 App — ZENTHRA.CORE_SECURITY (v3.7 Enterprise Stable)
// =============================================================
// Punto de entrada principal del frontend ZENTHRA.
// Integra:
//  - React Router (BrowserRouter)
//  - AuthProvider (gestión JWT global)
//  - AppRouter (gestor de rutas públicas y privadas)
// =============================================================

import { BrowserRouter as Router } from "react-router-dom";
import AppRouter from "@/routes/AppRouter";
import { AuthProvider } from "@/context/AuthContext";

export default function App() {
  return (
    // 🔐 Contexto global de autenticación
    <AuthProvider>
      {/* 🌍 Sistema principal de rutas */}
      <Router>
        <AppRouter />
      </Router>
    </AuthProvider>
  );
}