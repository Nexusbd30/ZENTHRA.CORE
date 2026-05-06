// =============================================================
// SISTEMA DE RUTAS PRINCIPAL — ZENTHRA.CORE_SECURITY (v3.7 Clean)
// =============================================================

import { Routes, Route, Navigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import Loader from "@/components/Loader";

// Paginas principales
import DashboardLayout from "@/layouts/DashboardLayout";
import Dashboard from "@/pages/Dashboard";
import Login from "@/pages/Login";
import Register from "@/pages/Register";
import Home from "@/pages/Home";

// Modulos internos
import Users from "@/pages/Users";
import AIPage from "@/modules/ai/AIPage";
import ThreatsPage from "@/modules/threats/ThreatsPage";
import DataCenterPage from "@/modules/datacenter/DataCenterPage";
import MonitoringPage from "@/modules/monitoring/MonitoringPage";
import DiagnosticsPage from "@/modules/diagnostics/DiagnosticsPage";
import SecurityPage from "@/modules/security/SecurityPage";
import AlertsPage from "@/modules/alerts/AlertsPage"; // NUEVO
import LogsPage from "@/modules/logs/LogsPage";

// Proteccion de rutas
import PrivateRoute from "@/modules/auth/PrivateRoute";

export default function AppRouter() {
  const { user, loading } = useAuth();

  if (loading) return <Loader />;

  return (
    <Routes>
      {/* Publicas */}
      <Route path="/" element={<Home />} />
      <Route
        path="/login"
        element={user ? <Navigate to="/dashboard" replace /> : <Login />}
      />
      <Route path="/register" element={<Register />} />

      {/* Privadas */}
      <Route
        path="/dashboard/*"
        element={
          <PrivateRoute>
            <DashboardLayout />
          </PrivateRoute>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="users" element={<Users />} />
        <Route path="ai" element={<AIPage />} />
        <Route path="threats" element={<ThreatsPage />} />
        <Route path="datacenter" element={<DataCenterPage />} />
        <Route path="logs" element={<LogsPage />} />
        <Route path="monitoring" element={<MonitoringPage />} />
        <Route path="diagnostics" element={<DiagnosticsPage />} />
        <Route path="security" element={<SecurityPage />} />
        {/* Pagina dedicada de alertas */}
        <Route path="alerts" element={<AlertsPage />} />
      </Route>

      {/* Fallback */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
