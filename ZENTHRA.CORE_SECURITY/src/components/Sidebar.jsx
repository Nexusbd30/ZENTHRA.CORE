// =============================================================
// 🧭 SIDEBAR — ZENTHRA.CORE_SECURITY (v3.6 Enterprise Revised)
// =============================================================
// - Navegación lateral con rutas reales del AppRouter
// - Alertas (Prometheus) separadas de Amenazas (Threats)
// - Integrado con AuthContext + NotificationProvider
// - Estilos activos coherentes con el resto del panel
// =============================================================

import { NavLink, useNavigate } from "react-router-dom";
import {
  LayoutDashboard,
  Users as UsersIcon,
  Bell,
  ShieldAlert,
  ShieldCheck,
  HardDrive,
  Activity,
  Stethoscope,
  LogOut,
} from "lucide-react";
import logo from "@/assets/logos/zenthra-logo.png";
import { useAuth } from "@/hooks/useAuth";
import { useNotification } from "@/hooks/useNotification";

export default function Sidebar() {
  const navigate = useNavigate();
  const { logout } = useAuth();
  const { notify } = useNotification();

  const activeCls =
    "bg-[#2d3449] text-[#adc6ff] border-l-4 border-[#adc6ff]";
  const baseCls =
    "text-[#424754] hover:bg-[#171f33] hover:text-[#adc6ff]";

  const itemCls = (isActive) =>
    `flex items-center gap-3 px-4 py-3 font-medium text-sm tracking-tight transition-all duration-300 ${
      isActive ? activeCls : baseCls
    }`;

  const handleLogout = () => {
    logout();
    notify("warning", "🔒 Sesión cerrada correctamente");
    navigate("/login", { replace: true });
  };

  return (
    <aside className="fixed left-0 top-0 h-screen w-64 bg-[#131b2e] border-r border-[#424754]/20 shadow-[24px_0_48px_-12px_rgba(6,14,32,0.5)] flex flex-col z-40">
      <div className="px-6 mb-8 mt-6 flex items-center gap-3">
        <div className="w-10 h-10 bg-primary/10 flex items-center justify-center rounded-sm">
          <img
            src={logo}
            alt="ZENTHRA Logo"
            className="w-8 h-8 object-contain"
          />
        </div>
        <div>
          <div className="font-['Space_Grotesk'] font-black text-[#adc6ff] leading-none uppercase">
            COMMAND
          </div>
          <div className="text-[10px] text-[#424754] uppercase tracking-widest">
            Level 4 Clear
          </div>
        </div>
      </div>

      <nav className="flex-1 space-y-1 px-2">
        <NavLink to="/dashboard" className={({ isActive }) => itemCls(isActive)}>
          <LayoutDashboard size={18} /> Dashboard
        </NavLink>
        <NavLink to="/dashboard/alerts" className={({ isActive }) => itemCls(isActive)}>
          <Bell size={18} /> Alertas
        </NavLink>
        <NavLink to="/dashboard/threats" className={({ isActive }) => itemCls(isActive)}>
          <ShieldAlert size={18} /> Amenazas
        </NavLink>
        <NavLink to="/dashboard/monitoring" className={({ isActive }) => itemCls(isActive)}>
          <Activity size={18} /> Monitoreo
        </NavLink>
        <NavLink to="/dashboard/diagnostics" className={({ isActive }) => itemCls(isActive)}>
          <Stethoscope size={18} /> Diagnostico
        </NavLink>
        <NavLink to="/dashboard/datacenter" className={({ isActive }) => itemCls(isActive)}>
          <HardDrive size={18} /> Infraestructura
        </NavLink>
        <NavLink to="/dashboard/users" className={({ isActive }) => itemCls(isActive)}>
          <UsersIcon size={18} /> Usuarios
        </NavLink>
        <NavLink to="/dashboard/security" className={({ isActive }) => itemCls(isActive)}>
          <ShieldCheck size={18} /> Seguridad
        </NavLink>
      </nav>

      <div className="mt-auto border-t border-[#424754]/20 px-4 py-4">
        <button
          onClick={handleLogout}
          className="flex items-center gap-3 w-full text-left text-[#424754] hover:text-[#adc6ff] hover:bg-[#171f33] px-4 py-3 transition-all rounded-sm"
        >
          <LogOut size={18} /> Cerrar sesión
        </button>
      </div>
    </aside>
  );
}
