import { createElement, Suspense } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import {
  Activity,
  Bell,
  Bot,
  DatabaseZap,
  FileClock,
  Gauge,
  LayoutDashboard,
  LogOut,
  Menu,
  Network,
  Search,
  Settings,
  ShieldCheck,
  ShieldAlert,
  Stethoscope,
  Users,
  X,
} from "lucide-react";
import { useState } from "react";

import Loader from "@/components/Loader";
import { useAuth } from "@/hooks/useAuth";
import { useNotification } from "@/hooks/useNotification";
import logo from "@/assets/logos/vaelqorix-logo.jpeg";

const navSections = [
  {
    title: "Operaciones",
    items: [
      { to: "/dashboard", label: "Resumen", icon: LayoutDashboard, end: true },
      { to: "/dashboard/alerts", label: "Alertas", icon: Bell },
      { to: "/dashboard/threats", label: "Incidentes", icon: ShieldAlert },
      { to: "/dashboard/secops", label: "SecOps", icon: Settings },
      { to: "/dashboard/monitoring", label: "Monitoreo", icon: Activity },
    ],
  },
  {
    title: "Plataforma",
    items: [
      { to: "/dashboard/diagnostics", label: "Diagnostico", icon: Stethoscope },
      { to: "/dashboard/datacenter", label: "Infraestructura", icon: Network },
      { to: "/dashboard/logs", label: "Logs", icon: FileClock },
      { to: "/dashboard/ai", label: "AI Security", icon: Bot },
    ],
  },
  {
    title: "Gobierno",
    items: [
      { to: "/dashboard/users", label: "Usuarios", icon: Users },
      { to: "/dashboard/security", label: "Seguridad", icon: ShieldCheck },
    ],
  },
];

const routeTitles = {
  "/dashboard": {
    title: "Centro de mando",
    eyebrow: "Vision general",
    description: "Estado operativo de alertas, infraestructura y actividad de seguridad.",
  },
  "/dashboard/alerts": {
    title: "Alertas",
    eyebrow: "Operacion SOC",
    description: "Senales activas, severidad y actividad reciente del backend.",
  },
  "/dashboard/threats": {
    title: "Incidentes",
    eyebrow: "Threat response",
    description: "Registro, seguimiento y detalle de amenazas detectadas.",
  },
  "/dashboard/monitoring": {
    title: "Monitoreo",
    eyebrow: "Infraestructura",
    description: "Metricas de servicios, recursos y disponibilidad.",
  },
  "/dashboard/secops": {
    title: "SecOps",
    eyebrow: "Gobierno operativo",
    description: "Readiness, providers, tenant policies, eventos SOC y preflight de acciones.",
  },
  "/dashboard/diagnostics": {
    title: "Diagnostico",
    eyebrow: "Health checks",
    description: "Validaciones de backend, conectividad y estado interno.",
  },
  "/dashboard/datacenter": {
    title: "Infraestructura",
    eyebrow: "Network map",
    description: "Vista de nodos, servicios y superficie tecnica.",
  },
  "/dashboard/logs": {
    title: "Logs",
    eyebrow: "Auditoria runtime",
    description: "Eventos de ejecucion y trazas recientes del sistema.",
  },
  "/dashboard/ai": {
    title: "AI Security",
    eyebrow: "Enterprise AI",
    description: "Contratos, memoria y readiness de inteligencia de seguridad.",
  },
  "/dashboard/users": {
    title: "Usuarios",
    eyebrow: "Control de acceso",
    description: "Gestion de cuentas, roles y permisos de operadores.",
  },
  "/dashboard/security": {
    title: "Seguridad",
    eyebrow: "Sesion y postura",
    description: "Estado de sesion, token y controles de seguridad del panel.",
  },
};

function getRouteMeta(pathname) {
  return routeTitles[pathname] || routeTitles["/dashboard"];
}

export default function DashboardLayout() {
  const { user, logout, backendOffline } = useAuth();
  const { notify } = useNotification();
  const navigate = useNavigate();
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const routeMeta = getRouteMeta(location.pathname);
  const operatorName = (user.email || "operator")
    .split("@")[0]
    .replace(/[-_.]+/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());

  const handleLogout = () => {
    logout();
    notify("warning", "Sesion cerrada correctamente.");
    navigate("/login", { replace: true });
  };

  return (
    <div className="min-h-screen bg-[#0b1020] font-body text-[#eef3ff]">
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute inset-0 bg-[linear-gradient(135deg,rgba(74,225,118,0.08),transparent_32%),linear-gradient(315deg,rgba(173,198,255,0.08),transparent_30%)]" />
        <div className="grid-bg absolute inset-0 opacity-70" />
      </div>

      <button
        type="button"
        onClick={() => setSidebarOpen(true)}
        className="fixed left-4 top-4 z-[70] inline-flex h-10 w-10 items-center justify-center border border-white/10 bg-[#121a2f] text-[#dbe7ff] shadow-lg lg:hidden"
        aria-label="Abrir navegacion"
      >
        <Menu size={18} />
      </button>

      <aside
        className={[
          "fixed inset-y-0 left-0 z-[80] flex w-72 flex-col border-r border-white/10 bg-[#10182b]/95 shadow-2xl backdrop-blur-xl transition-transform duration-200 lg:translate-x-0",
          sidebarOpen ? "translate-x-0" : "-translate-x-full",
        ].join(" ")}
      >
        <div className="flex h-20 items-center justify-between border-b border-white/10 px-5">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center border border-[#adc6ff]/20 bg-[#0b1020]">
              <img src={logo} alt="VAELQORIX" className="h-8 w-8 object-contain" />
            </div>
            <div>
              <div className="font-headline text-sm font-black uppercase text-[#adc6ff]">
                VAELQORIX
              </div>
              <div className="font-label text-[10px] uppercase text-[#8c909f]">
                XDR Command
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={() => setSidebarOpen(false)}
            className="inline-flex h-9 w-9 items-center justify-center text-[#8c909f] hover:text-white lg:hidden"
            aria-label="Cerrar navegacion"
          >
            <X size={18} />
          </button>
        </div>

        <div className="border-b border-white/10 px-5 py-4">
          <div className="flex items-center justify-between">
            <span className="font-label text-[10px] uppercase text-[#8c909f]">Estado backend</span>
            <span
              className={[
                "inline-flex items-center gap-2 font-label text-[10px] uppercase",
                backendOffline ? "text-[#f59e0b]" : "text-[#4ae176]",
              ].join(" ")}
            >
              <span
                className={[
                  "h-2 w-2 rounded-full",
                  backendOffline ? "bg-[#f59e0b]" : "bg-[#4ae176]",
                ].join(" ")}
              />
              {backendOffline ? "Offline" : "Conectado"}
            </span>
          </div>
          <div className="mt-3 grid grid-cols-2 gap-2">
            <StatusTile icon={Gauge} label="Fase" value="6" />
            <StatusTile icon={DatabaseZap} label="Modo" value="UI" />
          </div>
        </div>

        <nav className="custom-scrollbar flex-1 overflow-y-auto px-3 py-4">
          {navSections.map((section) => (
            <div key={section.title} className="mb-5">
              <div className="px-3 pb-2 font-label text-[10px] uppercase text-[#5f687a]">
                {section.title}
              </div>
              <div className="space-y-1">
                {section.items.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    end={item.end}
                    onClick={() => setSidebarOpen(false)}
                    className={({ isActive }) =>
                      [
                        "flex min-h-11 items-center gap-3 px-3 text-sm transition-colors",
                        isActive
                          ? "border-l-2 border-[#4ae176] bg-[#1a2540] text-white"
                          : "text-[#aeb7ca] hover:bg-[#172137] hover:text-white",
                      ].join(" ")
                    }
                  >
                    <item.icon size={18} />
                    <span>{item.label}</span>
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        <div className="border-t border-white/10 p-4">
          <div className="mb-3 flex items-center gap-3 bg-[#0b1020] p-3">
            <div className="flex h-9 w-9 items-center justify-center bg-[#22304f] font-label text-xs font-bold text-[#adc6ff]">
              {(user.email || "OP").slice(0, 2).toUpperCase()}
            </div>
            <div className="min-w-0">
              <div className="truncate text-sm font-semibold text-white">{operatorName}</div>
              <div className="truncate font-label text-[10px] uppercase text-[#8c909f]">
                {user.role || "operator"}
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={handleLogout}
            className="flex h-10 w-full items-center justify-center gap-2 border border-white/10 text-sm text-[#aeb7ca] transition-colors hover:border-[#ffb4ab]/40 hover:text-[#ffb4ab]"
          >
            <LogOut size={16} />
            Cerrar sesion
          </button>
        </div>
      </aside>

      {sidebarOpen && (
        <button
          type="button"
          className="fixed inset-0 z-[75] bg-black/60 lg:hidden"
          onClick={() => setSidebarOpen(false)}
          aria-label="Cerrar navegacion"
        />
      )}

      <div className="relative z-10 lg:pl-72">
        <header className="sticky top-0 z-40 border-b border-white/10 bg-[#0b1020]/86 backdrop-blur-xl">
          <div className="flex min-h-20 flex-col gap-4 px-5 py-4 lg:flex-row lg:items-center lg:justify-between lg:px-8">
            <div className="pl-12 lg:pl-0">
              <div className="font-label text-[10px] uppercase tracking-normal text-[#8c909f]">
                {routeMeta.eyebrow}
              </div>
              <h1 className="mt-1 font-headline text-2xl font-bold text-white">
                {routeMeta.title}
              </h1>
              <p className="mt-1 max-w-2xl text-sm text-[#aeb7ca]">{routeMeta.description}</p>
            </div>

            <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
              <label className="relative block min-w-0 sm:w-72">
                <Search
                  size={16}
                  className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[#8c909f]"
                />
                <input
                  type="search"
                  placeholder="Buscar modulo o evento"
                  className="h-10 w-full border border-white/10 bg-[#121a2f] pl-9 pr-3 text-sm text-white outline-none transition-colors placeholder:text-[#6f788b] focus:border-[#adc6ff]/50"
                />
              </label>
              <div className="flex items-center gap-2">
                <HealthPill offline={backendOffline} />
                <button
                  type="button"
                  onClick={() => navigate("/dashboard/diagnostics")}
                  className="inline-flex h-10 items-center gap-2 border border-white/10 bg-[#121a2f] px-3 text-sm text-[#dbe7ff] transition-colors hover:border-[#adc6ff]/40"
                >
                  <Stethoscope size={16} />
                  Diagnostico
                </button>
              </div>
            </div>
          </div>
        </header>

        <main className="min-h-[calc(100vh-5rem)] px-5 py-6 lg:px-8">
          {backendOffline && (
            <div className="mb-6 border border-[#f59e0b]/30 bg-[#3b2a11]/70 px-4 py-3 text-sm text-[#ffd89a]">
              Backend offline: metricas, alertas y gestion no estan disponibles en tiempo real.
            </div>
          )}

          <Suspense fallback={<Loader />}>
            <Outlet />
          </Suspense>
        </main>
      </div>
    </div>
  );
}

function StatusTile({ icon: TileIcon, label, value }) {
  return (
    <div className="border border-white/10 bg-[#121a2f] p-3">
      {createElement(TileIcon, { size: 16, className: "mb-2 text-[#adc6ff]" })}
      <div className="font-label text-[9px] uppercase text-[#8c909f]">{label}</div>
      <div className="text-sm font-semibold text-white">{value}</div>
    </div>
  );
}

function HealthPill({ offline }) {
  return (
    <span
      className={[
        "inline-flex h-10 items-center gap-2 border px-3 font-label text-[10px] uppercase",
        offline
          ? "border-[#f59e0b]/30 bg-[#3b2a11] text-[#ffd89a]"
          : "border-[#4ae176]/30 bg-[#10281b] text-[#9ef0b6]",
      ].join(" ")}
    >
      <span className={["h-2 w-2 rounded-full", offline ? "bg-[#f59e0b]" : "bg-[#4ae176]"].join(" ")} />
      {offline ? "Offline" : "Live"}
    </span>
  );
}
