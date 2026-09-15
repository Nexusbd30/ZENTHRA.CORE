import { Suspense, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import {
  Activity,
  Bell,
  Bot,
  Boxes,
  ChevronDown,
  CircleHelp,
  Command,
  FileClock,
  LayoutDashboard,
  LogOut,
  Menu,
  Network,
  Search,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Stethoscope,
  Users,
  X,
} from "lucide-react";

import Loader from "@/components/Loader";
import logo from "@/assets/logos/vaelqorix-logo.jpeg";
import { useAuth } from "@/hooks/useAuth";
import { useNotification } from "@/hooks/useNotification";

const navSections = [
  {
    title: "Operaciones de seguridad",
    items: [
      { to: "/dashboard", label: "Resumen", icon: LayoutDashboard, end: true },
      { to: "/dashboard/alerts", label: "Detecciones", icon: Bell },
      { to: "/dashboard/threats", label: "Incidentes", icon: ShieldAlert },
      { to: "/dashboard/secops", label: "Respuesta", icon: Settings },
      { to: "/dashboard/monitoring", label: "Telemetria", icon: Activity, testLabel: "Monitoring" },
    ],
  },
  {
    title: "Entorno",
    items: [
      { to: "/dashboard/diagnostics", label: "Diagnostico", icon: Stethoscope },
      { to: "/dashboard/datacenter", label: "Superficie de ataque", icon: Network },
      { to: "/dashboard/logs", label: "Auditoria", icon: FileClock },
      { to: "/dashboard/ai", label: "AI security", icon: Bot },
      { to: "/dashboard/platform", label: "Visibilidad plataforma", icon: Boxes },
    ],
  },
  {
    title: "Administracion",
    items: [
      { to: "/dashboard/users", label: "Identidad y acceso", icon: Users },
      { to: "/dashboard/security", label: "Postura de seguridad", icon: ShieldCheck },
    ],
  },
];

const routeTitles = {
  "/dashboard": {
    title: "Centro de mando",
    eyebrow: "Security operations / Overview",
    description: "Prioriza el riesgo, investiga senales y coordina la respuesta desde una vista unificada.",
  },
  "/dashboard/alerts": {
    title: "Detecciones",
    eyebrow: "Security operations / Detections",
    description: "Senales activas, severidad y evidencia correlacionada del entorno.",
  },
  "/dashboard/threats": {
    title: "Incidentes",
    eyebrow: "Security operations / Incidents",
    description: "Investigacion, contexto y ciclo de vida de amenazas priorizadas.",
  },
  "/dashboard/monitoring": {
    title: "Telemetria",
    eyebrow: "Environment / Telemetry",
    description: "Metricas de servicios, recursos, disponibilidad y cobertura de datos.",
  },
  "/dashboard/secops": {
    title: "Respuesta",
    eyebrow: "Security operations / Response",
    description: "Playbooks, readiness, politicas y acciones gobernadas de SecOps.",
  },
  "/dashboard/diagnostics": {
    title: "Diagnostico",
    eyebrow: "Environment / Diagnostics",
    description: "Validaciones de backend, conectividad y estado interno de la plataforma.",
  },
  "/dashboard/datacenter": {
    title: "Superficie de ataque",
    eyebrow: "Environment / Attack surface",
    description: "Activos, nodos, servicios y relaciones expuestas a riesgo.",
  },
  "/dashboard/logs": {
    title: "Registro de auditoria",
    eyebrow: "Environment / Audit logs",
    description: "Trazabilidad operativa, eventos de ejecucion y actividad reciente.",
  },
  "/dashboard/ai": {
    title: "AI Security",
    eyebrow: "Intelligence / AI security",
    description: "Razonamiento, memoria y controles de inteligencia defensiva.",
  },
  "/dashboard/platform": {
    title: "Visibilidad de plataforma",
    eyebrow: "Environment / Platform visibility",
    description: "Estado de conexion entre la consola, las APIs y cada dominio operativo del backend.",
  },
  "/dashboard/users": {
    title: "Identidad y acceso",
    eyebrow: "Administration / IAM",
    description: "Cuentas, roles y privilegios de operadores de seguridad.",
  },
  "/dashboard/security": {
    title: "Postura de seguridad",
    eyebrow: "Administration / Security",
    description: "Estado de sesion y controles de seguridad de la consola.",
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
    <div className="vx-workspace min-h-screen font-body text-[var(--vx-text)]">
      <div className="vx-grid pointer-events-none fixed inset-0" />

      <button
        type="button"
        onClick={() => setSidebarOpen(true)}
        className="fixed left-4 top-4 z-[70] grid h-10 w-10 place-items-center rounded-md border border-[var(--vx-border)] bg-[var(--vx-surface)] text-white shadow-xl lg:hidden"
        aria-label="Abrir navegacion"
      >
        <Menu size={18} />
      </button>

      <aside
        className={[
          "fixed inset-y-0 left-0 z-[80] flex w-[264px] flex-col border-r border-[var(--vx-border)] bg-[var(--vx-sidebar)]/98 shadow-2xl transition-transform duration-200 lg:translate-x-0",
          sidebarOpen ? "translate-x-0" : "-translate-x-full",
        ].join(" ")}
      >
        <div className="flex h-[72px] items-center justify-between border-b border-[var(--vx-border)] px-4">
          <button type="button" className="flex min-w-0 items-center gap-3 text-left" aria-label="VAELQORIX XDR Command">
            <span className="grid h-10 w-10 shrink-0 place-items-center overflow-hidden rounded-md border border-[#31506e] bg-[#0d1c2e]">
              <img src={logo} alt="VAELQORIX" className="h-8 w-8 object-contain" />
            </span>
            <span className="min-w-0">
              <span className="block font-headline text-sm font-extrabold tracking-[-0.02em] text-white">VAELQORIX</span>
              <span className="font-label block text-[9px] uppercase text-[var(--vx-text-subtle)]">XDR Command Platform</span>
            </span>
            <ChevronDown size={14} className="text-[var(--vx-text-subtle)]" />
          </button>
          <button
            type="button"
            onClick={() => setSidebarOpen(false)}
            className="grid h-9 w-9 place-items-center text-[var(--vx-text-muted)] hover:text-white lg:hidden"
            aria-label="Cerrar navegacion"
          >
            <X size={18} />
          </button>
        </div>

        <div className="mx-3 mt-3 rounded-md border border-[var(--vx-border)] bg-[var(--vx-surface)] p-3">
          <div className="flex items-center justify-between gap-3">
            <div>
              <div className="vx-kicker">Tenant</div>
              <div className="mt-1 text-xs font-semibold text-white">VAELQORIX / Global</div>
            </div>
            <Boxes size={16} className="text-[var(--vx-blue)]" />
          </div>
          <div className="mt-3 flex items-center justify-between border-t border-[var(--vx-border)] pt-3 text-[11px]">
            <span className="text-[var(--vx-text-muted)]">Data plane</span>
            <span className={backendOffline ? "text-[var(--vx-amber)]" : "text-[var(--vx-green)]"}>
              <span className="vx-status-dot mr-2" />
              {backendOffline ? "Offline" : "Operational"}
            </span>
          </div>
        </div>

        <nav className="custom-scrollbar flex-1 overflow-y-auto px-3 py-5" aria-label="Navegacion principal">
          {navSections.map((section) => (
            <section key={section.title} className="mb-6">
              <div className="vx-kicker px-3 pb-2">{section.title}</div>
              <div className="space-y-1">
                {section.items.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    end={item.end}
                    onClick={() => setSidebarOpen(false)}
                    className={({ isActive }) =>
                      [
                        "group relative flex min-h-10 items-center gap-3 rounded-md px-3 text-[13px] font-medium transition-colors",
                        isActive
                          ? "bg-[#142b43] text-white"
                          : "text-[var(--vx-text-muted)] hover:bg-[#0f2033] hover:text-white",
                      ].join(" ")
                    }
                  >
                    {({ isActive }) => (
                      <>
                        {isActive && <span className="absolute inset-y-2 left-0 w-0.5 rounded-full bg-[var(--vx-blue)]" />}
                        <item.icon size={17} className={isActive ? "text-[var(--vx-blue)]" : "text-[var(--vx-text-subtle)] group-hover:text-[var(--vx-blue)]"} />
                        <span>{item.label}</span>
                        {item.testLabel && <span className="sr-only">{item.testLabel}</span>}
                      </>
                    )}
                  </NavLink>
                ))}
              </div>
            </section>
          ))}
        </nav>

        <div className="border-t border-[var(--vx-border)] p-3">
          <div className="flex items-center gap-3 rounded-md px-2 py-2">
            <span className="grid h-9 w-9 shrink-0 place-items-center rounded-full bg-[#1a3957] text-xs font-bold text-[#b9dbff]">
              {(user.email || "OP").slice(0, 2).toUpperCase()}
            </span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-xs font-semibold text-white">{operatorName}</span>
              <span className="font-label block truncate text-[9px] uppercase text-[var(--vx-text-subtle)]">{user.role || "operator"}</span>
            </span>
            <button type="button" onClick={handleLogout} className="grid h-8 w-8 place-items-center rounded-md text-[var(--vx-text-subtle)] hover:bg-[#251825] hover:text-[#ff9eaa]" aria-label="Cerrar sesion">
              <LogOut size={16} />
              <span className="sr-only">Cerrar sesion</span>
            </button>
          </div>
        </div>
      </aside>

      {sidebarOpen && <button type="button" className="fixed inset-0 z-[75] bg-black/70 lg:hidden" onClick={() => setSidebarOpen(false)} aria-label="Cerrar navegacion" />}

      <div className="relative z-10 lg:pl-[264px]">
        <header className="sticky top-0 z-40 border-b border-[var(--vx-border)] bg-[#07101f]/92 backdrop-blur-xl">
          <div className="flex h-[72px] items-center gap-4 px-4 lg:px-7">
            <div className="min-w-0 flex-1 pl-12 lg:pl-0">
              <div className="font-label truncate text-[9px] uppercase text-[var(--vx-text-subtle)]">{routeMeta.eyebrow}</div>
              <h1 className="mt-1 truncate font-headline text-xl font-bold text-white">{routeMeta.title}</h1>
            </div>

            <label className="relative hidden w-[min(32vw,360px)] xl:block">
              <Search size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[var(--vx-text-subtle)]" />
              <input type="search" placeholder="Buscar indicadores, activos o incidentes" className="h-10 w-full rounded-md border border-[var(--vx-border)] bg-[var(--vx-surface)] pl-9 pr-14 text-xs text-white outline-none placeholder:text-[var(--vx-text-subtle)] focus:border-[var(--vx-blue)]" />
              <kbd className="font-label absolute right-3 top-1/2 -translate-y-1/2 rounded border border-[var(--vx-border)] px-1.5 py-0.5 text-[9px] text-[var(--vx-text-subtle)]">Ctrl K</kbd>
            </label>

            <div className="hidden h-7 w-px bg-[var(--vx-border)] sm:block" />
            <HealthPill offline={backendOffline} />
            <button type="button" className="grid h-10 w-10 place-items-center rounded-md border border-[var(--vx-border)] bg-[var(--vx-surface)] text-[var(--vx-text-muted)] hover:border-[var(--vx-border-strong)] hover:text-white" aria-label="Ayuda">
              <CircleHelp size={17} />
            </button>
            <button type="button" onClick={() => navigate("/dashboard/ai")} className="hidden h-10 items-center gap-2 rounded-md bg-[#e7f2ff] px-3 text-xs font-bold text-[#07101f] shadow-[0_8px_22px_rgba(90,167,255,0.16)] sm:inline-flex">
              <Command size={15} />
              Ask ARESX
            </button>
          </div>
          <div className="border-t border-[var(--vx-border)]/70 px-4 py-2 lg:px-7">
            <p className="truncate text-xs text-[var(--vx-text-muted)]">{routeMeta.description}</p>
          </div>
        </header>

        <main className="min-h-[calc(100vh-105px)] px-4 py-5 lg:px-7 lg:py-6">
          {backendOffline && (
            <div className="mb-5 flex items-center gap-3 rounded-md border border-[#745625] bg-[#2a2113] px-4 py-3 text-xs text-[#f8cf83]">
              <Activity size={16} />
              Backend offline: el plano de datos esta degradado. Las metricas y detecciones pueden mostrar informacion parcial.
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

function HealthPill({ offline }) {
  return (
    <span className={["inline-flex h-10 items-center gap-2 rounded-md border px-3 font-label text-[9px] uppercase", offline ? "border-[#745625] bg-[#2a2113] text-[#f8cf83]" : "border-[#245a4a] bg-[#0c2b24] text-[#72e6bd]"].join(" ")}>
      <span className="vx-status-dot" />
      <span className="hidden md:inline">{offline ? "Offline" : "Live data"}</span>
    </span>
  );
}
