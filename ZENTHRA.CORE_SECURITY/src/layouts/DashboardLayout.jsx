import { Suspense } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { useNotification } from "@/hooks/useNotification";
import Loader from "@/components/Loader";

const navItems = [
  { to: "/dashboard", icon: "grid_view", label: "Dashboard", end: true },
  { to: "/dashboard/alerts", icon: "dashboard", label: "Overview" },
  { to: "/dashboard/threats", icon: "security", label: "Incidents" },
  { to: "/dashboard/datacenter", icon: "hub", label: "Network Map" },
  { to: "/dashboard/logs", icon: "terminal", label: "Logs" },
  { to: "/dashboard/monitoring", icon: "dns", label: "Monitoring Infrastructure" },
  { to: "/dashboard/ai", icon: "radar", label: "Threat Intel" },
  { to: "/dashboard/users", icon: "verified_user", label: "User Security" },
  { to: "/dashboard/security", icon: "shield", label: "Security Status" },
];

export default function DashboardLayout() {
  const { user, logout, backendOffline } = useAuth();
  const { notify } = useNotification();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    notify("warning", "Sesión cerrada correctamente.");
    navigate("/login", { replace: true });
  };

  const operatorName = (user?.email || "sentinel-04")
    .split("@")[0]
    .replace(/[^a-zA-Z0-9-]/g, "-")
    .toUpperCase();

  return (
    <div className="min-h-screen bg-[#0a0e14] font-body text-[#f1f3fc]">
      <aside className="fixed left-0 top-0 z-50 flex h-screen w-64 flex-col border-r border-white/5 bg-slate-950/90 shadow-[20px_0_40px_rgba(0,0,0,0.4)] backdrop-blur-xl">
        <div className="p-6">
          <h1 className="font-headline text-2xl font-black tracking-tighter text-cyan-400 drop-shadow-[0_0_8px_rgba(0,240,255,0.4)]">
            ZENTHRA
          </h1>
          <p className="mt-1 font-label text-xs text-[#00deec] opacity-80">
            SYSTEM_ACTIVE
          </p>
        </div>

        <nav className="flex-1 space-y-2 px-4 py-4">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                [
                  "flex items-center gap-3 px-4 py-3 transition-all duration-300",
                  isActive
                    ? "border-l-2 border-cyan-400 bg-slate-900/80 font-bold text-cyan-400"
                    : "text-slate-400 hover:bg-slate-800/50 hover:text-cyan-200",
                ].join(" ")
              }
            >
              <span className="material-symbols-outlined">{item.icon}</span>
              <span className="font-headline text-sm tracking-tight">{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="mt-auto border-t border-slate-800/50 px-4 py-6">
          <button
            type="button"
            className="flex w-full items-center justify-center gap-2 rounded-sm bg-gradient-to-br from-[#8ff5ff] to-[#00eefc] px-4 py-3 font-label text-xs font-bold text-[#003f43] shadow-[0_0_15px_rgba(143,245,255,0.2)] transition-all hover:shadow-[0_0_20px_rgba(143,245,255,0.4)]"
          >
            <span className="material-symbols-outlined text-sm">add</span>
            NEW_INCIDENT
          </button>

          <div className="mt-6 flex flex-col gap-2">
            <button
              type="button"
              className="flex items-center gap-3 px-4 py-2 font-label text-xs text-slate-400 transition-colors hover:text-cyan-200"
            >
              <span className="material-symbols-outlined text-sm">settings</span>
              Settings
            </button>
            <button
              type="button"
              className="flex items-center gap-3 px-4 py-2 font-label text-xs text-slate-400 transition-colors hover:text-cyan-200"
            >
              <span className="material-symbols-outlined text-sm">help</span>
              Support
            </button>
          </div>
        </div>
      </aside>

      <header className="fixed left-64 right-0 top-0 z-40 flex h-16 items-center justify-between bg-slate-950/40 px-6 py-4 backdrop-blur-md">
        <div className="flex items-center gap-4">
          <span className="font-label text-xs text-[#a8abb3]">
            NODE_04 // {operatorName || "SECTOR_G7"}
          </span>
        </div>

        <div className="flex items-center gap-6">
          <div className="relative hidden group lg:block">
            <input
              type="text"
              placeholder="QUERY_SYSTEM..."
              className="w-64 rounded-sm bg-[#20262f] px-4 py-1.5 pr-10 font-label text-xs text-[#f1f3fc] outline-none transition-all focus:ring-1 focus:ring-[#8ff5ff]/30"
            />
            <span className="material-symbols-outlined absolute right-3 top-1/2 -translate-y-1/2 text-sm text-[#a8abb3]">
              search
            </span>
          </div>

          <div className="flex items-center gap-4 border-l border-slate-800/50 pl-6">
            <span className="material-symbols-outlined cursor-pointer text-slate-500 transition-colors hover:text-cyan-300">
              notifications
            </span>
            <span className="material-symbols-outlined cursor-pointer text-slate-500 transition-colors hover:text-cyan-300">
              shield_with_heart
            </span>
            <button
              type="button"
              onClick={handleLogout}
              className="material-symbols-outlined cursor-pointer text-slate-500 transition-colors hover:text-cyan-300"
            >
              power_settings_new
            </button>
            <div className="flex h-8 w-8 items-center justify-center rounded-sm border border-[#8ff5ff]/20 bg-[#1b2028] font-label text-[11px] font-bold text-[#8ff5ff]">
              {(user?.email || "ZS").slice(0, 2).toUpperCase()}
            </div>
          </div>
        </div>
      </header>

      <div className="fixed inset-0 z-0 ml-64 mt-16 overflow-hidden pointer-events-none">
        <div className="grid-pattern absolute inset-0" />
        <div className="absolute inset-0 bg-gradient-to-br from-transparent via-transparent to-[#8ff5ff]/[0.03]" />
      </div>

      <main className="relative z-10 ml-64 mt-16 min-h-[calc(100vh-4rem)] overflow-y-auto px-6 pb-14 pt-6">
        {backendOffline && (
          <div className="mb-6 border-l-2 border-amber-400 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">
            Backend offline: métricas de seguridad, alertas y gestión no están disponibles ahora mismo.
          </div>
        )}

        <Suspense fallback={<Loader />}>
          <Outlet />
        </Suspense>
      </main>

      <footer className="fixed bottom-0 left-64 right-0 z-40 flex h-8 items-center justify-between border-t border-slate-900 bg-slate-950 px-6">
        <div className="flex gap-6">
          <span className="flex items-center gap-2 font-label text-[10px] text-[#8ff5ff]">
            <span className="h-1.5 w-1.5 rounded-full bg-[#8ff5ff] shadow-[0_0_5px_#8ff5ff]" />
            ENCRYPTION_LAYER: ACTIVE
          </span>
          <span className="font-label text-[10px] text-[#a8abb3]">DB_SYNC: OK</span>
          <span className="font-label text-[10px] text-[#a8abb3]">
            AI_ANALYTICS: PROCESSING...
          </span>
        </div>
        <div className="font-label text-[10px] text-[#a8abb3] opacity-40">
          © 2024 ZENTHRA SECURITY CORP // OPERATOR: {operatorName || "SENTINEL-04"}
        </div>
      </footer>
    </div>
  );
}
