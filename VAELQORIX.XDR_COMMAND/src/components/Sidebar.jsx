import { NavLink, useNavigate } from "react-router-dom";
import {
  Activity,
  Bell,
  HardDrive,
  LayoutDashboard,
  LogOut,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Stethoscope,
  Users as UsersIcon,
} from "lucide-react";

import logo from "@/assets/logos/vaelqorix-logo.jpeg";
import { useAuth } from "@/hooks/useAuth";
import { useNotification } from "@/hooks/useNotification";

const navItems = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/dashboard/alerts", label: "Alertas", icon: Bell },
  { to: "/dashboard/threats", label: "Amenazas", icon: ShieldAlert },
  { to: "/dashboard/secops", label: "SecOps", icon: Settings },
  { to: "/dashboard/monitoring", label: "Monitoreo", icon: Activity },
  { to: "/dashboard/diagnostics", label: "Diagnostico", icon: Stethoscope },
  { to: "/dashboard/datacenter", label: "Infraestructura", icon: HardDrive },
  { to: "/dashboard/users", label: "Usuarios", icon: UsersIcon },
  { to: "/dashboard/security", label: "Seguridad", icon: ShieldCheck },
];

export default function Sidebar() {
  const navigate = useNavigate();
  const { logout } = useAuth();
  const { notify } = useNotification();

  const handleLogout = () => {
    logout();
    notify("warning", "Sesion cerrada correctamente");
    navigate("/login", { replace: true });
  };

  return (
    <aside className="fixed left-0 top-0 z-40 flex h-screen w-64 flex-col border-r border-[#424754]/20 bg-[#131b2e] shadow-[24px_0_48px_-12px_rgba(6,14,32,0.5)]">
      <div className="mb-8 mt-6 flex items-center gap-3 px-6">
        <div className="flex h-10 w-10 items-center justify-center bg-primary/10">
          <img src={logo} alt="VAELQORIX" className="h-8 w-8 object-contain" />
        </div>
        <div>
          <div className="font-headline font-black uppercase leading-none text-[#adc6ff]">
            Command
          </div>
          <div className="font-label text-[10px] uppercase text-[#424754]">Level 4 Clear</div>
        </div>
      </div>

      <nav className="flex-1 space-y-1 px-2">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              [
                "flex items-center gap-3 px-4 py-3 text-sm font-medium transition-colors",
                isActive
                  ? "border-l-4 border-[#adc6ff] bg-[#2d3449] text-[#adc6ff]"
                  : "text-[#8c909f] hover:bg-[#171f33] hover:text-[#adc6ff]",
              ].join(" ")
            }
          >
            <item.icon size={18} />
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="mt-auto border-t border-[#424754]/20 px-4 py-4">
        <button
          type="button"
          onClick={handleLogout}
          className="flex w-full items-center gap-3 px-4 py-3 text-left text-[#8c909f] transition-colors hover:bg-[#171f33] hover:text-[#adc6ff]"
        >
          <LogOut size={18} />
          Cerrar sesion
        </button>
      </div>
    </aside>
  );
}
