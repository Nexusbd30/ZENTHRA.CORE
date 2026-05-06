import { LogOut, UserCircle2 } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { useNotify } from "@/components/NotificationProvider";

// =============================================================
// 💠 NAVBAR — ZENTHRA.CORE_SECURITY (v2.1)
// =============================================================
// - Barra superior del Dashboard
// - Integra cierre de sesión con AuthContext + notificaciones
// - Inspirada en la consola de AWS / Cisco SecureX
// =============================================================
export default function Navbar() {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const notify = useNotify();

  // =============================================================
  // 🔐 Cerrar sesión global
  // =============================================================
  const handleLogout = () => {
    localStorage.removeItem("access_token"); // coherente con la API
    logout();
    notify("info", "🔒 Sesión cerrada correctamente");
    navigate("/");
  };

  return (
    <nav className="flex items-center justify-between bg-[#0f172a]/90 backdrop-blur-md text-gray-100 px-6 py-3 shadow-lg border-b border-blue-500/30">
      {/* ========================================================= */}
      {/* TÍTULO / IDENTIFICADOR */}
      {/* ========================================================= */}
      <h2 className="text-lg font-semibold text-blue-400 tracking-wide">
        Panel Principal
      </h2>

      {/* ========================================================= */}
      {/* PERFIL / BOTÓN DE LOGOUT */}
      {/* ========================================================= */}
      <div className="flex items-center gap-4">
        {/* Información del usuario */}
        {user && (
          <div className="flex items-center gap-2 text-sm text-blue-200">
            <UserCircle2 className="w-5 h-5 text-blue-400" />
            <span>{user?.email || "Administrador"}</span>
          </div>
        )}

        {/* Botón de cierre de sesión */}
        <button
          onClick={handleLogout}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-md font-medium transition-all duration-200 shadow-md hover:shadow-blue-500/30"
        >
          <LogOut size={16} />
          <span>Cerrar sesión</span>
        </button>
      </div>
    </nav>
  );
}