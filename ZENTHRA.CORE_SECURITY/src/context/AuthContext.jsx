// =============================================================
// 💠 AuthContext — ZENTHRA.CORE_SECURITY (v3.8 Enterprise Secure+Offline)
// =============================================================
// Control central de autenticación JWT.
// Gestiona el ciclo completo de sesión:
//   - Validación inicial del token contra el backend
//   - Persistencia local (localStorage)
//   - Logout automático al expirar
//   - Integración con nexusApi.js y Login.jsx
//   - Notificaciones globales de estado de sesión
//
// 🛰️ Modo Offline-Aware:
//   - Si el backend está OFF (no responde), NO marcamos la sesión
//     como "expirada": simplemente indicamos backendOffline = true.
//   - Si había un usuario en localStorage, se mantiene para poder
//     navegar la UI en modo "solo interfaz" sin revalidar.
//   - Si NUNCA has iniciado sesión antes, no hay usuario y PrivateRoute
//     seguirá pidiendo login (sin mocks, auth 100% real).
// =============================================================

import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
} from "react";
import { getCurrentUser, logoutUser } from "@/api/nexusApi";
import { useNotification } from "@/hooks/useNotification";

const AuthContext = createContext(null);

// Mensaje estándar del interceptor de nexusApi cuando el backend
// no es alcanzable (servidor apagado, red caída, etc.).
const OFFLINE_MSG = "No se puede conectar con el servidor.";

export const AuthProvider = ({ children }) => {
  // =============================================================
  // ⚙️ Estado global de autenticación
  // =============================================================
  const [user, setUser] = useState(() => {
    const stored = localStorage.getItem("user");
    return stored ? JSON.parse(stored) : null;
  });

  const [loading, setLoading] = useState(true);

  // Flag extra para saber si el backend está offline
  const [backendOffline, setBackendOffline] = useState(false);

  const { notify } = useNotification();

  // =============================================================
  // 🧹 resetSession — Limpieza suave de sesión
  // -------------------------------------------------------------
  // Se usa cuando queremos asegurarnos de que NO quede ningún
  // usuario ni token en memoria ni en localStorage.
  // También resetea el flag de backendOffline.
// =============================================================
  const resetSession = useCallback(() => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("user");
    setUser(null);
    setBackendOffline(false);
  }, []);

  // =============================================================
  // 🧭 VALIDAR SESIÓN AL INICIAR LA APP
  // -------------------------------------------------------------
  // Verifica si existe un token JWT en localStorage.
  //   - Si no hay token: no hay sesión → loading = false.
  //   - Si hay token:
  //       * Si el backend responde → getCurrentUser() actualiza user.
  //       * Si el backend dice "no hay conexión" → marcamos
  //         backendOffline = true, pero NO borramos la sesión local.
  //       * Si el backend responde con error "real" (401/403/etc.),
  //         se asume sesión expirada → resetSession().
// =============================================================
  const initializeSession = useCallback(async () => {
    const token = localStorage.getItem("access_token");

    // Si no hay token, no hay sesión que validar.
    if (!token) {
      setBackendOffline(false);
      setLoading(false);
      return;
    }

    try {
      setBackendOffline(false); // vamos a intentar contactar con el backend
      const data = await getCurrentUser();

      if (data?.email) {
        setUser(data);
        localStorage.setItem("user", JSON.stringify(data));
        setBackendOffline(false);
      } else {
        // Respuesta rara: limpiamos por seguridad.
        resetSession();
        notify("warning", "Sesión no válida. Inicia sesión nuevamente.");
      }
    } catch (error) {
      console.warn("⚠️ Error validando sesión:", error);

      const msg = error?.message || "";

      if (msg.includes(OFFLINE_MSG)) {
        // 🔌 Backend caído → modo offline
        // - No tocamos user ni token (usamos lo que haya en localStorage)
        // - Solo marcamos flag de backendOffline
        setBackendOffline(true);
        // Notificación suave (sin molestar demasiado al usuario)
        notify(
          "warning",
          "Backend offline — sesión no verificada en tiempo real (modo solo interfaz)."
        );
      } else {
        // ❌ Error real de sesión (401/403/token corrupto/etc.)
        resetSession();
        notify(
          "warning",
          "🔒 Sesión expirada o inválida. Inicia sesión nuevamente."
        );
      }
    } finally {
      setLoading(false);
    }
  }, [resetSession, notify]);

  useEffect(() => {
    initializeSession();
  }, [initializeSession]);

  // =============================================================
  // 🔓 LOGIN
  // -------------------------------------------------------------
  // Guarda el token y los datos del usuario tras un inicio exitoso.
// =============================================================
  const login = ({ token, user }) => {
    if (token) localStorage.setItem("access_token", token);
    if (user) localStorage.setItem("user", JSON.stringify(user));
    setUser(user);
    setBackendOffline(false);
    notify("success", "✅ Sesión iniciada correctamente");
  };

  // =============================================================
  // 🔒 LOGOUT
  // -------------------------------------------------------------
  // Limpia token y datos del usuario tanto en memoria como
  // en localStorage. Además redirige a /login mediante logoutUser().
// =============================================================
  const handleLogout = (message) => {
    try {
      // logoutUser ya hace window.location.href = "/login"
      logoutUser();
    } catch (e) {
      console.warn("Error al cerrar sesión en backend:", e);
      resetSession();
    }

    resetSession();

    if (message) notify("warning", message);
  };

  const logout = () => handleLogout("Sesión cerrada correctamente.");

  // =============================================================
  // ⏰ AUTO LOGOUT (Expiración del JWT)
// =============================================================
  useEffect(() => {
    const token = localStorage.getItem("access_token");
    if (!token) return;

    try {
      const [, payload] = token.split(".");
      const decoded = JSON.parse(atob(payload));
      const expMs = decoded.exp * 1000;
      const timeLeft = expMs - Date.now();

      if (timeLeft <= 0) {
        handleLogout("🔒 Tu sesión ha expirado. Inicia sesión nuevamente.");
      } else {
        const timer = setTimeout(() => {
          handleLogout("🔒 Tu sesión ha expirado. Inicia sesión nuevamente.");
        }, timeLeft);

        return () => clearTimeout(timer);
      }
    } catch (err) {
      console.warn("⚠️ Token inválido o dañado:", err);
    }
  }, [user]);

  // =============================================================
  // 🌍 RETORNO DEL CONTEXTO GLOBAL
  // =============================================================
  return (
    <AuthContext.Provider
      value={{
        user,
        login,
        logout,
        resetSession,
        loading,
        backendOffline, // 👈 flag visible para el resto del front
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

// =============================================================
// 🎯 HOOK PERSONALIZADO (useAuthContext)
// =============================================================
export const useAuthContext = () => useContext(AuthContext);
