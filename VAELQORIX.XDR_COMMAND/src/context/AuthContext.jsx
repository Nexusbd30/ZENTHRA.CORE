// =============================================================
// ðŸ’  AuthContext â€” VAELQORIX XDR Command (v3.8 Enterprise Secure+Offline)
// =============================================================
// Control central de autenticaciÃ³n JWT.
// Gestiona el ciclo completo de sesiÃ³n:
//   - ValidaciÃ³n inicial del token contra el backend
//   - Persistencia local (localStorage)
//   - Logout automÃ¡tico al expirar
//   - IntegraciÃ³n con vaelqorixApi.js y Login.jsx
//   - Notificaciones globales de estado de sesiÃ³n
//
// ðŸ›°ï¸ Modo Offline-Aware:
//   - Si el backend estÃ¡ OFF (no responde), NO marcamos la sesiÃ³n
//     como "expirada": simplemente indicamos backendOffline = true.
//   - Si habÃ­a un usuario en localStorage, se mantiene para poder
//     navegar la UI en modo "solo interfaz" sin revalidar.
//   - Si NUNCA has iniciado sesiÃ³n antes, no hay usuario y PrivateRoute
//     seguirÃ¡ pidiendo login (sin mocks, auth 100% real).
// =============================================================

import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
} from "react";
import { getCurrentUser, logoutUser } from "@/api/vaelqorixApi";
import { useNotification } from "@/hooks/useNotification";

const AuthContext = createContext(null);

// Mensaje estÃ¡ndar del interceptor de vaelqorixApi cuando el backend
// no es alcanzable (servidor apagado, red caÃ­da, etc.).
const OFFLINE_MSG = "No se puede conectar con el servidor.";

export const AuthProvider = ({ children }) => {
  // =============================================================
  // âš™ï¸ Estado global de autenticaciÃ³n
  // =============================================================
  const [user, setUser] = useState(() => {
    const stored = localStorage.getItem("user");
    return stored ? JSON.parse(stored) : null;
  });

  const [loading, setLoading] = useState(true);

  // Flag extra para saber si el backend estÃ¡ offline
  const [backendOffline, setBackendOffline] = useState(false);

  const { notify } = useNotification();

  // =============================================================
  // ðŸ§¹ resetSession â€” Limpieza suave de sesiÃ³n
  // -------------------------------------------------------------
  // Se usa cuando queremos asegurarnos de que NO quede ningÃºn
  // usuario ni token en memoria ni en localStorage.
  // TambiÃ©n resetea el flag de backendOffline.
// =============================================================
  const resetSession = useCallback(() => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("user");
    setUser(null);
    setBackendOffline(false);
  }, []);

  // =============================================================
  // ðŸ§­ VALIDAR SESIÃ“N AL INICIAR LA APP
  // -------------------------------------------------------------
  // Verifica si existe un token JWT en localStorage.
  //   - Si no hay token: no hay sesiÃ³n â†’ loading = false.
  //   - Si hay token:
  //       * Si el backend responde â†’ getCurrentUser() actualiza user.
  //       * Si el backend dice "no hay conexiÃ³n" â†’ marcamos
  //         backendOffline = true, pero NO borramos la sesiÃ³n local.
  //       * Si el backend responde con error "real" (401/403/etc.),
  //         se asume sesiÃ³n expirada â†’ resetSession().
// =============================================================
  const initializeSession = useCallback(async () => {
    const token = localStorage.getItem("access_token");

    // Si no hay token, no hay sesiÃ³n que validar.
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
        notify("warning", "SesiÃ³n no vÃ¡lida. Inicia sesiÃ³n nuevamente.");
      }
    } catch (error) {
      console.warn("âš ï¸ Error validando sesiÃ³n:", error);

      const msg = error?.message || "";

      if (msg.includes(OFFLINE_MSG)) {
        // ðŸ”Œ Backend caÃ­do â†’ modo offline
        // - No tocamos user ni token (usamos lo que haya en localStorage)
        // - Solo marcamos flag de backendOffline
        setBackendOffline(true);
        // NotificaciÃ³n suave (sin molestar demasiado al usuario)
        notify(
          "warning",
          "Backend offline â€” sesiÃ³n no verificada en tiempo real (modo solo interfaz)."
        );
      } else {
        // âŒ Error real de sesiÃ³n (401/403/token corrupto/etc.)
        resetSession();
        notify(
          "warning",
          "ðŸ”’ SesiÃ³n expirada o invÃ¡lida. Inicia sesiÃ³n nuevamente."
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
  // ðŸ”“ LOGIN
  // -------------------------------------------------------------
  // Guarda el token y los datos del usuario tras un inicio exitoso.
// =============================================================
  const login = ({ token, user }) => {
    if (token) localStorage.setItem("access_token", token);
    if (user) localStorage.setItem("user", JSON.stringify(user));
    setUser(user);
    setBackendOffline(false);
    notify("success", "âœ… SesiÃ³n iniciada correctamente");
  };

  // =============================================================
  // ðŸ”’ LOGOUT
  // -------------------------------------------------------------
  // Limpia token y datos del usuario tanto en memoria como
  // en localStorage. AdemÃ¡s redirige a /login mediante logoutUser().
// =============================================================
  const handleLogout = (message) => {
    try {
      // logoutUser ya hace window.location.href = "/login"
      logoutUser();
    } catch (e) {
      console.warn("Error al cerrar sesiÃ³n en backend:", e);
      resetSession();
    }

    resetSession();

    if (message) notify("warning", message);
  };

  const logout = () => handleLogout("SesiÃ³n cerrada correctamente.");

  // =============================================================
  // â° AUTO LOGOUT (ExpiraciÃ³n del JWT)
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
        handleLogout("ðŸ”’ Tu sesiÃ³n ha expirado. Inicia sesiÃ³n nuevamente.");
      } else {
        const timer = setTimeout(() => {
          handleLogout("ðŸ”’ Tu sesiÃ³n ha expirado. Inicia sesiÃ³n nuevamente.");
        }, timeLeft);

        return () => clearTimeout(timer);
      }
    } catch (err) {
      console.warn("âš ï¸ Token invÃ¡lido o daÃ±ado:", err);
    }
  }, [user]);

  // =============================================================
  // ðŸŒ RETORNO DEL CONTEXTO GLOBAL
  // =============================================================
  return (
    <AuthContext.Provider
      value={{
        user,
        login,
        logout,
        resetSession,
        loading,
        backendOffline, // ðŸ‘ˆ flag visible para el resto del front
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

// =============================================================
// ðŸŽ¯ HOOK PERSONALIZADO (useAuthContext)
// =============================================================
export const useAuthContext = () => useContext(AuthContext);
