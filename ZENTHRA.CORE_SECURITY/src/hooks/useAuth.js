// =============================================================
// 🧠 useAuth — ZENTHRA.CORE_SECURITY (v3.1 Offline-Aware)
// =============================================================
// Hook global de autenticación.
// Proporciona acceso directo al contexto global de Auth.
// Permite obtener:
//   - user: usuario autenticado
//   - login(): iniciar sesión y guardar token
//   - logout(): cerrar sesión y limpiar datos
//   - loading: indica si se está validando el token
//   - backendOffline: indica si el backend no responde (modo offline)
// =============================================================

import { useAuthContext } from "@/context/AuthContext";

/**
 * Hook personalizado que centraliza el acceso al contexto de autenticación.
 *
 * @returns {{
 *   user: Object | null,
 *   login: Function,
 *   logout: Function,
 *   loading: boolean,
 *   backendOffline: boolean
 * }}
 */
export const useAuth = () => {
  const { user, login, logout, loading, backendOffline } = useAuthContext();

  return {
    /** Usuario autenticado (o null si no hay sesión) */
    user,

    /** Función para iniciar sesión: recibe { token, user } */
    login,

    /** Cierra sesión, limpia token y redirige */
    logout,

    /** Estado de carga: true mientras se valida la sesión */
    loading,

    /** Flag que indica si el backend está offline / no responde */
    backendOffline,
  };
};
