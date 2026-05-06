// =============================================================
// 🔒 PrivateRoute — ZENTHRA.CORE_SECURITY (v3.6 Enterprise)
// =============================================================
// Componente de protección de rutas privadas.
// Garantiza que solo los usuarios autenticados (con JWT válido)
// puedan acceder a las secciones internas del sistema.
//
// ✅ Características:
//  - Valida sesión en tiempo real mediante AuthContext (useAuth)
//  - Evita "flickers" visuales mientras se verifica el token
//  - Redirige automáticamente al login si la sesión no existe o expiró
//  - Preserva la ruta de origen para redirección post-login
// =============================================================

import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";

export default function PrivateRoute({ children, element }) {
  // =============================================================
  // 🧠 Contexto global de autenticación
  // -------------------------------------------------------------
  // Obtiene el usuario autenticado y el estado de validación
  // desde el AuthContext (controlado por AuthProvider).
  // =============================================================
  const { user, loading } = useAuth();

  // =============================================================
  // 📍 Información de ubicación actual
  // -------------------------------------------------------------
  // Guardamos la ruta actual para redirigir al usuario
  // al mismo lugar después de iniciar sesión correctamente.
  // =============================================================
  const location = useLocation();

  // =============================================================
  // ⏳ Estado de validación del token
  // -------------------------------------------------------------
  // Mientras se verifica la sesión JWT, se muestra una pantalla
  // de espera limpia y coherente con el diseño ZENTHRA.
  // =============================================================
  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-[#0f172a] text-white text-lg tracking-wide">
        🔐 Verificando sesión...
      </div>
    );
  }

  // =============================================================
  // 🚫 Usuario no autenticado
  // -------------------------------------------------------------
  // Si el usuario no tiene un token válido o la sesión expiró,
  // se redirige automáticamente a /login.
  //
  // Además, se guarda la ruta previa en `state.from` para que
  // después del login se redirija correctamente a la página original.
  // =============================================================
  if (!user) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  // =============================================================
  // ✅ Usuario autenticado
  // -------------------------------------------------------------
  // Si el usuario tiene sesión activa y el token es válido,
  // se renderiza el contenido protegido de la ruta.
  // =============================================================
  return children || element || null;
}
