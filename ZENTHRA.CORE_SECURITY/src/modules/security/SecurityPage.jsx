// =============================================================
// 🛡️ SecurityPage — Consola de Seguridad de Sesión (v2.6 SOC-Ready)
// =============================================================
// Vista centralizada del estado de seguridad de ZENTHRA:
//   - Usuario autenticado (identidad + rol)
//   - Estado del backend (ONLINE / OFFLINE → backendOffline)
//   - Estado del token JWT (expiración, tiempo restante, payload básico)
//   - Información básica del canal (HTTP / HTTPS)
//
// IMPORTANTE:
//   - No hace llamadas al backend.
//   - Solo lee:
//       • AuthContext (useAuth) → user, backendOffline
//       • localStorage.access_token → token crudo
//       • Analiza el JWT con getTokenMeta (utils/jwtUtils).
// =============================================================

import { motion as Motion } from "framer-motion";
import { useAuth } from "@/hooks/useAuth";
import { getTokenMeta } from "@/utils/jwtUtils";

export default function SecurityPage() {
  const { user, backendOffline } = useAuth();

  // Token crudo desde localStorage (solo para inspección UI)
  const rawToken = localStorage.getItem("access_token") || null;
  const tokenMeta = rawToken ? getTokenMeta(rawToken) : null;

  const { expDate, iatDate, expiresInMs, expired, payload } = tokenMeta || {};

  // Cálculo simple de tiempo restante en minutos (JS puro, sin TypeScript)
  let expiresInMinutes = null;
  if (typeof expiresInMs === "number") {
    expiresInMinutes = Math.max(0, Math.round(expiresInMs / 60000));
  }

  // Texto estado backend
  const backendStatusText = backendOffline
    ? "🔸 Backend: OFFLINE (sin conexión con la API)"
    : "🟢 Backend: ONLINE (API accesible)";

  // Estado de autenticación (sesión)
  const authStatusText = backendOffline
    ? "Backend offline — no se puede validar el token en tiempo real. La interfaz sigue operativa en modo lectura."
    : user
    ? "Sesión segura activa. Token JWT validado recientemente contra el backend."
    : "Sin sesión activa. Inicia sesión para acceder a los módulos protegidos.";

  // Info de canal (aproximado, solo a nivel de UI)
  const isHttps = window.location.protocol === "https:";
  const channelText = isHttps
    ? "🔐 Canal actual: HTTPS (cifrado a nivel de transporte)."
    : "⚠️ Canal actual: HTTP — En producción se recomienda HTTPS con TLS 1.2+.";

  // Color + texto de estado del token
  let tokenStatusText = "No hay token en memoria.";
  let tokenStatusClass = "text-slate-300";

  if (rawToken && tokenMeta) {
    if (expired) {
      tokenStatusText = "Token expirado — se forzará logout en breve.";
      tokenStatusClass = "text-red-400";
    } else if (expiresInMinutes != null && expiresInMinutes <= 5) {
      tokenStatusText = `Token a punto de expirar (≈ ${expiresInMinutes} min).`;
      tokenStatusClass = "text-amber-300";
    } else if (expiresInMinutes != null) {
      tokenStatusText = `Token válido. Expira en ≈ ${expiresInMinutes} min.`;
      tokenStatusClass = "text-emerald-300";
    } else {
      tokenStatusText = "Token cargado, sin metadatos de expiración legibles.";
      tokenStatusClass = "text-slate-300";
    }
  }

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gradient-to-b from-[#0f172a] via-[#1e3a8a] to-[#1e40af] text-white px-4">
      {/* 🔰 Título principal */}
      <Motion.h1
        initial={{ opacity: 0, y: -40 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="text-4xl font-bold text-blue-400 mb-4 tracking-widest text-center"
      >
        Consola de Seguridad
      </Motion.h1>

      {/* 🧾 Descripción general */}
      <Motion.p
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.25, duration: 0.7 }}
        className="text-blue-200 text-center max-w-2xl leading-relaxed mb-8"
      >
        Panel central de estado de{" "}
        <span className="text-blue-400 font-semibold">
          ZENTHRA.CORE_SECURITY
        </span>
        . Aquí puedes revisar la sesión activa, el backend, el token JWT y el
        canal de comunicación.
      </Motion.p>

      {/* 🔐 Tarjeta principal */}
      <Motion.div
        initial={{ scale: 0.9, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ delay: 0.4, duration: 0.6 }}
        className="bg-blue-900/30 border border-blue-500/40 rounded-2xl p-8 shadow-2xl w-full max-w-3xl backdrop-blur-md"
      >
        {/* Estado de autenticación */}
        <h2 className="text-xl font-semibold text-blue-300 mb-2 tracking-wide">
          Estado de Autenticación
        </h2>
        <p className="text-sm text-blue-100 mb-4">{authStatusText}</p>

        {/* Info de usuario actual + backend/canal */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          {/* Usuario actual */}
          <div className="bg-black/20 border border-blue-500/30 rounded-xl p-4">
            <p className="text-xs text-blue-200 uppercase tracking-wide mb-1">
              Usuario actual
            </p>
            <p className="text-sm">
              {user
                ? user.full_name || user.email || "Usuario autenticado"
                : "— Sin sesión activa —"}
            </p>
            {user && (
              <>
                <p className="text-xs text-blue-200 mt-2">
                  Email:{" "}
                  <span className="font-mono text-blue-100">
                    {user.email}
                  </span>
                </p>
                <p className="text-xs text-blue-200 mt-1">
                  Rol:{" "}
                  <span className="font-semibold capitalize">
                    {user.role || "user"}
                  </span>
                </p>
              </>
            )}
          </div>

          {/* Estado backend + canal */}
          <div className="bg-black/20 border border-blue-500/30 rounded-xl p-4">
            <p className="text-xs text-blue-200 uppercase tracking-wide mb-1">
              Backend & Canal
            </p>
            <p className="text-sm mb-2">{backendStatusText}</p>
            <p className="text-xs text-blue-200">{channelText}</p>
          </div>
        </div>

        {/* Token info */}
        <div className="bg-black/25 border border-blue-500/40 rounded-xl p-4 mb-2">
          <p className="text-xs text-blue-200 uppercase tracking-wide mb-2">
            Token JWT
          </p>
          <p className={`text-sm mb-2 ${tokenStatusClass}`}>
            {tokenStatusText}
          </p>

          {expDate && (
            <p className="text-xs text-blue-100">
              Expira:{" "}
              <span className="font-mono">
                {expDate.toLocaleString("es-ES")}
              </span>
            </p>
          )}
          {iatDate && (
            <p className="text-xs text-blue-100 mt-1">
              Emitido:{" "}
              <span className="font-mono">
                {iatDate.toLocaleString("es-ES")}
              </span>
            </p>
          )}

          {/* Payload resumido (sub, iss) para debugging SOC */}
          {payload && (
            <p className="text-[11px] text-blue-200/80 mt-3 break-all">
              <span className="font-semibold">sub:</span>{" "}
              {payload.sub || "—"}{" "}
              <span className="font-semibold ml-2">iss:</span>{" "}
              {payload.iss || "—"}
            </p>
          )}
        </div>

        <div className="mt-4 text-right text-[11px] text-blue-300/80">
          ZENTHRA.CORE_SECURITY · Vista de seguridad de sesión
        </div>
      </Motion.div>
    </div>
  );
}


