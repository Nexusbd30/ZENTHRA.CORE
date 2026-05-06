// =============================================================
// ZENTHRA.CORE_SECURITY — API CLIENT
// v3.20 Elite Secure RealAuth+UX + Hardening + Correlation+Health
// =============================================================
// Responsabilidades:
//   - Gestionar todas las llamadas HTTP al backend ZENTHRA.
//   - Inyectar el JWT de sesión en rutas protegidas (/users, /threats, ...).
//   - Usar un monitor token *dedicado* para /monitoring/* (no JWT de usuario).
//   - Manejo global de errores (401/403/network) con mensajes UX-friendly.
//   - Soporte opcional de mocks solo para métricas PromQL si VITE_USE_MOCKS=true.
//   - Expone helpers para:
//       · Motor de correlación: /monitoring/correlation/run
//       · Health global infra: /monitoring/health/full
//
// NOTAS CLAVE:
//   - NUNCA se generan sesiones falsas tipo offline@mock.
//   - Si el backend cae (network error), se lanza:
//       "No se puede conectar con el servidor."
//     y los componentes muestran mensajes tipo
//       "Backend offline — ..."
// =============================================================

import axios from "axios";

// =============================================================
// 🌐 Config base
// =============================================================

// URL base del backend (definida en .env → VITE_API_URL)
const API_BASE_URL =
  (import.meta.env.VITE_API_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");

// Token interno para /monitoring/* (NO es el JWT de usuario)
const MONITOR_TOKEN = (import.meta.env.VITE_ZENTHRA_MONITOR_TOKEN || "").trim();

// Clave donde guardamos el JWT real de usuario
const USER_TOKEN_KEY = "access_token";

console.log("[ZENTHRA] API_BASE_URL =", API_BASE_URL);
if (!MONITOR_TOKEN) {
  console.warn(
    "[ZENTHRA] VITE_ZENTHRA_MONITOR_TOKEN vacio; /monitoring/* usara JWT admin si existe"
  );
}

// =============================================================
// 🧩 Instancia axios principal
// =============================================================

const nexusApi = axios.create({
  baseURL: API_BASE_URL,
  headers: { "Content-Type": "application/json" },
  timeout: 10000,
});

// =============================================================
// 🧭 Utilidades de ruta
// =============================================================

/**
 * Determina si una petición apunta a /monitoring/*
 * (usa URL absoluta para evitar falsos positivos).
 */
const isMonitoringPath = (config) => {
  try {
    const url = new URL(config.url, API_BASE_URL);
    return url.pathname.startsWith("/monitoring/");
  } catch {
    // Fallback si la URL es relativa o rara
    return String(config?.url || "").startsWith("/monitoring/");
  }
};

/**
 * Determina si una petición es al endpoint de login.
 */
const isAuthLoginPath = (config) => {
  const url = String(config?.url || "");
  return url.startsWith("/auth/login");
};

// =============================================================
// 🔐 Helpers de token de usuario
// =============================================================

export const getUserToken = () => {
  return localStorage.getItem(USER_TOKEN_KEY) || "";
};

export const setUserToken = (token) => {
  if (token) {
    localStorage.setItem(USER_TOKEN_KEY, token);
  } else {
    localStorage.removeItem(USER_TOKEN_KEY);
  }
};

// =============================================================
// 🔐 Interceptores
// =============================================================

// 📨 REQUEST — Inyección de tokens (JWT o monitor-token)
nexusApi.interceptors.request.use(
  (config) => {
    // Aseguramos que headers exista
    config.headers = config.headers || {};

    // 1) Excepción: /auth/login → NO enviamos JWT
    if (isAuthLoginPath(config)) {
      return config;
    }

    // 2) /monitoring/* → SIEMPRE via monitor token (no JWT de usuario)
    if (isMonitoringPath(config)) {
      if (MONITOR_TOKEN) {
        config.headers.Authorization = `Bearer ${MONITOR_TOKEN}`;
      } else {
        const jwt = getUserToken();
        if (jwt) config.headers.Authorization = `Bearer ${jwt}`;
      }
      if (!config.headers.Accept) {
        config.headers.Accept = "application/json";
      }
      return config;
    }

    // 3) Resto de rutas protegidas → JWT REAL de usuario
    const jwt = getUserToken();
    if (jwt) {
      config.headers.Authorization = `Bearer ${jwt}`;
    }

    return config;
  },
  (error) => Promise.reject(error)
);

// 📩 RESPONSE — Manejo global de errores
nexusApi.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status;
    const requestConfig = error.config || {};
    const url = String(requestConfig?.url || "");

    // =========================================================
    // 🌐 Error de red (backend caído / sin respuesta)
    //   → error.response es undefined, es un fallo de conexión
    // =========================================================
    if (!error.response) {
      console.error(
        "[ZENTHRA] Error de conexión con el servidor:",
        error.message
      );
      throw new Error("No se puede conectar con el servidor.");
    }

    // =========================================================
    // 🔐 401 → Token inválido/expirado (excepto en /auth/login)
    // =========================================================
    if (status === 401 && !isAuthLoginPath(requestConfig)) {
      console.warn("[ZENTHRA] Token inválido o expirado. Cerrando sesión…");
      setUserToken("");
      localStorage.removeItem("user");
      window.location.href = "/login";
    }

    // =========================================================
    // 🎯 403 en rutas sensibles (/users*, /threats*)
    //     → mensaje claro de falta de permisos (rol admin)
    // =========================================================
    if (
      status === 403 &&
      (url.startsWith("/users") || url.startsWith("/threats"))
    ) {
      const msg =
        "No tienes permisos para realizar esta acción (se requiere rol administrador).";
      console.warn("[ZENTHRA] 403 en ruta sensible:", url, "→", msg);
      throw new Error(msg);
    }

    // =========================================================
    // 🧱 Resto de errores → usar detail/message del backend si existe
    // =========================================================
    const detail =
      error.response?.data?.detail ||
      error.response?.data?.message ||
      error.message ||
      "Error desconocido en la comunicación con el servidor";

    console.error("[ZENTHRA] API Error:", detail);
    throw new Error(detail);
  }
);

// =============================================================
// 🔐 Auth — 100% real (sin mocks)
// =============================================================

/**
 * Login real contra /auth/login.
 * El backend espera { username, password } (username = email).
 */
export const loginUser = async ({ username, password }) => {
  const payload = { username, password };
  const { data } = await nexusApi.post("/auth/login", payload);

  if (data?.access_token) {
    // 🔐 Guardamos el mismo token que usas en PowerShell
    setUserToken(data.access_token);
  }

  return data;
};

/**
 * Obtiene el usuario actual real desde /users/me.
 * Si falla, se lanza error y el AuthContext decide cómo reaccionar.
 */
export const getCurrentUser = async () => {
  const { data } = await nexusApi.get("/users/me");
  return data;
};

/**
 * Logout global: limpia storage y fuerza redirección a /login.
 */
export const logoutUser = () => {
  setUserToken("");
  localStorage.removeItem("user");
  window.location.href = "/login";
};

// =============================================================
// 👥 Users
// =============================================================

/**
 * Lista de usuarios paginada (o simple array, según backend).
 */
export const getUsers = async (page = 1, limit = 20) => {
  const { data } = await nexusApi.get(`/users/?page=${page}&limit=${limit}`);
  return Array.isArray(data) ? data : data.items || data.users || [];
};

export const createUser = async (payload) => {
  const { data } = await nexusApi.post("/users/", payload);
  return data;
};

export const updateUser = async (id, payload) => {
  const { data } = await nexusApi.put(`/users/${id}`, payload);
  return data;
};

export const deleteUser = async (id) => {
  const { data } = await nexusApi.delete(`/users/${id}`);
  return data;
};

export const toggleUserActive = async (id, isActive) => {
  const { data } = await nexusApi.patch(`/users/${id}/toggle-active`, null, {
    params: { is_active: isActive },
  });
  return data;
};

// =============================================================
// 🚨 Threats
// =============================================================

export const listThreats = async (skip = 0, limit = 20) => {
  const { data } = await nexusApi.get(`/threats/?skip=${skip}&limit=${limit}`);
  return data;
};

export const createThreat = async (payload) => {
  const { data } = await nexusApi.post("/threats/", payload);
  return data;
};

export const getThreatById = async (id) => {
  const { data } = await nexusApi.get(`/threats/${id}`);
  return data;
};

export const updateThreat = async (id, payload) => {
  const { data } = await nexusApi.put(`/threats/${id}`, payload);
  return data;
};

export const deleteThreat = async (id) => {
  const { data } = await nexusApi.delete(`/threats/${id}`);
  return data;
};

// =============================================================
// 🧠 Correlation Engine (monitoring/correlation/run)
// =============================================================

/**
 * Ejecuta el motor de correlación en backend.
 * Protegido por ZENTHRA_MONITOR_TOKEN (no usa JWT de usuario).
 *
 * Respuesta:
 *   {
 *     created_count: number,
 *     created_threats: [...]
 *   }
 */
export const runCorrelationOnce = async () => {
  const { data } = await nexusApi.post("/monitoring/correlation/run");
  return data;
};

// =============================================================
// 🩺 Health Global Infraestructura (monitoring/health/full)
// =============================================================

/**
 * Devuelve el estado global de infraestructura:
 *   backend / database / prometheus / alertmanager / overall
 *
 * Ideal para cards tipo "InfrastructureHealthCard".
 */
export const getFullInfraHealth = async () => {
  const { data } = await nexusApi.get("/monitoring/health/full");
  return data;
};

// =============================================================
// 🩺 Helpers generales
// =============================================================

export const getHealth = async () => {
  try {
    const { data } = await nexusApi.get("/health");
    console.log("[ZENTHRA] Backend Health:", data);
    return data;
  } catch (e) {
    console.error("[ZENTHRA] Error en /health:", e);
    throw new Error("No se pudo consultar /health del backend.");
  }
};

export const listThreatsRaw = async (skip = 0, limit = 20) => {
  const { data } = await nexusApi.get(`/threats/?skip=${skip}&limit=${limit}`);
  console.log("[ZENTHRA] Threats Raw:", data);
  return data;
};

// =============================================================
// 🔔 Alertas Prometheus (SIEMPRE REAL desde Alertmanager)
// =============================================================

/**
 * Devuelve la lista plana de alertas activas desde:
 *   /monitoring/alerts/realtime → backend → Alertmanager /api/v2/alerts
 */
export const getAlerts = async () => {
  const { data } = await nexusApi.get("/monitoring/alerts/realtime", {
    headers: { Accept: "application/json" },
  });
  return Array.isArray(data) ? data : [];
};

export const getRuntimeLogs = async ({ limit = 200, severity, search } = {}) => {
  const params = { limit };
  if (severity && severity !== "all") params.severity = severity;
  if (search) params.search = search;

  const { data } = await nexusApi.get("/users/runtime-logs", {
    params,
    headers: { Accept: "application/json" },
  });
  return data;
};

// =============================================================
// 📈 PromQL (con fallback a mocks SOLO si USE_MOCKS es true)
// =============================================================

export const promQuery = async (q) => {
  const { data } = await nexusApi.get("/monitoring/query", { params: { q } });
  return data;
};

export const promRange = async ({ q, start, end, step = "15s" }) => {
  const { data } = await nexusApi.get("/monitoring/range", {
    params: { q, start, end, step },
  });
  return data;
};

// =============================================================
// 🖧 Windows Host — NICs disponibles (para métricas de red)
// =============================================================

export const getWindowsNICs = async () => {
  const { data } = await nexusApi.get("/monitoring/windows/nics");
  return Array.isArray(data?.data) ? data.data : [];
};

export const getGpuSummary = async () => {
  const { data } = await nexusApi.get("/monitoring/gpu/summary");
  return data;
};

export const getHostSummary = async () => {
  const { data } = await nexusApi.get("/monitoring/host/summary");
  return data;
};

export const getSourceDiagnostics = async () => {
  const { data } = await nexusApi.get("/monitoring/sources/diagnostics");
  return data;
};

export default nexusApi;
