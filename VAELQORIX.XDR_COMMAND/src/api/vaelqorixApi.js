// =============================================================
// VAELQORIX XDR Command - API CLIENT
// v3.20 Elite Secure RealAuth+UX + Hardening + Correlation+Health
// =============================================================
// Responsabilidades:
//   - Gestionar todas las llamadas HTTP al backend VAELQORIX.
//   - Inyectar el JWT de sesión en rutas protegidas (/users, /threats, ...).
//   - Usar un monitor token *dedicado* para /monitoring/* (no JWT de usuario).
//   - Manejo global de errores (401/403/network) con mensajes UX-friendly.
//   - Soporte opcional de mocks solo para métricas PromQL si VITE_USE_MOCKS=true.
//   - Expone helpers para:
//       - Motor de correlación: /monitoring/correlation/run
//       - Health global infra: /monitoring/health/full
//
// NOTAS CLAVE:
//   - NUNCA se generan sesiones falsas tipo offline@mock.
//   - Si el backend cae (network error), se lanza:
//       "No se puede conectar con el servidor."
//     y los componentes muestran mensajes tipo
//       "Backend offline - ..."
// =============================================================

import axios from "axios";

// =============================================================
//  Config base
// =============================================================

// URL base del backend (definida en .env -> VITE_API_URL)
const API_BASE_URL =
  (import.meta.env.VITE_API_URL || "http://127.0.0.1:8010").replace(/\/+$/, "");
const API_TIMEOUT_MS = Number(import.meta.env.VITE_API_TIMEOUT_MS || 45000);

// Token interno para /monitoring/* (NO es el JWT de usuario)
const MONITOR_TOKEN = (
  import.meta.env.VITE_VAELQORIX_MONITOR_TOKEN ||
  ""
).trim();

// Clave donde guardamos el JWT real de usuario
const USER_TOKEN_KEY = "access_token";

if (!MONITOR_TOKEN) {
  console.warn(
    "[VAELQORIX] VITE_VAELQORIX_MONITOR_TOKEN vacio; /monitoring/* usara JWT admin si existe"
  );
}

// =============================================================
//  Instancia axios principal
// =============================================================

const vaelqorixApi = axios.create({
  baseURL: API_BASE_URL,
  headers: { "Content-Type": "application/json" },
  timeout: API_TIMEOUT_MS,
});

// =============================================================
//  Utilidades de ruta
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

const isAutonomyPath = (config) => {
  try {
    const url = new URL(config.url, API_BASE_URL);
    return (
      url.pathname.startsWith("/api/v1/redqueen/") ||
      url.pathname.startsWith("/api/v1/ares/") ||
      url.pathname.startsWith("/api/v1/audit/") ||
      url.pathname.startsWith("/api/v1/ingest/")
    );
  } catch {
    const url = String(config?.url || "");
    return (
      url.startsWith("/api/v1/redqueen/") ||
      url.startsWith("/api/v1/ares/") ||
      url.startsWith("/api/v1/audit/") ||
      url.startsWith("/api/v1/ingest/")
    );
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
// [SEC] Helpers de token de usuario
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
// [SEC] Interceptores
// =============================================================

//  REQUEST - Inyección de tokens (JWT o monitor-token)
vaelqorixApi.interceptors.request.use(
  (config) => {
    // Aseguramos que headers exista
    config.headers = config.headers || {};

    // 1) Excepción: /auth/login -> NO enviamos JWT
    if (isAuthLoginPath(config)) {
      return config;
    }

    // 2) /monitoring/* -> SIEMPRE via monitor token (no JWT de usuario)
    if (isMonitoringPath(config) || isAutonomyPath(config)) {
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

    // 3) Resto de rutas protegidas -> JWT REAL de usuario
    const jwt = getUserToken();
    if (jwt) {
      config.headers.Authorization = `Bearer ${jwt}`;
    }

    return config;
  },
  (error) => Promise.reject(error)
);

//  RESPONSE - Manejo global de errores
vaelqorixApi.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status;
    const requestConfig = error.config || {};
    const url = String(requestConfig?.url || "");

    // =========================================================
    //  Error de red (backend caído / sin respuesta)
    //   -> error.response es undefined, es un fallo de conexión
    // =========================================================
    if (!error.response) {
      console.error(
        "[VAELQORIX] Error de conexión con el servidor:",
        error.message
      );
      if (error.code === "ECONNABORTED") {
        throw new Error("La petición al backend tardó demasiado.");
      }
      throw new Error("No se puede conectar con el servidor.");
    }

    // =========================================================
    // [SEC] 401 -> Token inválido/expirado (excepto en /auth/login)
    // =========================================================
    if (status === 401 && !isAuthLoginPath(requestConfig)) {
      console.warn("[VAELQORIX] Token inválido o expirado. Cerrando sesión...");
      setUserToken("");
      localStorage.removeItem("user");
      window.location.href = "/login";
    }

    // =========================================================
    //  403 en rutas sensibles (/users*, /threats*)
    //     -> mensaje claro de falta de permisos (rol admin)
    // =========================================================
    if (
      status === 403 &&
      (url.startsWith("/users") || url.startsWith("/threats"))
    ) {
      const msg =
        "No tienes permisos para realizar esta acción (se requiere rol administrador).";
      console.warn("[VAELQORIX] 403 en ruta sensible:", url, "->", msg);
      throw new Error(msg);
    }

    // =========================================================
    //  Resto de errores -> usar detail/message del backend si existe
    // =========================================================
    const detail =
      error.response?.data?.detail ||
      error.response?.data?.message ||
      error.message ||
      "Error desconocido en la comunicación con el servidor";

    console.error("[VAELQORIX] API Error:", detail);
    throw new Error(detail);
  }
);

// =============================================================
// [SEC] Auth - 100% real (sin mocks)
// =============================================================

/**
 * Login real contra /auth/login.
 * El backend espera { username, password } (username = email).
 */
export const loginUser = async ({ username, password }) => {
  const payload = { username, password };
  const { data } = await vaelqorixApi.post("/auth/login", payload);

  if (data?.access_token) {
    // [SEC] Guardamos el mismo token que usas en PowerShell
    setUserToken(data.access_token);
  }

  return data;
};

/**
 * Obtiene el usuario actual real desde /users/me.
 * Si falla, se lanza error y el AuthContext decide cómo reaccionar.
 */
export const getCurrentUser = async () => {
  const { data } = await vaelqorixApi.get("/users/me");
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
// [USERS] Users
// =============================================================

/**
 * Lista de usuarios paginada (o simple array, según backend).
 */
export const getUsers = async (page = 1, limit = 20) => {
  const { data } = await vaelqorixApi.get(`/users/?page=${page}&limit=${limit}`);
  return Array.isArray(data) ? data : data.items || data.users || [];
};

export const createUser = async (payload) => {
  const { data } = await vaelqorixApi.post("/users/", payload);
  return data;
};

export const updateUser = async (id, payload) => {
  const { data } = await vaelqorixApi.put(`/users/${id}`, payload);
  return data;
};

export const deleteUser = async (id) => {
  const { data } = await vaelqorixApi.delete(`/users/${id}`);
  return data;
};

export const toggleUserActive = async (id, isActive) => {
  const { data } = await vaelqorixApi.patch(`/users/${id}/toggle-active`, null, {
    params: { is_active: isActive },
  });
  return data;
};

// =============================================================
//  Threats
// =============================================================

export const listThreats = async (skip = 0, limit = 20) => {
  const { data } = await vaelqorixApi.get(`/threats/?skip=${skip}&limit=${limit}`);
  return data;
};

export const createThreat = async (payload) => {
  const { data } = await vaelqorixApi.post("/threats/", payload);
  return data;
};

export const getThreatById = async (id) => {
  const { data } = await vaelqorixApi.get(`/threats/${id}`);
  return data;
};

export const updateThreat = async (id, payload) => {
  const { data } = await vaelqorixApi.put(`/threats/${id}`, payload);
  return data;
};

export const deleteThreat = async (id) => {
  const { data } = await vaelqorixApi.delete(`/threats/${id}`);
  return data;
};

// =============================================================
// [AI] Correlation Engine (monitoring/correlation/run)
// =============================================================

/**
 * Ejecuta el motor de correlación en backend.
 * Protegido por VAELQORIX_MONITOR_TOKEN (no usa JWT de usuario).
 *
 * Respuesta:
 *   {
 *     created_count: number,
 *     created_threats: [...]
 *   }
 */
export const runCorrelationOnce = async () => {
  const { data } = await vaelqorixApi.post("/monitoring/correlation/run");
  return data;
};

// =============================================================
//  Health Global Infraestructura (monitoring/health/full)
// =============================================================

/**
 * Devuelve el estado global de infraestructura:
 *   backend / database / prometheus / alertmanager / overall
 *
 * Ideal para cards tipo "InfrastructureHealthCard".
 */
export const getFullInfraHealth = async () => {
  const { data } = await vaelqorixApi.get("/monitoring/health/full");
  return data;
};

// =============================================================
//  Helpers generales
// =============================================================

export const getHealth = async () => {
  try {
    const { data } = await vaelqorixApi.get("/health");
    return data;
  } catch (e) {
    console.error("[VAELQORIX] Error en /health:", e);
    throw new Error("No se pudo consultar /health del backend.");
  }
};

export const listThreatsRaw = async (skip = 0, limit = 20) => {
  const { data } = await vaelqorixApi.get(`/threats/?skip=${skip}&limit=${limit}`);
  return data;
};

// =============================================================
//  Alertas Prometheus (SIEMPRE REAL desde Alertmanager)
// =============================================================

/**
 * Devuelve la lista plana de alertas activas desde:
 *   /monitoring/alerts/realtime -> backend -> Alertmanager /api/v2/alerts
 */
export const getAlerts = async () => {
  const { data } = await vaelqorixApi.get("/monitoring/alerts/realtime", {
    headers: { Accept: "application/json" },
  });
  return Array.isArray(data) ? data : [];
};

export const getRuntimeLogs = async ({ limit = 200, severity, search } = {}) => {
  const params = { limit };
  if (severity && severity !== "all") params.severity = severity;
  if (search) params.search = search;

  const { data } = await vaelqorixApi.get("/monitoring/logs", {
    params,
    headers: { Accept: "application/json" },
  });
  return data;
};

export const getProductionReadiness = async () => {
  const { data } = await vaelqorixApi.get("/monitoring/production-readiness");
  return data;
};

// =============================================================
// SecOps / DevSecOps Command Center
// =============================================================

export const getSecOpsStatus = async () => {
  const { data } = await vaelqorixApi.get("/api/v1/secops/status");
  return data;
};

export const getSecOpsPosture = async () => {
  const { data } = await vaelqorixApi.get("/api/v1/secops/posture");
  return data;
};

export const getSecOpsEnterpriseReadiness = async ({ tenantId } = {}) => {
  const headers = tenantId ? { "X-Tenant-Id": tenantId } : undefined;
  const { data } = await vaelqorixApi.get("/api/v1/secops/enterprise/readiness", {
    headers,
  });
  return data;
};

export const listTenantPolicies = async ({ tenantId } = {}) => {
  const params = {};
  if (tenantId) params.tenant_id = tenantId;
  const { data } = await vaelqorixApi.get("/api/v1/secops/tenant-policies", {
    params,
  });
  return Array.isArray(data) ? data : data.items || [];
};

export const upsertTenantPolicy = async (payload) => {
  const { data } = await vaelqorixApi.post("/api/v1/secops/tenant-policies", payload);
  return data;
};

export const getSecOpsIntegrationsReadiness = async () => {
  const { data } = await vaelqorixApi.get("/api/v1/secops/integrations/readiness");
  return data;
};

export const listSecOpsProviders = async () => {
  const { data } = await vaelqorixApi.get("/api/v1/secops/providers");
  return Array.isArray(data) ? data : [];
};

export const getSecOpsProviderReadiness = async (provider) => {
  const { data } = await vaelqorixApi.get(
    `/api/v1/secops/providers/${encodeURIComponent(provider)}/readiness`
  );
  return data;
};

export const runSecOpsExecutionPreflight = async ({
  provider,
  actionType,
  executionControls = {},
}) => {
  const { data } = await vaelqorixApi.post("/api/v1/secops/execution/preflight", {
    provider,
    action_type: actionType,
    execution_controls: executionControls,
  });
  return data;
};

export const getSecOpsSecurityEvents = async ({
  eventType,
  reason,
  tenantId,
  limit = 50,
} = {}) => {
  const params = { limit };
  if (eventType) params.event_type = eventType;
  if (reason) params.reason = reason;
  if (tenantId) params.tenant_id = tenantId;
  const { data } = await vaelqorixApi.get("/api/v1/secops/security/events", {
    params,
  });
  return data;
};

export const exportSecOpsSecurityEvents = async ({
  destination = "generic_webhook",
  format = "soc_case.v1",
  includeItems = true,
  send = false,
  limit = 100,
  reason,
  tenantId,
} = {}) => {
  const payload = {
    destination,
    format,
    include_items: includeItems,
    send,
    limit,
  };
  if (reason) payload.reason = reason;
  if (tenantId) payload.tenant_id = tenantId;
  const { data } = await vaelqorixApi.post("/api/v1/secops/security/events/export", payload);
  return data;
};

export const materializeSecOpsSecurityEvents = async ({ minCount = 2, limit = 100 } = {}) => {
  const { data } = await vaelqorixApi.post("/api/v1/secops/security/events/materialize", {
    min_count: minCount,
    limit,
  });
  return data;
};

export const runSecOpsSecurityEventLifecycle = async (
  sourceEventId,
  { executionControls = { dry_run: true }, humanApproved = false, approvalEvidence = null } = {}
) => {
  const { data } = await vaelqorixApi.post(
    `/api/v1/secops/security/events/${encodeURIComponent(sourceEventId)}/lifecycle`,
    {
      execution_controls: executionControls,
      human_approved: humanApproved,
      approval_evidence: approvalEvidence,
    }
  );
  return data;
};

export const getResponseLogs = async ({ limit = 100, source, status } = {}) => {
  const params = { limit };
  if (source) params.source = source;
  if (status) params.status = status;

  const { data } = await vaelqorixApi.get("/monitoring/response-logs", { params });
  return Array.isArray(data) ? data : [];
};

export const getRedQueenStatus = async () => {
  const { data } = await vaelqorixApi.get("/api/v1/redqueen/status");
  return data;
};

export const evaluateRedQueenPolicy = async ({ score, actionType }) => {
  const { data } = await vaelqorixApi.post("/api/v1/redqueen/policy/evaluate", null, {
    params: { score, action_type: actionType },
  });
  return data;
};

export const issueRedQueenVerdict = async (payload) => {
  const { data } = await vaelqorixApi.post("/api/v1/redqueen/verdict", payload);
  return data;
};

export const issueRedQueenVerdictFromThreat = async (threatId, payload = {}) => {
  const { data } = await vaelqorixApi.post(
    `/api/v1/redqueen/verdict/from-threat/${threatId}`,
    payload
  );
  return data;
};

export const getRedQueenVerdict = async (verdictId) => {
  const { data } = await vaelqorixApi.get(`/api/v1/redqueen/verdict/${verdictId}`);
  return data;
};

export const ingestAresXEvent = async ({ source, payload }) => {
  const { data } = await vaelqorixApi.post("/api/v1/ingest/event", { source, payload });
  return data;
};

export const listAresXIngestSources = async () => {
  const { data } = await vaelqorixApi.get("/api/v1/ingest/sources");
  return data;
};

export const getAresXIngestStats = async () => {
  const { data } = await vaelqorixApi.get("/api/v1/ingest/stats");
  return data;
};

export const listRedQueenVerdicts = async ({ status, target, limit = 25 } = {}) => {
  const params = { limit };
  if (status && status !== "all") params.status = status;
  if (target) params.target = target;
  const { data } = await vaelqorixApi.get("/api/v1/redqueen/verdicts", { params });
  return data;
};

export const getAresXVerdict = async (verdictId) => {
  const { data } = await vaelqorixApi.get(`/api/v1/redqueen/verdicts/${verdictId}`);
  return data;
};

export const approveAresXVerdict = async (verdictId) => {
  const { data } = await vaelqorixApi.post(`/api/v1/redqueen/verdicts/${verdictId}/approve`);
  return data;
};

export const rejectAresXVerdict = async (verdictId) => {
  const { data } = await vaelqorixApi.post(`/api/v1/redqueen/verdicts/${verdictId}/reject`);
  return data;
};

export const getRedQueenStats = async () => {
  const { data } = await vaelqorixApi.get("/api/v1/redqueen/stats");
  return data;
};

export const getEntityProfile = async (entityId) => {
  const { data } = await vaelqorixApi.get(
    `/api/v1/redqueen/entities/${encodeURIComponent(entityId)}/profile`
  );
  return data;
};

export const getAresStatus = async () => {
  const { data } = await vaelqorixApi.get("/api/v1/ares/status");
  return data;
};

export const getAresOperationFlow = async () => {
  const { data } = await vaelqorixApi.get("/api/v1/ares/operation-flow");
  return data;
};

export const createAresApprovalToken = async ({ verdict, approver, reason = "" }) => {
  const { data } = await vaelqorixApi.post("/api/v1/ares/approval-token", {
    verdict,
    approver,
    reason,
  });
  return data;
};

export const setAresKillSwitch = async (mode) => {
  const { data } = await vaelqorixApi.post(`/api/v1/ares/kill-switch/${mode}`);
  return data;
};

export const getAresKillSwitch = async () => {
  const { data } = await vaelqorixApi.get("/api/v1/ares/kill-switch");
  return data;
};

export const activateAresKillSwitch = async ({ reason, actor = "frontend" }) => {
  const { data } = await vaelqorixApi.post("/api/v1/ares/kill-switch/activate", {
    reason,
    actor,
  });
  return data;
};

export const deactivateAresKillSwitch = async ({ reason, actor = "frontend" }) => {
  const { data } = await vaelqorixApi.post("/api/v1/ares/kill-switch/deactivate", {
    reason,
    actor,
  });
  return data;
};

export const runAresLifecycle = async (payload) => {
  const { data } = await vaelqorixApi.post("/api/v1/ares/lifecycle", payload);
  return data;
};

export const runAresLifecycleFromThreat = async (threatId, payload = {}) => {
  const { data } = await vaelqorixApi.post(
    `/api/v1/ares/lifecycle/from-threat/${threatId}`,
    payload
  );
  return data;
};

export const getAresResults = async (verdictId) => {
  const { data } = await vaelqorixApi.get(`/api/v1/ares/results/${verdictId}`);
  return data;
};

export const getAresEvidenceBundle = async (verdictId) => {
  const { data } = await vaelqorixApi.get(`/api/v1/ares/evidence/${verdictId}`);
  return data;
};

export const listAresExecutions = async ({
  verdictId,
  status,
  targetEntity,
  limit = 25,
} = {}) => {
  const params = { limit };
  if (verdictId) params.verdict_id = verdictId;
  if (status && status !== "all") params.status = status;
  if (targetEntity) params.target_entity = targetEntity;
  const { data } = await vaelqorixApi.get("/api/v1/ares/executions", { params });
  return data;
};

export const getAresExecution = async (executionId) => {
  const { data } = await vaelqorixApi.get(`/api/v1/ares/executions/${executionId}`);
  return data;
};

export const rollbackAresExecution = async (
  executionId,
  { reason, actor = "frontend" }
) => {
  const { data } = await vaelqorixApi.post(`/api/v1/ares/executions/${executionId}/rollback`, {
    reason,
    actor,
  });
  return data;
};

export const getAresApprovals = async (verdictId) => {
  const { data } = await vaelqorixApi.get(`/api/v1/ares/approvals/${verdictId}`);
  return data;
};

export const getAresAudit = async ({ verdictId, limit = 50 } = {}) => {
  const params = { limit };
  if (verdictId) params.verdict_id = verdictId;

  const { data } = await vaelqorixApi.get("/api/v1/ares/audit", { params });
  return data;
};

export const verifyAresAudit = async () => {
  const { data } = await vaelqorixApi.get("/api/v1/ares/audit/verify");
  return data;
};

export const listAresXAuditRecords = async ({
  verdictId,
  eventType,
  actor,
  limit = 25,
} = {}) => {
  const params = { limit };
  if (verdictId) params.verdict_id = verdictId;
  if (eventType) params.event_type = eventType;
  if (actor) params.actor = actor;
  const { data } = await vaelqorixApi.get("/api/v1/audit/records", { params });
  return data;
};

export const verifyAresXAudit = async ({ fromSequence = 1 } = {}) => {
  const { data } = await vaelqorixApi.post("/api/v1/audit/verify", {
    from_sequence: fromSequence,
  });
  return data;
};

// =============================================================
//  PromQL (con fallback a mocks SOLO si USE_MOCKS es true)
// =============================================================

export const promQuery = async (q) => {
  const { data } = await vaelqorixApi.get("/monitoring/query", { params: { q } });
  return data;
};

export const promRange = async ({ q, start, end, step = "15s" }) => {
  const { data } = await vaelqorixApi.get("/monitoring/range", {
    params: { q, start, end, step },
  });
  return data;
};

// =============================================================
//  Windows Host - NICs disponibles (para métricas de red)
// =============================================================

export const getWindowsNICs = async () => {
  const { data } = await vaelqorixApi.get("/monitoring/windows/nics");
  return Array.isArray(data?.data) ? data.data : [];
};

export const getGpuSummary = async () => {
  const { data } = await vaelqorixApi.get("/monitoring/gpu/summary");
  return data;
};

export const getHostSummary = async () => {
  const { data } = await vaelqorixApi.get("/monitoring/host/summary");
  return data;
};

export const getSourceDiagnostics = async () => {
  const { data } = await vaelqorixApi.get("/monitoring/sources/diagnostics");
  return data;
};

export default vaelqorixApi;
