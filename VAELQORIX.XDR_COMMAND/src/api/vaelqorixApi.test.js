import { beforeEach, describe, expect, it, vi } from "vitest";

const api = {
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
  delete: vi.fn(),
  patch: vi.fn(),
  interceptors: {
    request: { use: vi.fn() },
    response: { use: vi.fn() },
  },
};

let requestHandler;
let requestErrorHandler;
let responseHandler;
let responseErrorHandler;

vi.mock("axios", () => ({
  default: {
    create: vi.fn(() => api),
  },
}));

async function loadModule() {
  vi.resetModules();
  api.get.mockReset();
  api.post.mockReset();
  api.put.mockReset();
  api.delete.mockReset();
  api.patch.mockReset();
  api.interceptors.request.use.mockImplementation((success, error) => {
    requestHandler = success;
    requestErrorHandler = error;
  });
  api.interceptors.response.use.mockImplementation((success, error) => {
    responseHandler = success;
    responseErrorHandler = error;
  });
  return import("./vaelqorixApi.js");
}

beforeEach(() => {
  localStorage.clear();
  window.location.href = "http://localhost/";
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

describe("vaelqorixApi token helpers and interceptors", () => {
  it("stores, returns, and removes the user token", async () => {
    const mod = await loadModule();

    expect(mod.getUserToken()).toBe("");
    mod.setUserToken("jwt");
    expect(mod.getUserToken()).toBe("jwt");
    mod.setUserToken("");
    expect(mod.getUserToken()).toBe("");
  });

  it("injects auth headers for protected, monitoring, and autonomy requests", async () => {
    await loadModule();
    localStorage.setItem("access_token", "jwt");

    expect(requestHandler({ url: "/auth/login", headers: {} }).headers.Authorization).toBeUndefined();

    const monitoring = requestHandler({ url: "/monitoring/alerts/realtime", headers: {} });
    expect(monitoring.headers.Authorization).toBe("Bearer jwt");
    expect(monitoring.headers.Accept).toBe("application/json");

    const absoluteMonitoring = requestHandler({
      url: "http://127.0.0.1:8010/monitoring/health/full",
      headers: { Accept: "text/plain" },
    });
    expect(absoluteMonitoring.headers.Authorization).toBe("Bearer jwt");
    expect(absoluteMonitoring.headers.Accept).toBe("text/plain");

    const autonomy = requestHandler({ url: "/api/v1/redqueen/status", headers: {} });
    expect(autonomy.headers.Authorization).toBe("Bearer jwt");

    const protectedRequest = requestHandler({ url: "/users/", headers: {} });
    expect(protectedRequest.headers.Authorization).toBe("Bearer jwt");
  });

  it("falls back safely for unusual interceptor URLs", async () => {
    await loadModule();
    localStorage.setItem("access_token", "jwt");

    const monitoring = requestHandler({ url: "http://[", headers: {} });
    expect(monitoring.headers.Authorization).toBe("Bearer jwt");

    const rejected = new Error("request failed");
    await expect(requestErrorHandler(rejected)).rejects.toThrow("request failed");
    expect(responseHandler({ data: "ok" })).toEqual({ data: "ok" });
  });

  it("normalizes response errors", async () => {
    await loadModule();
    localStorage.setItem("access_token", "jwt");
    localStorage.setItem("user", "{}");

    expect(() =>
      responseErrorHandler({ code: "ECONNABORTED", message: "timeout", config: {} })
    ).toThrow("La petición al backend tardó demasiado.");

    expect(() => responseErrorHandler({ message: "offline", config: {} })).toThrow(
      "No se puede conectar con el servidor."
    );

    expect(() =>
      responseErrorHandler({ response: { status: 403, data: {} }, config: { url: "/users/1" } })
    ).toThrow("No tienes permisos");

    expect(() =>
      responseErrorHandler({
        response: { status: 500, data: { detail: "backend detail" } },
        config: { url: "/health" },
      })
    ).toThrow("backend detail");

    expect(() =>
      responseErrorHandler({
        response: { status: 500, data: { message: "backend message" } },
        message: "fallback",
        config: { url: "/health" },
      })
    ).toThrow("backend message");

    expect(() =>
      responseErrorHandler({ response: { status: 401, data: {} }, config: { url: "/users/me" } })
    ).toThrow("Error desconocido");
    expect(localStorage.getItem("access_token")).toBeNull();
  });
});

describe("vaelqorixApi helpers", () => {
  it("executes auth, users, threats, monitoring, redqueen, ares, audit and prom helpers", async () => {
    const mod = await loadModule();

    api.post.mockResolvedValue({ data: { access_token: "token", ok: true } });
    api.get.mockResolvedValue({ data: { items: [{ id: 1 }], data: ["nic"], ok: true } });
    api.put.mockResolvedValue({ data: { updated: true } });
    api.delete.mockResolvedValue({ data: { deleted: true } });
    api.patch.mockResolvedValue({ data: { active: true } });

    await expect(mod.loginUser({ username: "a@b.com", password: "pw" })).resolves.toEqual({
      access_token: "token",
      ok: true,
    });
    expect(localStorage.getItem("access_token")).toBe("token");

    await mod.getCurrentUser();
    await mod.logoutUser();
    await mod.getUsers();
    api.get.mockResolvedValueOnce({ data: [{ id: 2 }] });
    await expect(mod.getUsers(2, 5)).resolves.toEqual([{ id: 2 }]);
    api.get.mockResolvedValueOnce({ data: { users: [{ id: 3 }] } });
    await expect(mod.getUsers()).resolves.toEqual([{ id: 3 }]);
    await mod.createUser({ email: "a@b.com" });
    await mod.updateUser(1, { full_name: "A" });
    await mod.deleteUser(1);
    await mod.toggleUserActive(1, true);

    await mod.listThreats();
    await mod.createThreat({ title: "T" });
    await mod.getThreatById(1);
    await mod.updateThreat(1, { title: "U" });
    await mod.deleteThreat(1);
    await mod.runCorrelationOnce();
    await mod.getFullInfraHealth();
    await mod.getHealth();
    await mod.listThreatsRaw();
    api.get.mockResolvedValueOnce({ data: [{ labels: {} }] });
    await expect(mod.getAlerts()).resolves.toHaveLength(1);
    api.get.mockResolvedValueOnce({ data: {} });
    await expect(mod.getAlerts()).resolves.toEqual([]);
    await mod.getRuntimeLogs({ severity: "error", search: "db" });
    await mod.getRuntimeLogs({ severity: "all" });
    await mod.getProductionReadiness();
    api.get.mockResolvedValueOnce({ data: [{ id: "r" }] });
    await expect(mod.getResponseLogs({ source: "ares", status: "ok" })).resolves.toHaveLength(1);
    api.get.mockResolvedValueOnce({ data: {} });
    await expect(mod.getResponseLogs()).resolves.toEqual([]);

    await mod.getRedQueenStatus();
    await mod.evaluateRedQueenPolicy({ score: 90, actionType: "isolate" });
    await mod.issueRedQueenVerdict({ target: "host" });
    await mod.issueRedQueenVerdictFromThreat("threat-1");
    await mod.getRedQueenVerdict("verdict-1");
    await mod.ingestAresXEvent({ source: "wazuh", payload: {} });
    await mod.listAresXIngestSources();
    await mod.getAresXIngestStats();
    await mod.listRedQueenVerdicts({ status: "approved", target: "host", limit: 3 });
    await mod.listRedQueenVerdicts({ status: "all" });
    await mod.getAresXVerdict("verdict-1");
    await mod.approveAresXVerdict("verdict-1");
    await mod.rejectAresXVerdict("verdict-1");
    await mod.getRedQueenStats();
    await mod.getEntityProfile("host/name");
    await mod.getAresStatus();
    await mod.getAresOperationFlow();
    await mod.setAresKillSwitch("active");
    await mod.getAresKillSwitch();
    await mod.activateAresKillSwitch({ reason: "incident" });
    await mod.deactivateAresKillSwitch({ reason: "clear" });
    await mod.runAresLifecycle({ verdict_id: "v1" });
    await mod.runAresLifecycleFromThreat("threat-1");
    await mod.getAresResults("verdict-1");
    await mod.listAresExecutions({
      verdictId: "verdict-1",
      status: "done",
      targetEntity: "host",
      limit: 2,
    });
    await mod.listAresExecutions({ status: "all" });
    await mod.getAresExecution("exec-1");
    await mod.rollbackAresExecution("exec-1", { reason: "test" });
    await mod.getAresApprovals("verdict-1");
    await mod.getAresAudit({ verdictId: "verdict-1" });
    await mod.getAresAudit();
    await mod.verifyAresAudit();
    await mod.listAresXAuditRecords({
      verdictId: "verdict-1",
      eventType: "append",
      actor: "soc",
    });
    await mod.listAresXAuditRecords();
    await mod.verifyAresXAudit();
    await mod.promQuery("up");
    await mod.promRange({ q: "up", start: 1, end: 2 });
    await expect(mod.getWindowsNICs()).resolves.toEqual(["nic"]);
    api.get.mockResolvedValueOnce({ data: {} });
    await expect(mod.getWindowsNICs()).resolves.toEqual([]);
    await mod.getGpuSummary();
    await mod.getHostSummary();
    await mod.getSourceDiagnostics();
  });

  it("wraps getHealth failures", async () => {
    const mod = await loadModule();
    api.get.mockRejectedValueOnce(new Error("boom"));

    await expect(mod.getHealth()).rejects.toThrow("No se pudo consultar /health");
  });
});
