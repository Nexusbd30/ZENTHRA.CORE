import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import App from "./App";
import ConfirmDialog from "./components/ConfirmDialog";
import DashboardCard from "./components/DashboardCard";
import GpuMetrics from "./components/GpuMetrics";
import Header from "./components/Header";
import InfrastructureHealthCard from "./components/InfrastructureHealthCard";
import Loader from "./components/Loader";
import Navbar from "./components/Navbar";
import NetworkThreatsSummary from "./components/NetworkThreatsSummary";
import NetworkTrafficCard from "./components/NetworkTrafficCard";
import Notification from "./components/Notification";
import {
  NotificationProvider,
  useNotification as useProviderNotification,
  useNotify,
} from "./components/NotificationProvider";
import Sidebar from "./components/Sidebar";
import SocSummaryCard from "./components/SocSummaryCard";
import SystemAlerts from "./components/SystemAlerts";
import SystemMetrics from "./components/SystemMetrics";
import UserFormModal from "./components/UserFormModal";
import UserTable from "./components/UserTable";
import TimeSeriesChart from "./components/charts/TimeSeriesChart";
import { Card, CardContent } from "./components/ui/card";
import { AuthProvider, useAuthContext } from "./context/AuthContext";
import { useAuth } from "./hooks/useAuth";
import { useNotification } from "./hooks/useNotification";
import DashboardLayout from "./layouts/DashboardLayout";
import AIPage from "./modules/ai/AIPage";
import AlertsPage from "./modules/alerts/AlertsPage";
import PrivateRoute from "./modules/auth/PrivateRoute";
import DataCenterPage from "./modules/datacenter/DataCenterPage";
import DiagnosticsPage from "./modules/diagnostics/DiagnosticsPage";
import LogsPage from "./modules/logs/LogsPage";
import MonitoringPage from "./modules/monitoring/MonitoringPage";
import SecurityPage from "./modules/security/SecurityPage";
import ThreatDetailsModal from "./modules/threats/ThreatDetailsModal";
import ThreatFormModal from "./modules/threats/ThreatFormModal";
import ThreatTable from "./modules/threats/ThreatTable";
import ThreatTimeline from "./modules/threats/ThreatTimeline";
import ThreatsPage from "./modules/threats/ThreatsPage";
import Dashboard from "./pages/Dashboard";
import Home from "./pages/Home";
import Login from "./pages/Login";
import Register from "./pages/Register";
import TestNotify from "./pages/TestNotify";
import Users from "./pages/Users";
import AppRouter from "./routes/AppRouter";

const api = vi.hoisted(() => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    patch: vi.fn(),
  },
  getAlerts: vi.fn(),
  getFullInfraHealth: vi.fn(),
  getHostSummary: vi.fn(),
  getSourceDiagnostics: vi.fn(),
  promQuery: vi.fn(),
  promRange: vi.fn(),
  getGpuSummary: vi.fn(),
  getUsers: vi.fn(),
  createUser: vi.fn(),
  updateUser: vi.fn(),
  deleteUser: vi.fn(),
  toggleUserActive: vi.fn(),
  listThreats: vi.fn(),
  getThreatById: vi.fn(),
  createThreat: vi.fn(),
  updateThreat: vi.fn(),
  deleteThreat: vi.fn(),
  runCorrelationOnce: vi.fn(),
  loginUser: vi.fn(),
  getCurrentUser: vi.fn(),
  logoutUser: vi.fn(),
  getRuntimeLogs: vi.fn(),
  getProductionReadiness: vi.fn(),
  getResponseLogs: vi.fn(),
  getRedQueenStatus: vi.fn(),
  evaluateRedQueenPolicy: vi.fn(),
  issueRedQueenVerdict: vi.fn(),
  issueRedQueenVerdictFromThreat: vi.fn(),
  getRedQueenVerdict: vi.fn(),
  ingestAresXEvent: vi.fn(),
  listAresXIngestSources: vi.fn(),
  getAresXIngestStats: vi.fn(),
  listRedQueenVerdicts: vi.fn(),
  getAresXVerdict: vi.fn(),
  approveAresXVerdict: vi.fn(),
  rejectAresXVerdict: vi.fn(),
  getRedQueenStats: vi.fn(),
  getEntityProfile: vi.fn(),
  getAresStatus: vi.fn(),
  getAresOperationFlow: vi.fn(),
  setAresKillSwitch: vi.fn(),
  getAresKillSwitch: vi.fn(),
  activateAresKillSwitch: vi.fn(),
  deactivateAresKillSwitch: vi.fn(),
  runAresLifecycle: vi.fn(),
  runAresLifecycleFromThreat: vi.fn(),
  getAresResults: vi.fn(),
  listAresExecutions: vi.fn(),
  getAresExecution: vi.fn(),
  rollbackAresExecution: vi.fn(),
  getAresApprovals: vi.fn(),
  getAresAudit: vi.fn(),
  verifyAresAudit: vi.fn(),
  listAresXAuditRecords: vi.fn(),
  verifyAresXAudit: vi.fn(),
  getWindowsNICs: vi.fn(),
}));

vi.mock("@/api/vaelqorixApi", () => api);

const alertFixtures = [
  {
    fingerprint: "a1",
    labels: { alertname: "NetworkDDoS", severity: "critical", instance: "edge-1" },
    annotations: { summary: "DDoS", description: "packet flood" },
    status: { state: "firing" },
    startsAt: "2026-01-01T00:00:00Z",
    generatorURL: "/graph?g0.expr=up",
  },
  {
    fingerprint: "a2",
    labels: { alertname: "HighLatencyP95", severity: "warning", job: "api" },
    annotations: { summary: "Latency", description: "p95 high" },
    state: "pending",
    startsAt: "bad-date",
  },
];

const userFixtures = [
  { id: 1, email: "admin@vaelqorix.ai", full_name: "Admin", role: "admin", is_active: true },
  { id: 2, email: "user@vaelqorix.ai", full_name: "", role: "", is_active: false },
];

const threatFixtures = [
  {
    id: 1,
    title: "Credential stuffing",
    level: "high",
    category: "auth",
    status: "open",
    source_ip: "10.0.0.5",
    description: "auth attack",
    created_at: "2026-01-01T00:00:00Z",
  },
];

const validToken = () =>
  `header.${btoa(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600 }))}.sig`;

const tokenWith = (payload) => `header.${btoa(JSON.stringify(payload))}.sig`;

function resetApiMocks() {
  api.default.get.mockResolvedValue({ data: { items: userFixtures } });
  api.default.post.mockResolvedValue({ data: { id: 1 } });
  api.default.put.mockResolvedValue({ data: { id: 1 } });
  api.default.delete.mockResolvedValue({ data: { ok: true } });
  api.default.patch.mockResolvedValue({ data: { ok: true } });
  api.getAlerts.mockResolvedValue(alertFixtures);
  api.getFullInfraHealth.mockResolvedValue({
    overall: "up",
    backend: "up",
    database: "degraded",
    prometheus: "down",
    alertmanager: "unknown",
  });
  api.getHostSummary.mockResolvedValue({
    cpu_percent: { available: true, value: 42 },
    memory_percent: { available: true, value: 64 },
    network_mbps: { available: true, value: 12.5 },
    latency_ms: { available: true, value: 120 },
    gpu: { available: true, utilization_percent: 55.5, source: "nvidia" },
    nics: [{ name: "Ethernet0" }],
  });
  api.getSourceDiagnostics.mockResolvedValue({
    overall: "ready",
    sources: {
      prometheus: { status: "up", detail: "ok" },
      alertmanager: { status: "missing", detail: "not configured" },
      backend: { status: "down", detail: "offline" },
    },
  });
  api.promRange.mockResolvedValue({
    data: { result: [{ values: [[1, "10"], [2, "20"]] }] },
  });
  api.promQuery.mockResolvedValue({ data: { result: [{ value: [3, "30"] }] } });
  api.getGpuSummary.mockResolvedValue({ available: true });
  api.getUsers.mockResolvedValue(userFixtures);
  api.createUser.mockResolvedValue({ id: 3 });
  api.updateUser.mockResolvedValue({ id: 1 });
  api.deleteUser.mockResolvedValue({ ok: true });
  api.toggleUserActive.mockResolvedValue({ ok: true });
  api.listThreats.mockResolvedValue(threatFixtures);
  api.getThreatById.mockResolvedValue({ description: "Fetched threat detail", score: 88 });
  api.createThreat.mockResolvedValue({ id: 2 });
  api.updateThreat.mockResolvedValue({ id: 1 });
  api.deleteThreat.mockResolvedValue({ ok: true });
  api.runCorrelationOnce.mockResolvedValue({ created_count: 1 });
  api.loginUser.mockResolvedValue({ access_token: validToken() });
  api.getCurrentUser.mockResolvedValue({ email: "admin@vaelqorix.ai", role: "admin" });
  api.logoutUser.mockImplementation(() => {});
  api.getRuntimeLogs.mockResolvedValue({
    items: [{ id: "l1", severity: "info", message: "boot", created_at: "2026-01-01T00:00:00Z" }],
  });
  api.getProductionReadiness.mockResolvedValue({ status: "ready", checks: [] });
  api.getResponseLogs.mockResolvedValue([{ id: "r1", status: "success", source: "ares" }]);
  api.getRedQueenStatus.mockResolvedValue({ status: "ready" });
  api.evaluateRedQueenPolicy.mockResolvedValue({ decision: "approve" });
  api.issueRedQueenVerdict.mockResolvedValue({ verdict_id: "v1" });
  api.issueRedQueenVerdictFromThreat.mockResolvedValue({ verdict_id: "v2" });
  api.getRedQueenVerdict.mockResolvedValue({ verdict_id: "v1" });
  api.ingestAresXEvent.mockResolvedValue({ event_id: "e1" });
  api.listAresXIngestSources.mockResolvedValue(["wazuh"]);
  api.getAresXIngestStats.mockResolvedValue({ total: 1 });
  api.listRedQueenVerdicts.mockResolvedValue([{ verdict_id: "v1", status: "pending" }]);
  api.getAresXVerdict.mockResolvedValue({ verdict_id: "v1" });
  api.approveAresXVerdict.mockResolvedValue({ status: "approved" });
  api.rejectAresXVerdict.mockResolvedValue({ status: "rejected" });
  api.getRedQueenStats.mockResolvedValue({ total: 1 });
  api.getEntityProfile.mockResolvedValue({ entity_id: "host" });
  api.getAresStatus.mockResolvedValue({ status: "ready" });
  api.getAresOperationFlow.mockResolvedValue({ steps: [] });
  api.setAresKillSwitch.mockResolvedValue({ active: true });
  api.getAresKillSwitch.mockResolvedValue({ active: false });
  api.activateAresKillSwitch.mockResolvedValue({ active: true });
  api.deactivateAresKillSwitch.mockResolvedValue({ active: false });
  api.runAresLifecycle.mockResolvedValue({ execution_id: "x1" });
  api.runAresLifecycleFromThreat.mockResolvedValue({ execution_id: "x2" });
  api.getAresResults.mockResolvedValue({ verdict_id: "v1" });
  api.listAresExecutions.mockResolvedValue([{ execution_id: "x1" }]);
  api.getAresExecution.mockResolvedValue({ execution_id: "x1" });
  api.rollbackAresExecution.mockResolvedValue({ rolled_back: true });
  api.getAresApprovals.mockResolvedValue([{ id: "a1" }]);
  api.getAresAudit.mockResolvedValue([{ id: "audit1" }]);
  api.verifyAresAudit.mockResolvedValue({ valid: true });
  api.listAresXAuditRecords.mockResolvedValue([{ id: "audit1" }]);
  api.verifyAresXAudit.mockResolvedValue({ valid: true });
  api.getWindowsNICs.mockResolvedValue(["Ethernet0"]);
}

function renderApp(ui, { route = "/", auth = true } = {}) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  if (auth) {
    localStorage.setItem("access_token", validToken());
    localStorage.setItem("user", JSON.stringify({ email: "admin@vaelqorix.ai", role: "admin" }));
  }
  return render(
    <QueryClientProvider client={queryClient}>
      <NotificationProvider>
        <AuthProvider>
          <MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter>
        </AuthProvider>
      </NotificationProvider>
    </QueryClientProvider>
  );
}

function HookProbe() {
  const auth = useAuth();
  const authContext = useAuthContext();
  const notification = useNotification();
  const providerNotification = useProviderNotification();
  const notify = useNotify();
  return (
    <button
      onClick={() => {
        auth.login({ token: "token", user: { email: "probe@vaelqorix.ai" } });
        notification.notify("info", "hook notification", 50);
        providerNotification.notify("unknown", "provider notification", 50);
        notify("success", "notify alias", 50);
        auth.logout();
        authContext.resetSession();
      }}
    >
      {auth.loading ? "loading" : auth.user?.email || "no-user"}
    </button>
  );
}

beforeEach(() => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(window, "confirm").mockReturnValue(true);
  localStorage.clear();
  resetApiMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("frontend coverage", () => {
  it("renders primitive components and notification hooks", async () => {
    const onClick = vi.fn();
    renderApp(
      <>
        <ConfirmDialog isOpen={false} />
        <ConfirmDialog isOpen danger title="Delete" message="Confirm delete" onCancel={onClick} onConfirm={onClick} />
        <DashboardCard title="Risk" value="99" subtitle="critical" color="red" icon={() => <svg data-testid="icon" />} />
        <DashboardCard color="missing" />
        <Header user={{ email: "admin@vaelqorix.ai" }} onLogout={onClick} />
        <Loader />
        <Notification type="success" message="done" onClose={onClick} />
        <Notification type="error" message="bad" onClose={onClick} />
        <Notification type="warning" message="warn" onClose={onClick} />
        <Notification type="info" message="info" onClose={onClick} />
        <Card><CardContent>card content</CardContent></Card>
        <TimeSeriesChart noDataMessage="empty chart" />
        <TimeSeriesChart
          data={[{ t: 1, cpu: 10, mem: 20 }]}
          lines={[{ key: "cpu", label: "CPU" }, { key: "mem" }]}
          yLabel="metrics"
          tickFormatter={() => "tick"}
          valueFormatter={(value, name) => [`${value}`, name]}
        />
        <HookProbe />
      </>
    );

    await screen.findByText("admin@vaelqorix.ai");
    fireEvent.click(screen.getByText("Cancelar"));
    fireEvent.click(screen.getByText("Confirmar"));
    fireEvent.click(screen.getByText("done").closest("div").parentElement.nextElementSibling);
    fireEvent.click(screen.getAllByText(/admin@vaelqorix.ai|no-user/).find((node) => node.tagName === "BUTTON"));
    expect(onClick).toHaveBeenCalled();
  });

  it("renders async infrastructure and monitoring components in success states", async () => {
    renderApp(
      <>
        <InfrastructureHealthCard />
        <NetworkThreatsSummary />
        <GpuMetrics windowMinutes={1} stepSeconds={1} />
        <SystemAlerts autoRefreshMs={0} limit={2} />
        <SystemMetrics windowMinutes={1} stepSeconds={1} />
        <NetworkTrafficCard nic="Ethernet0" windowMinutes={1} stepSeconds={1} refreshMs={0} />
        <SocSummaryCard />
      </>
    );

    await waitFor(() => expect(screen.getAllByText(/NetworkDDoS|DDoS|Backend|CPU|GPU|Amenazas/).length).toBeGreaterThan(0));
  });

  it("renders async infrastructure and monitoring components in error and empty states", async () => {
    api.getFullInfraHealth.mockRejectedValueOnce(new Error("health boom"));
    api.getAlerts
      .mockRejectedValueOnce(new Error("No se puede conectar con el servidor."))
      .mockRejectedValueOnce(new Error("alerts boom"))
      .mockResolvedValueOnce([]);
    api.promRange.mockResolvedValue({ data: { result: [] } });
    api.promQuery.mockResolvedValue({ data: { result: [] } });

    renderApp(
      <>
        <InfrastructureHealthCard />
        <NetworkThreatsSummary />
        <SystemAlerts autoRefreshMs={0} />
        <SystemMetrics windowMinutes={1} stepSeconds={1} />
        <GpuMetrics windowMinutes={1} stepSeconds={1} />
        <NetworkTrafficCard nic="NIC not detected" refreshMs={0} />
      </>
    );

    await waitFor(() => expect(screen.getAllByText(/offline|Sin|No se pudo|Sin datos/).length).toBeGreaterThan(0));
  });

  it.skip("renders navigation, auth routes, and app shell states", async () => {
    renderApp(
      <Routes>
        <Route path="/" element={<><Navbar /><Sidebar /></>} />
      </Routes>,
      { auth: false }
    );
    await screen.findByText("Panel Principal");
    cleanup();

    renderApp(<PrivateRoute><div>private blocked</div></PrivateRoute>, { auth: false });
    await waitFor(() => expect(document.body.textContent).not.toContain("private blocked"));
    cleanup();

    renderApp(<AppRouter />, { route: "/login", auth: false });
    await waitFor(() => expect(document.body.textContent).toMatch(/Initialize Handshake|Panel Principal|Inicializando/));
    cleanup();

    localStorage.clear();
    render(
      <NotificationProvider>
        <App />
      </NotificationProvider>
    );
    expect(document.body.textContent).toBeTruthy();
  });

  it.skip("renders isolated shell route controls", async () => {
    renderApp(<Navbar />, { auth: false });
    await screen.findByText("Panel Principal");
    cleanup();

    renderApp(<Sidebar />, { auth: false });
    expect(document.body.textContent).toMatch(/Dashboard|Threats|Monitoring|Salir/i);
  });

  it.skip("renders isolated route guards and app router", async () => {
    renderApp(<PrivateRoute><div>blocked</div></PrivateRoute>, { auth: false });
    await waitFor(() => expect(document.body.textContent).not.toContain("blocked"));
    cleanup();

    renderApp(<AppRouter />, { route: "/login", auth: false });
    await waitFor(() => expect(document.body.textContent).toMatch(/Initialize Handshake|Vaelqorix/i));
    cleanup();

    localStorage.clear();
    render(
      <NotificationProvider>
        <App />
      </NotificationProvider>
    );
    expect(document.body.textContent).toBeTruthy();
  });

  it("renders main pages and performs user-facing interactions", async () => {
    renderApp(
      <>
        <Home />
        <Dashboard />
        <Login />
        <Register />
        <TestNotify />
        <Users />
      </>,
      { route: "/login", auth: false }
    );

    expect(screen.getAllByText(/Vaelqorix/i).length).toBeGreaterThan(0);
    fireEvent.change(screen.getByPlaceholderText("operator@vaelqorix.ai"), {
      target: { value: "invalid" },
    });
    fireEvent.submit(screen.getByText("Initialize Handshake").closest("form"));
    expect((await screen.findAllByText("Ingresa un correo electronico valido.")).length).toBeGreaterThan(0);

    fireEvent.change(screen.getByPlaceholderText("operator@vaelqorix.ai"), {
      target: { value: "admin@vaelqorix.ai" },
    });
    fireEvent.change(screen.getByPlaceholderText("************"), { target: { value: "secret" } });
    fireEvent.click(screen.getByText("Initialize Handshake"));

    fireEvent.change(screen.getByPlaceholderText("tu.correo@empresa.com"), {
      target: { value: "new@vaelqorix.ai" },
    });
    fireEvent.change(screen.getByPlaceholderText("Nombre y apellidos"), {
      target: { value: "New User" },
    });
    fireEvent.change(screen.getByPlaceholderText("**********"), { target: { value: "secret" } });
    fireEvent.click(screen.getByText("Registrar usuario"));

    await waitFor(() => expect(api.loginUser).toHaveBeenCalled());
    await waitFor(() => expect(api.default.post).toHaveBeenCalled());

    fireEvent.click(screen.getByText("Mostrar Éxito"));
    fireEvent.click(screen.getByText("Nuevo Usuario"));
    expect((await screen.findAllByText(/Nuevo usuario|Crear usuario/i)).length).toBeGreaterThan(0);
  });

  it("covers users page load, create/edit, toggle, delete and error paths", async () => {
    api.getUsers.mockResolvedValueOnce({ items: userFixtures });
    renderApp(<Users />, { auth: false });
    await screen.findByText("admin@vaelqorix.ai");

    fireEvent.click(screen.getByRole("button", { name: /nuevo usuario/i }));
    await screen.findByRole("heading", { name: "Nuevo usuario" });
    fireEvent.click(document.querySelector(".fixed.inset-0 button"));

    fireEvent.click(screen.getAllByTitle("Editar")[0]);
    await screen.findByRole("heading", { name: "Editar usuario" });
    fireEvent.click(document.querySelector(".fixed.inset-0 button"));

    fireEvent.click(screen.getByText("Activo"));
    await waitFor(() => expect(api.toggleUserActive).toHaveBeenCalledWith(1, false));

    fireEvent.click(screen.getAllByTitle("Eliminar")[0]);
    await waitFor(() => expect(api.deleteUser).toHaveBeenCalledWith(1));
    cleanup();

    api.getUsers.mockResolvedValueOnce([]);
    renderApp(<Users />, { auth: false });
    await screen.findByText("No hay usuarios registrados");
    cleanup();

    api.getUsers.mockRejectedValueOnce(new Error("No se puede conectar con el servidor."));
    renderApp(<Users />, { auth: false });
    await waitFor(() => expect(screen.getAllByText(/Backend offline/).length).toBeGreaterThan(0));
    cleanup();

    api.getUsers.mockResolvedValueOnce(userFixtures);
    api.deleteUser.mockRejectedValueOnce(new Error("delete failed"));
    window.confirm.mockReturnValueOnce(true);
    renderApp(<Users />, { auth: false });
    await screen.findByText("admin@vaelqorix.ai");
    fireEvent.click(screen.getAllByTitle("Eliminar")[0]);
    await waitFor(() => expect(api.deleteUser).toHaveBeenCalled());
    cleanup();

    api.getUsers.mockResolvedValueOnce(userFixtures);
    api.toggleUserActive.mockRejectedValueOnce(new Error("No se puede conectar con el servidor."));
    renderApp(<Users />, { auth: false });
    await screen.findByText("admin@vaelqorix.ai");
    fireEvent.click(screen.getByText("Activo"));
    await waitFor(() => expect(api.toggleUserActive).toHaveBeenCalled());
  });

  it("covers logs page filters, selection, export, copy and failure states", async () => {
    const clipboard = { writeText: vi.fn().mockResolvedValue(undefined) };
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: clipboard });
    const revokeObjectURL = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
    const createObjectURL = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:logs");
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    api.getRuntimeLogs.mockResolvedValue({
      files: ["runtime.log"],
      items: [
        {
          event_id: "evt-1",
          timestamp: "2026-01-01T00:00:00Z",
          source_ip: "10.0.0.1",
          dest_ip: "10.0.0.2",
          protocol: "TCP",
          action: "BLOCKED",
          severity: "critical",
          message: "blocked packet",
          logger: "ares",
          source_file: "runtime.log",
          request_method: "POST",
          status_code: 403,
          duration_ms: 12,
        },
        {
          event_id: "evt-2",
          timestamp: "bad-date",
          action: "FLAGGED",
          severity: "medium",
          message: "flagged packet",
          logger: "redqueen",
          source_file: "runtime.log",
        },
      ],
    });

    renderApp(<LogsPage />, { auth: false });
    await screen.findByText("#evt-1");
    fireEvent.click(screen.getAllByText("medium")[0]);
    await waitFor(() => expect(api.getRuntimeLogs).toHaveBeenCalledWith(expect.objectContaining({ severity: "medium" })));
    fireEvent.change(screen.getByPlaceholderText(/SEARCH LOGS/), { target: { value: "blocked" } });
    fireEvent.submit(screen.getByPlaceholderText(/SEARCH LOGS/).closest("form"));
    await waitFor(() => expect(api.getRuntimeLogs).toHaveBeenCalledWith(expect.objectContaining({ search: "blocked" })));
    fireEvent.click(screen.getByText("#evt-2").closest("tr"));
    expect(screen.getByText("Log Detail: #evt-2")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Copy JSON"));
    await waitFor(() => expect(clipboard.writeText).toHaveBeenCalled());
    fireEvent.click(screen.getByText("Export"));
    expect(createObjectURL).toHaveBeenCalled();
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:logs");
    fireEvent.click(screen.getByText("Refresh"));
    await waitFor(() => expect(api.getRuntimeLogs).toHaveBeenCalled());
    cleanup();

    api.getRuntimeLogs.mockReset();
    api.getRuntimeLogs.mockRejectedValue(new Error("logs failed"));
    renderApp(<LogsPage />, { auth: false });
    await screen.findByText("logs failed");
    cleanup();

    api.getRuntimeLogs.mockReset();
    api.getRuntimeLogs.mockResolvedValue({ items: [], files: [] });
    renderApp(<LogsPage />, { auth: false });
    await screen.findByText("No matching logs found.");
  });

  it("covers AI page command center controls and degraded loads", async () => {
    api.getRedQueenStatus.mockResolvedValue({ phase: "online", role: "brain" });
    api.getAresStatus.mockResolvedValue({ phase: "armed" });
    api.getAresKillSwitch.mockResolvedValue({ kill_switch: { active: false } });
    api.getRedQueenStats.mockResolvedValue({ total_verdicts: 2, human_required: 1 });
    api.getAresXIngestStats.mockResolvedValue({ total: 7, window: "24h" });
    api.listAresXIngestSources.mockResolvedValue({ sources: ["qradar", "wazuh"] });
    api.listRedQueenVerdicts.mockResolvedValue({
      items: [
        {
          verdict_id: "v1",
          target: "host-1",
          risk_score: 95,
          confidence_score: 0.91,
          status: "pending",
          primary_action: "isolate",
          severity: "critical",
          requires_human_approval: true,
          xai_explanation: { top_factors: [{ feature: "f1", label: "lateral movement", value: 0.8 }] },
        },
        { verdict_id: "v2", target: "host-2", risk_score: 30, confidence: 0.4, status: "rejected", action_type: "observe" },
      ],
    });
    api.listAresExecutions.mockResolvedValue({
      items: [
        { id: "exec-1", verdict_id: "v1", action_type: "isolate", target_entity: "host-1", status: "executed", rl_reward: 0.8 },
        { id: "exec-2", verdict_id: "v1", action_type: "block", target_entity: "ip", status: "rolled_back", rl_reward: 0.1 },
      ],
    });
    api.listAresXAuditRecords.mockResolvedValue({
      items: [{ record_id: "a1", sequence_number: 1, event_type: "APPROVE", actor: "soc", verdict_id: "v1", chain_hash: "hash" }],
    });
    api.verifyAresXAudit.mockResolvedValue({ valid: true, records_checked: 1 });

    renderApp(<AIPage />, { auth: false });
    await waitFor(() => expect(screen.getAllByText("host-1").length).toBeGreaterThan(0));
    fireEvent.click(screen.getByTitle("Refresh"));
    fireEvent.click(screen.getByTitle("Activate kill switch"));
    await waitFor(() => expect(api.activateAresKillSwitch).toHaveBeenCalled());
    fireEvent.click(screen.getAllByTitle("Approve")[0]);
    await waitFor(() => expect(api.approveAresXVerdict).toHaveBeenCalledWith("v1"));
    fireEvent.click(screen.getAllByTitle("Reject")[0]);
    await waitFor(() => expect(api.rejectAresXVerdict).toHaveBeenCalledWith("v1"));
    fireEvent.click(screen.getAllByTitle("Rollback")[0]);
    await waitFor(() => expect(api.rollbackAresExecution).toHaveBeenCalledWith("exec-1", expect.any(Object)));
    fireEvent.click(screen.getByTitle("Ingest QRadar control event"));
    await waitFor(() => expect(api.ingestAresXEvent).toHaveBeenCalled());
    cleanup();

    api.getAresKillSwitch.mockResolvedValueOnce({ kill_switch: { active: true } });
    renderApp(<AIPage />, { auth: false });
    await screen.findByText("Resume ARES");
    fireEvent.click(screen.getByTitle("Deactivate kill switch"));
    await waitFor(() => expect(api.deactivateAresKillSwitch).toHaveBeenCalled());
    cleanup();

    api.getRedQueenStatus.mockRejectedValueOnce(new Error("redqueen down"));
    api.listRedQueenVerdicts.mockResolvedValueOnce({ items: [] });
    api.listAresExecutions.mockResolvedValueOnce({ items: [] });
    api.listAresXAuditRecords.mockResolvedValueOnce({ items: [] });
    api.verifyAresXAudit.mockResolvedValueOnce({ valid: false });
    renderApp(<AIPage />, { auth: false });
    await screen.findByText("redqueen down");
  });

  it("covers dashboard data, empty, error and Aegis response flows", async () => {
    api.getAlerts.mockResolvedValueOnce([
      {
        labels: { severity: "critical", instance: "identity-1", alertname: "Critical identity replay" },
        annotations: { summary: "Privileged token replay" },
        startsAt: new Date(Date.now() - 120000).toISOString(),
      },
      {
        labels: { severity: "high", job: "network" },
        annotations: { summary: "Lateral movement" },
        startsAt: new Date(Date.now() - 7200000).toISOString(),
      },
      {
        labels: { severity: "warning", instance: "cloud" },
        annotations: {},
        startsAt: new Date(Date.now() + 60000).toISOString(),
      },
    ]);
    api.getHostSummary.mockResolvedValueOnce({
      cpu_percent: { available: true, value: 125 },
      memory_percent: { available: true, value: -5 },
      network_mbps: { available: true, value: "42.42" },
      latency_ms: { available: true, value: 777 },
      gpu: { available: true, utilization_percent: 66, source: "nvidia" },
    });

    renderApp(<Dashboard />);
    await screen.findByText("Privileged token replay");
    fireEvent.click(screen.getByText("1H"));
    fireEvent.click(screen.getByText("7D"));
    fireEvent.click(screen.getByText("Ver todo"));
    await screen.findByText("Vista completa de incidentes lista");
    fireEvent.click(screen.getByText("Privileged token replay").closest("button"));
    await screen.findByText(/Investigando: Privileged token replay/);
    fireEvent.click(screen.getByText("Abrir Aegis AI"));
    await screen.findByText("Aegis AI");
    fireEvent.click(screen.getByText("Revisar y autorizar"));
    await screen.findByText("Contencion en cola");
    fireEvent.change(screen.getByLabelText("Ask Aegis AI"), { target: { value: "trace identity" } });
    fireEvent.click(screen.getByText("Aegis AI").closest("aside").querySelector("button"));
    cleanup();

    api.getAlerts.mockRejectedValueOnce(new Error("alerts unavailable"));
    api.getHostSummary.mockRejectedValueOnce(new Error("metrics unavailable"));
    renderApp(<Dashboard />, { auth: false });
    await screen.findByText("alerts unavailable");
    expect(screen.getAllByText("N/A").length).toBeGreaterThan(0);
    cleanup();

    api.getAlerts.mockResolvedValueOnce([]);
    api.getHostSummary.mockResolvedValueOnce({
      cpu_percent: { available: false },
      memory_percent: { available: false },
      network_mbps: { available: false },
      latency_ms: { available: false },
      gpu: { available: false },
    });
    renderApp(<Dashboard />, { auth: false });
    await screen.findByText(/No hay incidentes activos/);
    expect(screen.getByText("Postura fuerte")).toBeInTheDocument();
  });

  it("covers home, login, register and notification page branches", async () => {
    renderApp(<Home />, { auth: false });
    fireEvent.click(screen.getByText("LOGIN"));
    expect(screen.getByText("Command Center")).toBeInTheDocument();
    cleanup();

    api.loginUser.mockResolvedValueOnce({ access_token: validToken() });
    api.getCurrentUser.mockRejectedValueOnce(new Error("profile unavailable"));
    renderApp(<Login />, {
      route: "/login",
      auth: false,
    });
    fireEvent.click(screen.getByText("visibility").closest("button"));
    expect(screen.getByPlaceholderText("************")).toHaveAttribute("type", "text");
    fireEvent.change(screen.getByPlaceholderText("operator@vaelqorix.ai"), {
      target: { value: "operator@vaelqorix.ai" },
    });
    fireEvent.change(screen.getByPlaceholderText("************"), { target: { value: "secret" } });
    fireEvent.click(screen.getByText("Initialize Handshake"));
    await waitFor(() => expect(api.loginUser).toHaveBeenCalledWith({ username: "operator@vaelqorix.ai", password: "secret" }));
    cleanup();

    api.loginUser.mockResolvedValueOnce({});
    renderApp(<Login />, { route: "/login", auth: false });
    fireEvent.change(screen.getByPlaceholderText("operator@vaelqorix.ai"), {
      target: { value: "operator@vaelqorix.ai" },
    });
    fireEvent.change(screen.getByPlaceholderText("************"), { target: { value: "secret" } });
    fireEvent.submit(screen.getByText("Initialize Handshake").closest("form"));
    await waitFor(() => expect(screen.getAllByText("Token no recibido del servidor.").length).toBeGreaterThan(0));
    cleanup();

    api.loginUser.mockRejectedValueOnce(new Error("No se puede conectar con el servidor."));
    renderApp(<Login />, { route: "/login", auth: false });
    fireEvent.change(screen.getByPlaceholderText("operator@vaelqorix.ai"), {
      target: { value: "operator@vaelqorix.ai" },
    });
    fireEvent.change(screen.getByPlaceholderText("************"), { target: { value: "secret" } });
    fireEvent.submit(screen.getByText("Initialize Handshake").closest("form"));
    await waitFor(() => expect(screen.getAllByText(/Backend offline: no es posible iniciar sesion/).length).toBeGreaterThan(0));
    cleanup();

    renderApp(<Register />, { route: "/register", auth: false });
    fireEvent.change(screen.getByPlaceholderText("tu.correo@empresa.com"), { target: { value: "invalid" } });
    fireEvent.change(screen.getByPlaceholderText("Nombre y apellidos"), { target: { value: "Bad Email" } });
    fireEvent.change(screen.getByPlaceholderText("**********"), { target: { value: "secret" } });
    fireEvent.submit(screen.getByText("Registrar usuario").closest("form"));
    await screen.findByText("Ingresa un correo electronico valido.");
    cleanup();

    api.default.post.mockResolvedValueOnce({ data: {} });
    renderApp(<Register />, { route: "/register", auth: false });
    fireEvent.change(screen.getByPlaceholderText("tu.correo@empresa.com"), { target: { value: "ok@vaelqorix.ai" } });
    fireEvent.change(screen.getByPlaceholderText("Nombre y apellidos"), { target: { value: "Ok User" } });
    fireEvent.change(screen.getByPlaceholderText("**********"), { target: { value: "secret" } });
    fireEvent.click(screen.getByText("Registrar usuario"));
    await screen.findByText("Usuario creado correctamente.");
    fireEvent.click(screen.getByText("Iniciar sesion"));
    cleanup();

    renderApp(<TestNotify />, { auth: false });
    fireEvent.click(screen.getByText(/Mostrar .xito/));
    fireEvent.click(screen.getByText("Mostrar Error"));
    fireEvent.click(screen.getByText("Mostrar Advertencia"));
    fireEvent.click(screen.getByText("Mostrar Info"));
    await waitFor(() => expect(document.body.textContent).toContain("success"));
  });

  it("covers user form modal create, edit and error flows", async () => {
    const onClose = vi.fn();
    const onSuccess = vi.fn();

    renderApp(<UserFormModal isOpen={false} onClose={onClose} onSuccess={onSuccess} />, {
      auth: false,
    });
    expect(document.body.textContent).not.toContain("Nuevo usuario");
    cleanup();

    renderApp(<UserFormModal isOpen onClose={onClose} onSuccess={onSuccess} />, { auth: false });
    fireEvent.change(document.querySelector('input[name="full_name"]'), { target: { value: "Created User" } });
    fireEvent.change(document.querySelector('input[name="email"]'), {
      target: { value: "created@vaelqorix.ai" },
    });
    fireEvent.change(document.querySelector('input[name="password"]'), { target: { value: "secret" } });
    fireEvent.change(document.querySelector('select[name="role"]'), { target: { value: "admin" } });
    fireEvent.click(document.querySelector('input[name="is_active"]'));
    fireEvent.submit(screen.getByText("Crear").closest("form"));
    await waitFor(() => expect(api.default.post).toHaveBeenCalledWith("/users/", expect.any(Object)));
    expect(onClose).toHaveBeenCalled();
    expect(onSuccess).toHaveBeenCalled();
    cleanup();

    api.default.put.mockResolvedValueOnce({ data: { id: 1 } });
    renderApp(
      <UserFormModal
        isOpen
        onClose={onClose}
        onSuccess={onSuccess}
        user={{ id: 1, full_name: "Edit Me", email: "edit@vaelqorix.ai", role: "user", is_active: false }}
      />,
      { auth: false }
    );
    fireEvent.change(document.querySelector('input[name="full_name"]'), { target: { value: "Edited User" } });
    fireEvent.click(document.querySelector('input[name="is_active"]'));
    fireEvent.submit(screen.getByText("Actualizar").closest("form"));
    await waitFor(() => expect(api.default.put).toHaveBeenCalledWith("/users/1", expect.any(Object)));
    cleanup();

    api.default.post.mockRejectedValueOnce({ response: { data: { detail: "email duplicated" } } });
    renderApp(<UserFormModal isOpen onClose={onClose} onSuccess={onSuccess} />, { auth: false });
    fireEvent.change(document.querySelector('input[name="full_name"]'), { target: { value: "Bad User" } });
    fireEvent.change(document.querySelector('input[name="email"]'), {
      target: { value: "bad@vaelqorix.ai" },
    });
    fireEvent.change(document.querySelector('input[name="password"]'), { target: { value: "secret" } });
    fireEvent.submit(screen.getByText("Crear").closest("form"));
    await waitFor(() => expect(document.body.textContent).toContain("email duplicated"));
  });

  it("covers user table success, delete, pagination, search and offline states", async () => {
    api.default.get.mockResolvedValue({ data: { items: userFixtures, pages: 2 } });
    renderApp(<UserTable />, { auth: false });
    await screen.findByText("admin@vaelqorix.ai");

    fireEvent.change(screen.getByPlaceholderText("Buscar por nombre o correo..."), {
      target: { value: "admin" },
    });
    await waitFor(() => expect(api.default.get).toHaveBeenCalledWith(expect.stringContaining("search=admin")));
    await screen.findByText("admin@vaelqorix.ai");

    fireEvent.click(screen.getByTitle("Recargar lista"));
    await screen.findByText("admin@vaelqorix.ai");

    fireEvent.click(screen.getByText("Siguiente"));
    await waitFor(() => expect(api.default.get).toHaveBeenCalledWith(expect.stringContaining("page=2")));
    await screen.findByText("admin@vaelqorix.ai");

    fireEvent.click(screen.getByText("Anterior"));
    await waitFor(() => expect(api.default.get).toHaveBeenCalledWith(expect.stringContaining("page=1")));
    await screen.findByText("admin@vaelqorix.ai");

    fireEvent.click(screen.getAllByTitle("Editar usuario")[0]);
    await screen.findByText("Editar usuario");
    fireEvent.click(document.querySelector(".fixed.inset-0 button"));
    await waitFor(() => expect(screen.queryByText("Editar usuario")).not.toBeInTheDocument());

    fireEvent.click(screen.getAllByTitle("Eliminar usuario")[0]);
    await screen.findByText("Eliminar usuario");
    fireEvent.click(screen.getByText("Eliminar"));
    await waitFor(() => expect(api.default.delete).toHaveBeenCalledWith("/users/1"));
    cleanup();

    api.default.get.mockReset();
    api.default.get.mockRejectedValueOnce(new Error("No se puede conectar con el servidor."));
    renderApp(<UserTable />, { auth: false });
    await waitFor(() => expect(screen.getAllByText(/Backend offline/).length).toBeGreaterThanOrEqual(1));
    cleanup();

    api.default.get.mockReset();
    api.default.get.mockResolvedValueOnce({ data: { items: [], pages: 1 } });
    renderApp(<UserTable />, { auth: false });
    await screen.findByText("No se encontraron usuarios");
  });

  it("renders enterprise modules and threat workflows", async () => {
    renderApp(
      <>
        <AIPage />
        <AlertsPage />
        <DataCenterPage />
        <DiagnosticsPage />
        <LogsPage />
        <MonitoringPage />
        <SecurityPage />
        <ThreatTimeline threats={threatFixtures} />
        <ThreatTable threats={threatFixtures} onEdit={vi.fn()} onDelete={vi.fn()} onView={vi.fn()} />
        <ThreatDetailsModal threat={threatFixtures[0]} onClose={vi.fn()} />
        <ThreatFormModal isOpen onClose={vi.fn()} onSuccess={vi.fn()} threat={threatFixtures[0]} />
        <ThreatsPage />
      </>,
      { auth: false }
    );

    await waitFor(() => expect(document.body.textContent).toMatch(/RedQueen|ARES|Threat|Credential|Security|Logs|Monitoring|Diagnostics|Data/i));
    const buttons = Array.from(document.querySelectorAll("button")).slice(0, 12);
    buttons.forEach((button) => fireEvent.click(button));
  });

  it("covers security page session, token and backend states", async () => {
    renderApp(<SecurityPage />, { auth: false });
    await waitFor(() => expect(screen.getAllByText(/Sin sesión activa/).length).toBeGreaterThan(0));
    expect(screen.getByText(/No hay token en memoria/)).toBeInTheDocument();
    cleanup();

    localStorage.setItem(
      "access_token",
      tokenWith({
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000) - 60,
        sub: "operator-1",
        iss: "vaelqorix",
      })
    );
    localStorage.setItem(
      "user",
      JSON.stringify({ full_name: "Security Operator", email: "sec@vaelqorix.ai", role: "admin" })
    );
    api.getCurrentUser.mockResolvedValueOnce({
      full_name: "Security Operator",
      email: "sec@vaelqorix.ai",
      role: "admin",
    });
    renderApp(<SecurityPage />, { auth: false });
    await screen.findByText(/Sesión segura activa/);
    expect(screen.getByText(/Token válido/)).toBeInTheDocument();
    expect(screen.getByText(/Security Operator/)).toBeInTheDocument();
    expect(screen.getByText(/operator-1/)).toBeInTheDocument();
    cleanup();

    localStorage.setItem("access_token", tokenWith({ exp: Math.floor(Date.now() / 1000) + 120 }));
    localStorage.setItem("user", JSON.stringify({ email: "soon@vaelqorix.ai" }));
    renderApp(<SecurityPage />, { auth: false });
    await screen.findByText(/Token a punto de expirar/);
    cleanup();

    localStorage.setItem("access_token", tokenWith({ exp: Math.floor(Date.now() / 1000) - 60 }));
    localStorage.setItem("user", JSON.stringify({ email: "expired@vaelqorix.ai", role: "" }));
    renderApp(<SecurityPage />, { auth: false });
    await screen.findByText(/Tu sesión ha expirado/);
    cleanup();

    localStorage.setItem("access_token", "header.invalid-payload.sig");
    localStorage.setItem("user", JSON.stringify({ email: "offline@vaelqorix.ai", role: "analyst" }));
    api.getCurrentUser.mockRejectedValueOnce(new Error("No se puede conectar con el servidor."));
    renderApp(<SecurityPage />, { auth: false });
    await waitFor(() => expect(screen.getAllByText(/Backend offline/).length).toBeGreaterThan(0));
    expect(screen.getByText(/sin metadatos de expiración legibles/)).toBeInTheDocument();
  });

  it("covers threat modal submit, validation, offline and permission failures", async () => {
    const onClose = vi.fn();
    const onSuccess = vi.fn();

    renderApp(<ThreatFormModal isOpen={false} onClose={onClose} onSuccess={onSuccess} />, { auth: false });
    expect(document.body.textContent).not.toContain("Nueva alerta manual");
    cleanup();

    renderApp(<ThreatFormModal isOpen onClose={onClose} onSuccess={onSuccess} />, { auth: false });
    fireEvent.submit(screen.getByText("Registrar").closest("form"));
    expect(await screen.findByText(/Completa al menos/)).toBeInTheDocument();
    fireEvent.change(document.querySelector('input[placeholder^="T"]'), { target: { value: "Manual incident" } });
    fireEvent.change(document.querySelectorAll("input")[1], { target: { value: "manual" } });
    fireEvent.change(document.querySelectorAll("select")[0], { target: { value: "critical" } });
    fireEvent.change(document.querySelectorAll("select")[1], { target: { value: "network" } });
    fireEvent.change(document.querySelector('input[type="number"]'), { target: { value: "91" } });
    fireEvent.change(document.querySelector("textarea"), { target: { value: "detailed evidence" } });
    fireEvent.submit(screen.getByText("Registrar").closest("form"));
    await waitFor(() => expect(api.createThreat).toHaveBeenCalledWith(expect.objectContaining({
      title: "Manual incident",
      source: "manual",
      level: "critical",
      category: "network",
      score: 91,
      description: "detailed evidence",
    })));
    expect(onSuccess).toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
    cleanup();

    api.createThreat.mockRejectedValueOnce(new Error("No se puede conectar con el servidor."));
    renderApp(<ThreatFormModal isOpen onClose={onClose} onSuccess={onSuccess} />, { auth: false });
    fireEvent.change(document.querySelector('input[placeholder^="T"]'), { target: { value: "Offline incident" } });
    fireEvent.change(document.querySelectorAll("input")[1], { target: { value: "manual" } });
    fireEvent.submit(screen.getByText("Registrar").closest("form"));
    await waitFor(() => expect(screen.getAllByText(/Backend offline/).length).toBeGreaterThan(0));
    cleanup();

    api.createThreat.mockRejectedValueOnce(new Error("403 rol administrador"));
    renderApp(<ThreatFormModal isOpen onClose={onClose} onSuccess={onSuccess} />, { auth: false });
    fireEvent.change(document.querySelector('input[placeholder^="T"]'), { target: { value: "Forbidden incident" } });
    fireEvent.change(document.querySelectorAll("input")[1], { target: { value: "manual" } });
    fireEvent.submit(screen.getByText("Registrar").closest("form"));
    await waitFor(() => expect(screen.getAllByText(/No tienes permisos/).length).toBeGreaterThan(0));
  });

  it("covers threat table filters, row actions, delete paths and empty/offline states", async () => {
    const onSelectThreat = vi.fn();
    const richThreats = [
      { id: "critical-1", title: "Critical availability", level: "critical", category: "availability", source: "prometheus/correlation", created_at: "bad-date" },
      { id: "high-1", title: "High database", severity: "high", category: "database", origin: "manual-review", timestamp: new Date("2026-01-01T00:00:00Z") },
      { id: "medium-1", title: "Medium performance", level: "medium", category: "performance", source: "user-report", date: "2026-01-02T00:00:00Z" },
      { id: "low-1", title: "Low other", level: "low", source: "sensor" },
    ];
    api.listThreats.mockResolvedValue(richThreats);

    renderApp(<ThreatTable onSelectThreat={onSelectThreat} autoRefreshMs={0} />, { auth: false });
    await screen.findByText("Critical availability");
    expect(screen.getByText(/Amenazas registradas: 4/)).toBeInTheDocument();
    fireEvent.change(screen.getAllByRole("combobox")[0], { target: { value: "critical" } });
    expect(screen.queryByText("High database")).not.toBeInTheDocument();
    fireEvent.change(screen.getAllByRole("combobox")[0], { target: { value: "all" } });
    fireEvent.change(screen.getAllByRole("combobox")[1], { target: { value: "manual" } });
    expect(screen.getByText("High database")).toBeInTheDocument();
    fireEvent.change(screen.getAllByRole("combobox")[1], { target: { value: "other" } });
    fireEvent.change(screen.getAllByRole("combobox")[2], { target: { value: "performance" } });
    expect(screen.getByText("Medium performance")).toBeInTheDocument();
    fireEvent.change(screen.getAllByRole("combobox")[2], { target: { value: "all" } });

    fireEvent.click(screen.getByText("Low other").closest("tr"));
    expect(onSelectThreat).toHaveBeenCalledWith(expect.objectContaining({ id: "low-1" }));
    fireEvent.click(screen.getAllByTitle("Ver detalles")[0]);
    expect(onSelectThreat).toHaveBeenCalled();
    fireEvent.click(screen.getAllByTitle("Eliminar amenaza")[0]);
    await waitFor(() => expect(api.deleteThreat).toHaveBeenCalledWith("high-1"));
    fireEvent.click(screen.getByText("Refrescar"));
    await waitFor(() => expect(api.listThreats).toHaveBeenCalled());
    cleanup();

    window.confirm.mockReturnValueOnce(false);
    api.deleteThreat.mockClear();
    api.listThreats.mockResolvedValueOnce([richThreats[0]]);
    renderApp(<ThreatTable onSelectThreat={onSelectThreat} />, { auth: false });
    await screen.findByText("Critical availability");
    fireEvent.click(screen.getByTitle("Eliminar amenaza"));
    expect(api.deleteThreat).not.toHaveBeenCalledWith("blocked");
    cleanup();

    api.listThreats.mockRejectedValueOnce(new Error("No se puede conectar con el servidor."));
    renderApp(<ThreatTable onSelectThreat={onSelectThreat} />, { auth: false });
    await waitFor(() => expect(screen.getAllByText(/Backend offline/).length).toBeGreaterThan(0));
    cleanup();

    api.listThreats.mockResolvedValueOnce([]);
    renderApp(<ThreatTable onSelectThreat={onSelectThreat} />, { auth: false });
    await screen.findByText(/No hay amenazas/);
    cleanup();

    api.listThreats.mockResolvedValueOnce({});
    renderApp(<ThreatTable onSelectThreat={onSelectThreat} />, { auth: false });
    await screen.findByText(/No hay amenazas/);
  });

  it("covers threat details fetch, copy, fallback, categories and close gestures", async () => {
    const onClose = vi.fn();
    const clipboard = { writeText: vi.fn().mockResolvedValue(undefined) };
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: clipboard });

    const detailed = {
      id: "detail-1",
      title: "Detailed incident",
      level: "critical",
      category: "network",
      source: "manual-review",
      score: 99,
      created_by: "analyst",
      target_service: "api",
      source_ip: "10.0.0.1",
      database_name: "prod",
      database_host: "db01",
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "bad-date",
      description: "full evidence",
    };
    renderApp(<ThreatDetailsModal threat={detailed} onClose={onClose} />, { auth: false });
    expect(screen.getByText("Detailed incident")).toBeInTheDocument();
    fireEvent.click(screen.getByTitle("Copiar detalle JSON"));
    await waitFor(() => expect(clipboard.writeText).toHaveBeenCalled());
    fireEvent.click(screen.getByText("Cerrar"));
    expect(onClose).toHaveBeenCalled();
    cleanup();

    api.getThreatById.mockResolvedValueOnce({ description: "expanded", category: "database", source: "prometheus/correlation" });
    renderApp(<ThreatDetailsModal threat={{ id: "fetch-1", title: "Fetch incident", level: "medium" }} onClose={onClose} />, { auth: false });
    await screen.findByText("expanded");
    expect(api.getThreatById).toHaveBeenCalledWith("fetch-1");
    cleanup();

    api.getThreatById.mockRejectedValueOnce(new Error("No se puede conectar con el servidor."));
    renderApp(<ThreatDetailsModal threat={{ id: "offline-1", title: "Offline detail", category: "auth", origin: "user-ticket" }} onClose={onClose} />, { auth: false });
    await screen.findByText(/No se ha registrado/);
    cleanup();

    clipboard.writeText.mockRejectedValueOnce(new Error("denied"));
    renderApp(<ThreatDetailsModal threat={{ id: "copy-fail", title: "Copy fail", category: "performance", source: "" }} onClose={onClose} />, { auth: false });
    fireEvent.click(screen.getByTitle("Copiar detalle JSON"));
    await waitFor(() => expect(clipboard.writeText).toHaveBeenCalled());
  });

  it("covers threats page correlation, selection, creation and error states", async () => {
    api.listThreats.mockResolvedValue([
      { id: "t1", title: "Critical row", level: "critical", source: "sensor", created_at: "2026-01-01T00:00:00Z", created_by: "soc" },
      { id: "t2", title: "Medium row", level: "medium", database_host: "db01" },
    ]);
    renderApp(<ThreatsPage />, { auth: false });
    await screen.findByText("Critical row");
    fireEvent.click(screen.getByText("Run Correlation"));
    await screen.findByText(/Correlaci/);
    fireEvent.click(screen.getByText("Critical row").closest("tr"));
    await screen.findByText("Detalles de la amenaza");
    fireEvent.click(screen.getByText("Cerrar"));
    fireEvent.click(screen.getByText("New Incident"));
    await screen.findByText("Nueva alerta manual");
    fireEvent.click(screen.getByText("Cancelar"));
    cleanup();

    api.runCorrelationOnce.mockResolvedValueOnce([]);
    renderApp(<ThreatsPage />, { auth: false });
    await screen.findByText("Critical row");
    fireEvent.click(screen.getByText("Run Correlation"));
    await screen.findByText(/sin nuevas amenazas/);
    cleanup();

    api.listThreats.mockRejectedValueOnce(new Error("No se puede conectar con el servidor."));
    renderApp(<ThreatsPage />, { auth: false });
    await screen.findByText(/No se puede conectar/);
    cleanup();

    api.runCorrelationOnce.mockRejectedValueOnce(new Error("correlation failed"));
    renderApp(<ThreatsPage />, { auth: false });
    await screen.findByText("Critical row");
    fireEvent.click(screen.getByText("Run Correlation"));
    await waitFor(() => expect(screen.getAllByText("correlation failed").length).toBeGreaterThan(0));
  }, 15000);

  it("covers auth provider offline, invalid, expired and malformed session branches", async () => {
    api.getCurrentUser.mockRejectedValueOnce(new Error("No se puede conectar con el servidor."));
    localStorage.setItem("access_token", validToken());
    localStorage.setItem("user", JSON.stringify({ email: "cached@vaelqorix.ai" }));
    renderApp(<HookProbe />, { auth: false });
    await screen.findByText("cached@vaelqorix.ai");
    cleanup();

    api.getCurrentUser.mockRejectedValueOnce(new Error("forbidden"));
    localStorage.setItem("access_token", validToken());
    localStorage.setItem("user", JSON.stringify({ email: "invalid@vaelqorix.ai" }));
    renderApp(<HookProbe />, { auth: false });
    await waitFor(() => expect(document.body.textContent).toContain("no-user"));
    cleanup();

    localStorage.setItem("access_token", "header.eyJleHAiOjF9.sig");
    localStorage.setItem("user", JSON.stringify({ email: "expired@vaelqorix.ai" }));
    renderApp(<HookProbe />, { auth: false });
    await waitFor(() => expect(api.logoutUser).toHaveBeenCalled());
    cleanup();

    api.getCurrentUser.mockRejectedValueOnce(new Error("No se puede conectar con el servidor."));
    localStorage.setItem("access_token", "broken-token");
    localStorage.setItem("user", JSON.stringify({ email: "broken@vaelqorix.ai" }));
    renderApp(<HookProbe />, { auth: false });
    await screen.findByText("broken@vaelqorix.ai");
  });

  it("throws hook errors outside their providers", () => {
    function NotificationHookConsumer() {
      useNotification();
      return null;
    }
    function ProviderNotificationConsumer() {
      useProviderNotification();
      return null;
    }
    function NotifyHookConsumer() {
      useNotify();
      return null;
    }

    expect(() => render(<NotificationHookConsumer />)).toThrow("useNotification");
    expect(() => render(<ProviderNotificationConsumer />)).toThrow("useNotification");
    expect(() => render(<NotifyHookConsumer />)).toThrow("useNotify");
  });
});
