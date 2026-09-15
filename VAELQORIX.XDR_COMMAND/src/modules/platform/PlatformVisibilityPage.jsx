import { createElement, useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  Bot,
  Boxes,
  CheckCircle2,
  CloudCog,
  Code2,
  DatabaseZap,
  FileCheck2,
  FileClock,
  Network,
  Play,
  RefreshCw,
  Route,
  ScanSearch,
  ServerCog,
  ShieldAlert,
  ShieldCheck,
  Workflow,
  XCircle,
} from "lucide-react";

import {
  getAresStatus,
  getCasesStatus,
  getCodeIntelligenceStatus,
  getComplianceEvidence,
  getConnectors,
  getDetectionStatus,
  getDnsFirewallStatus,
  getFullInfraHealth,
  getIdentityProviders,
  getIngestionStatus,
  getPlatformMap,
  getPlatformReadiness,
  getPlaybooks,
  getRedQueenStatus,
  getRuntimeStatus,
  getSecOpsStatus,
  getSensorsStatus,
  listAresXAuditRecords,
} from "@/api/vaelqorixApi";

const REFRESH_MS = 30000;

const MODULES = [
  { key: "platform", label: "Platform core", group: "Plataforma", endpoint: "GET /api/v1/platform/readiness", icon: Boxes, load: getPlatformReadiness },
  { key: "monitoring", label: "Monitoring", group: "Plataforma", endpoint: "GET /monitoring/health/full", icon: Activity, load: getFullInfraHealth },
  { key: "runtime", label: "Runtime", group: "Plataforma", endpoint: "GET /api/v1/runtime/status", icon: ServerCog, load: getRuntimeStatus },
  { key: "code", label: "Code intelligence", group: "Plataforma", endpoint: "GET /api/v1/code-intelligence/status", icon: Code2, load: getCodeIntelligenceStatus },
  { key: "ingestion", label: "Ingestion", group: "Datos y deteccion", endpoint: "GET /api/v1/ingestion/status", icon: DatabaseZap, load: getIngestionStatus },
  { key: "sensors", label: "Sensors", group: "Datos y deteccion", endpoint: "GET /api/v1/sensors/status", icon: ScanSearch, load: getSensorsStatus },
  { key: "detection", label: "Detection engine", group: "Datos y deteccion", endpoint: "GET /api/v1/detection/status", icon: ShieldAlert, load: getDetectionStatus },
  { key: "identity", label: "Identity defense", group: "Datos y deteccion", endpoint: "GET /api/v1/identity/providers", icon: ShieldCheck, load: getIdentityProviders },
  { key: "redqueen", label: "RedQueen", group: "Decision y respuesta", endpoint: "GET /api/v1/redqueen/status", icon: Bot, load: getRedQueenStatus },
  { key: "ares", label: "ARES", group: "Decision y respuesta", endpoint: "GET /api/v1/ares/status", icon: Workflow, load: getAresStatus },
  { key: "secops", label: "SecOps", group: "Decision y respuesta", endpoint: "GET /api/v1/secops/status", icon: CloudCog, load: getSecOpsStatus },
  { key: "dns", label: "DNS / Firewall", group: "Decision y respuesta", endpoint: "GET /api/v1/dns-firewall/status", icon: Network, load: getDnsFirewallStatus },
  { key: "connectors", label: "Connectors", group: "Integraciones y gobierno", endpoint: "GET /api/v1/connectors", icon: Route, load: getConnectors },
  { key: "playbooks", label: "Playbooks", group: "Integraciones y gobierno", endpoint: "GET /api/v1/playbooks", icon: Play, load: getPlaybooks },
  { key: "cases", label: "Cases", group: "Integraciones y gobierno", endpoint: "GET /api/v1/cases/status", icon: FileCheck2, load: getCasesStatus },
  { key: "compliance", label: "Compliance", group: "Integraciones y gobierno", endpoint: "GET /api/v1/compliance/evidence", icon: FileCheck2, load: getComplianceEvidence },
  { key: "audit", label: "Audit chain", group: "Integraciones y gobierno", endpoint: "GET /api/v1/audit/records", icon: FileClock, load: () => listAresXAuditRecords({ limit: 1 }) },
];

export default function PlatformVisibilityPage() {
  const [modules, setModules] = useState([]);
  const [platformMap, setPlatformMap] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    const [mapResult, moduleResults] = await Promise.all([
      getPlatformMap().catch(() => null),
      Promise.allSettled(MODULES.map((module) => module.load())),
    ]);

    setPlatformMap(mapResult);
    setModules(
      MODULES.map((module, index) => {
        const result = moduleResults[index];
        if (result.status === "rejected") {
          return {
            ...module,
            connection: "unavailable",
            detail: result.reason?.message || "Sin respuesta del backend",
          };
        }
        return {
          ...module,
          connection: resolveConnection(result.value),
          detail: describePayload(module.key, result.value),
          payload: result.value,
        };
      })
    );
    setLastUpdated(new Date());
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
    const intervalId = window.setInterval(load, REFRESH_MS);
    return () => window.clearInterval(intervalId);
  }, [load]);

  const summary = useMemo(() => {
    const connected = modules.filter((module) => module.connection === "connected").length;
    const attention = modules.filter((module) => module.connection === "attention").length;
    const unavailable = modules.filter((module) => module.connection === "unavailable").length;
    return { total: MODULES.length, connected, attention, unavailable };
  }, [modules]);

  const groups = useMemo(
    () =>
      [...new Set(MODULES.map((module) => module.group))].map((name) => ({
        name,
        items: modules.filter((module) => module.group === name),
      })),
    [modules]
  );

  return (
    <div className="mx-auto max-w-[1680px]">
      <section className="mb-5 flex flex-col gap-4 border-b border-[var(--vx-line-soft)] pb-5 md:flex-row md:items-end md:justify-between">
        <div>
          <div className="vx-eyebrow text-[var(--vx-cyan)]">Frontend - API - Backend</div>
          <h2 className="vx-title mt-2 text-2xl">Mapa de conexion operativo</h2>
          <p className="mt-1.5 max-w-3xl text-sm text-[var(--vx-text-muted)]">
            Una vista unica para comprobar que dominios responden, cuales requieren atencion y que contrato consume la interfaz.
          </p>
        </div>
        <button type="button" onClick={load} disabled={loading} className="vx-button-secondary shrink-0 disabled:opacity-60">
          <RefreshCw size={15} className={loading ? "animate-spin" : ""} />
          {loading ? "Comprobando" : "Actualizar conexiones"}
        </button>
      </section>

      <section className="vx-kpi-grid mb-4" aria-label="Resumen de conexiones">
        <SummaryCard label="Modulos auditados" value={summary.total} icon={Boxes} tone="var(--vx-text)" />
        <SummaryCard label="Conectados" value={summary.connected} icon={CheckCircle2} tone="var(--vx-safe)" />
        <SummaryCard label="Atencion" value={summary.attention} icon={Activity} tone="var(--vx-warning)" />
        <SummaryCard label="Sin respuesta" value={summary.unavailable} icon={XCircle} tone="var(--vx-critical)" />
      </section>

      <section className="vx-panel mb-4 overflow-hidden">
        <div className="vx-panel-header">
          <div>
            <div className="vx-eyebrow">Arquitectura visible</div>
            <h3 className="vx-title mt-0.5 text-base">{platformMap?.product || "VAELQORIX Platform"}</h3>
          </div>
          <span className="font-mono text-xs text-[var(--vx-text-muted)]">
            {lastUpdated
              ? `Actualizado ${lastUpdated.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}`
              : "Esperando datos"}
          </span>
        </div>
        <div className="grid gap-px bg-[var(--vx-line-soft)] sm:grid-cols-3">
          <ArchitectureStep index="01" label="Interfaz" value="React Command Center" />
          <ArchitectureStep index="02" label="Control plane" value={platformMap?.current_core || "FastAPI"} />
          <ArchitectureStep index="03" label="Runtime" value={platformMap?.runtime || "CortexFlow / ARES"} />
        </div>
      </section>

      <div className="grid gap-4 xl:grid-cols-2">
        {groups.map((group) => {
          const fallbackItems = MODULES.filter((module) => module.group === group.name);
          const items = group.items.length ? group.items : fallbackItems;
          return (
            <section key={group.name} className="vx-panel overflow-hidden">
              <div className="vx-panel-header">
                <div>
                  <div className="vx-eyebrow">Dominio</div>
                  <h3 className="vx-title mt-0.5 text-base">{group.name}</h3>
                </div>
                <span className="text-xs text-[var(--vx-text-dim)]">{items.length} contratos</span>
              </div>
              <div className="divide-y divide-[var(--vx-line-soft)]">
                {items.map((module) => (
                  <ModuleRow key={module.key} module={module} loading={loading && !modules.length} />
                ))}
              </div>
            </section>
          );
        })}
      </div>
    </div>
  );
}

function SummaryCard({ label, value, icon: Icon, tone }) {
  return (
    <article className="vx-kpi">
      <div className="flex items-center justify-between">
        <span className="vx-eyebrow">{label}</span>
        {createElement(Icon, { size: 16, style: { color: tone } })}
      </div>
      <strong className="mt-2 block font-headline text-[1.75rem] leading-none" style={{ color: tone }}>
        {value}
      </strong>
      <span className="mt-2 block text-xs text-[var(--vx-text-muted)]">Estado observado en tiempo real</span>
    </article>
  );
}

function ArchitectureStep({ index, label, value }) {
  return (
    <div className="bg-[var(--vx-panel)] p-4">
      <span className="font-mono text-[10px] text-[var(--vx-cyan)]">{index}</span>
      <div className="vx-eyebrow mt-3">{label}</div>
      <strong className="mt-1 block text-sm text-white">{value}</strong>
    </div>
  );
}

function ModuleRow({ module, loading }) {
  const Icon = module.icon;
  const state = loading ? "checking" : module.connection;
  const presentation = {
    connected: { label: "Conectado", color: "var(--vx-safe)", icon: CheckCircle2 },
    attention: { label: "Atencion", color: "var(--vx-warning)", icon: Activity },
    unavailable: { label: "Sin respuesta", color: "var(--vx-critical)", icon: XCircle },
    checking: { label: "Comprobando", color: "var(--vx-text-dim)", icon: RefreshCw },
  }[state];
  const StateIcon = presentation.icon;

  return (
    <div className="grid gap-3 px-4 py-3.5 sm:grid-cols-[minmax(150px,.8fr)_minmax(210px,1.2fr)_auto] sm:items-center">
      <div className="flex items-center gap-3">
        <span className="grid h-8 w-8 shrink-0 place-items-center bg-[#0a111c] text-[var(--vx-cyan)]">
          <Icon size={15} />
        </span>
        <strong className="text-sm text-white">{module.label}</strong>
      </div>
      <div className="min-w-0">
        <code className="block truncate text-[11px] text-[var(--vx-info)]">{module.endpoint}</code>
        <span className="mt-1 block truncate text-xs text-[var(--vx-text-muted)]">{module.detail || "Esperando respuesta"}</span>
      </div>
      <span className="inline-flex items-center gap-2 whitespace-nowrap font-mono text-[10px] uppercase" style={{ color: presentation.color }}>
        <StateIcon size={14} className={state === "checking" ? "animate-spin" : ""} />
        {presentation.label}
      </span>
    </div>
  );
}

function resolveConnection(payload) {
  const raw = String(payload?.overall || payload?.status || payload?.state || "").toLowerCase();
  if (["down", "error", "failed", "unavailable", "offline"].includes(raw)) return "unavailable";
  if (raw.includes("attention") || raw.includes("degraded") || Number(payload?.failed || 0) > 0) return "attention";
  return "connected";
}

function describePayload(key, payload) {
  if (!payload || typeof payload !== "object") return "Contrato respondio correctamente";
  if (key === "platform") return `${payload.passed || 0} checks correctos - ${payload.failed || 0} pendientes`;
  if (key === "monitoring") return `Estado global: ${payload.overall || payload.status || "disponible"}`;
  if (key === "identity") return `${payload.providers?.length || 0} proveedores de identidad`;
  if (key === "connectors") return `${payload.items?.length || 0} conectores registrados`;
  if (key === "playbooks") return `${payload.items?.length || 0} playbooks disponibles`;
  if (key === "audit") return `${payload.items?.length || 0} registros recuperados en la muestra`;
  if (Array.isArray(payload.capabilities)) return `${payload.capabilities.length} capacidades declaradas`;
  return `Estado: ${payload.status || payload.overall || "disponible"}`;
}
