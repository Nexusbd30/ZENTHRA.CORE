import { useEffect, useMemo, useState } from "react";
import {
  getAlerts,
  getFullInfraHealth,
  getHostSummary,
  getSourceDiagnostics,
} from "@/api/nexusApi";
import GpuMetrics from "@/components/GpuMetrics";
import SystemMetrics from "@/components/SystemMetrics";
import NetworkTrafficCard from "@/components/NetworkTrafficCard";

const OFFLINE_MSG = "No se puede conectar con el servidor.";
export default function MonitoringPage() {
  const [alerts, setAlerts] = useState([]);
  const [health, setHealth] = useState(null);
  const [hostSummary, setHostSummary] = useState(null);
  const [gpu, setGpu] = useState(null);
  const [nics, setNics] = useState([]);
  const [diagnostics, setDiagnostics] = useState(null);
  const [backendOffline, setBackendOffline] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const [alertsData, healthData, hostData, diagnosticsData] = await Promise.allSettled([
          getAlerts(),
          getFullInfraHealth(),
          getHostSummary(),
          getSourceDiagnostics(),
        ]);

        if (cancelled) return;

        const activeAlerts =
          alertsData.status === "fulfilled" && Array.isArray(alertsData.value)
            ? alertsData.value.filter((item) => (item?.status?.state || item?.state) !== "inactive")
            : [];

        setAlerts(activeAlerts);
        setHealth(healthData.status === "fulfilled" ? healthData.value : null);
        setHostSummary(hostData.status === "fulfilled" ? hostData.value : null);
        setNics(
          hostData.status === "fulfilled" && Array.isArray(hostData.value?.nics)
            ? hostData.value.nics
            : []
        );
        setGpu(hostData.status === "fulfilled" ? hostData.value?.gpu : null);
        setDiagnostics(diagnosticsData.status === "fulfilled" ? diagnosticsData.value : null);

        const hasOffline =
          alertsData.status === "rejected" &&
          String(alertsData.reason?.message || "").includes(OFFLINE_MSG);
        setBackendOffline(hasOffline);
      } catch {
        if (!cancelled) {
          setBackendOffline(true);
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    load();
    const intervalId = setInterval(load, 15000);

    return () => {
      cancelled = true;
      clearInterval(intervalId);
    };
  }, []);

  const derived = useMemo(() => {
    const uniqueNodes = new Set();
    alerts.forEach((alert) => {
      const source = alert?.labels?.instance || alert?.labels?.job;
      if (source) uniqueNodes.add(source);
    });
    nics.forEach((nic) => {
      if (nic?.name) uniqueNodes.add(nic.name);
    });

    const criticalAlerts = alerts.filter(
      (alert) => String(alert?.labels?.severity || "").toLowerCase() === "critical"
    ).length;

    const nodeCount = uniqueNodes.size || null;
    const uptime = health?.overall === "up" ? 100 : null;
    const gatewayStatus = !health ? "N/A" : health.overall === "down" ? "UNSTABLE" : health.overall === "degraded" ? "WATCH" : "STABLE";
    const gatewayLoad = hostSummary?.cpu_percent?.available
      ? Math.min(100, Math.max(0, Math.round(Number(hostSummary.cpu_percent.value))))
      : null;

    const feedItems = [
      ...alerts.slice(0, 4).map((alert, index) => ({
        id: `alert-${index}`,
        tone:
          String(alert?.labels?.severity || "").toLowerCase() === "critical"
            ? "error"
            : "primary",
        time: formatShortTime(alert?.startsAt),
        title: alert?.annotations?.summary || alert?.labels?.alertname || "Infrastructure alert",
        detail: alert?.labels?.instance || alert?.labels?.job || "Alertmanager source",
      })),
      ...buildHealthFeed(health),
    ].slice(0, 6);

    const inventoryRows = buildInventoryRows(health, nics, gatewayLoad);
    const latencyBars = buildLatencyBars(alerts, hostSummary?.latency_ms?.value);
    const densityValue =
      gpu?.available && typeof gpu.utilization_percent === "number"
        ? Math.round(gpu.utilization_percent)
        : null;

    return {
      nodeCount,
      activeAlerts: alerts.length,
      criticalAlerts,
      uptime,
      gatewayStatus,
      gatewayLoad,
      feedItems,
      inventoryRows,
      latencyBars,
      densityValue,
      gpuStatus:
        gpu?.available && typeof gpu.utilization_percent === "number"
          ? `${gpu.utilization_percent.toFixed(1)}%`
          : "N/A",
      primaryNic:
        nics.find((nic) => /ethernet|lan|wi-?fi/i.test(nic?.name || ""))?.name ||
        nics[0]?.name ||
        "NIC not detected",
    };
  }, [alerts, health, nics, hostSummary, gpu]);

  return (
    <div className="min-h-full bg-[#0a0e14] text-[#f1f3fc]">
      <section className="mb-8 grid grid-cols-1 gap-6 md:grid-cols-4">
        <MetricPanel
          label="Total Nodes"
          value={loading ? "..." : derived.nodeCount === null ? "N/A" : derived.nodeCount.toLocaleString("en-US")}
          footer={derived.nodeCount === null ? "Sin datos reales" : "Network synchronized"}
          tone="primary"
        />
        <MetricPanel
          label="Active Alerts"
          value={loading ? "..." : String(derived.activeAlerts).padStart(2, "0")}
          footer={derived.criticalAlerts > 0 ? "Critical Response Required" : "No Critical Alerts"}
          tone="error"
        />
        <MetricPanel
          label="Avg Uptime"
          value={loading ? "..." : derived.uptime === null ? "N/A" : `${derived.uptime.toFixed(2)}%`}
          progress={derived.uptime ?? undefined}
          tone="neutral"
        />
        <MetricPanel
          label="Gateway Status"
          value={loading ? "..." : derived.gatewayStatus}
          footer={derived.gatewayLoad === null ? "Load: N/A" : `Load: ${derived.gatewayLoad}%`}
          tone="tertiary"
        />
        <MetricPanel
          label="GPU Load"
          value={loading ? "..." : derived.gpuStatus}
          footer={gpu?.available ? `Source: ${gpu.source}` : "GPU exporter not detected"}
          tone="neutral"
        />
      </section>

      {backendOffline && (
        <div className="mb-6 border-l-2 border-amber-400 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">
          Backend offline: la vista sigue visible, pero las métricas reales de monitoring no están disponibles.
        </div>
      )}

      <SourceDiagnosticsPanel diagnostics={diagnostics} loading={loading} />

      <section className="mb-8 grid grid-cols-12 gap-8">
        <div className="col-span-12 flex h-[450px] flex-col overflow-hidden bg-[#0f141a] lg:col-span-8">
          <div className="flex items-center justify-between border-b border-[#8ff5ff]/10 p-4">
            <h4 className="font-label text-xs uppercase tracking-[0.2em] text-[#8ff5ff]">
              Global Connectivity Mesh
            </h4>
            <span className="font-label text-[10px] uppercase text-slate-500">
              Live Trace Active
            </span>
          </div>

          <div className="relative flex-1 overflow-hidden bg-[#0a0e14]">
            <div className="absolute inset-0 opacity-40 [background-image:radial-gradient(circle,rgba(143,245,255,0.12)_1px,transparent_1px)] [background-size:24px_24px]" />
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_25%_30%,rgba(143,245,255,0.16),transparent_18%),radial-gradient(circle_at_70%_48%,rgba(255,113,108,0.18),transparent_14%),radial-gradient(circle_at_45%_70%,rgba(175,136,255,0.16),transparent_16%)]" />
            <div className="absolute inset-0 opacity-20 [background-image:linear-gradient(rgba(143,245,255,0.08)_1px,transparent_1px),linear-gradient(90deg,rgba(143,245,255,0.08)_1px,transparent_1px)] [background-size:56px_56px]" />

            <StatusPing className="left-1/4 top-1/4" tone="primary" animated />
            <StatusPing className="left-1/2 top-1/3" tone="primary" />
            <StatusPing className="left-2/3 top-1/2" tone="error" animated />
            <StatusPing className="bottom-1/3 left-1/3" tone="primary" animated />
            <StatusPing className="left-1/4 top-1/2" tone="primary" />

            <div className="glass-panel absolute bottom-4 left-4 border border-[#8ff5ff]/10 p-4">
              <div className="space-y-2">
                {derived.inventoryRows.slice(0, 3).map((row) => (
                  <div key={row.name} className="flex items-center justify-between gap-8">
                    <span className="font-label text-[9px] uppercase text-slate-500">{row.name}</span>
                    <span className={`font-label text-[9px] ${row.statusTextClass}`}>{row.statusLabel}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="col-span-12 flex flex-col bg-[#0f141a] lg:col-span-4">
          <div className="border-b border-[#8ff5ff]/10 p-4">
            <h4 className="font-label text-xs uppercase tracking-[0.2em] text-[#8ff5ff]">
              Infrastructure Logs
            </h4>
          </div>
          <div className="flex-1 space-y-4 overflow-y-auto p-4">
            {derived.feedItems.map((item) => (
              <div key={item.id} className={`flex gap-4 border-l pl-4 ${feedBorder(item.tone)}`}>
                <div className="mt-1 font-label text-[9px] text-slate-500">{item.time}</div>
                <div>
                  <p className={`font-label text-[11px] uppercase ${feedText(item.tone)}`}>{item.title}</p>
                  <p className="font-label text-[9px] text-slate-500">{item.detail}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="mb-8 grid grid-cols-12 gap-8">
        <div className="col-span-12 bg-[#0f141a] lg:col-span-8">
          <div className="border-b border-[#8ff5ff]/10 p-4">
            <h4 className="font-label text-xs uppercase tracking-[0.2em] text-[#8ff5ff]">
              Core Node Inventory
            </h4>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-white/5 font-label text-[10px] uppercase tracking-widest text-slate-500">
                  <th className="px-6 py-4 font-normal">Asset Name</th>
                  <th className="px-6 py-4 font-normal">Status</th>
                  <th className="px-6 py-4 font-normal">IP Address</th>
                  <th className="px-6 py-4 font-normal">System Load</th>
                  <th className="px-6 py-4 font-normal">Uptime</th>
                </tr>
              </thead>
              <tbody className="font-label text-[11px]">
                {derived.inventoryRows.map((row) => (
                  <tr key={row.name} className="group border-b border-white/5 transition-colors hover:bg-[#1b2028] last:border-b-0">
                    <td className="px-6 py-4 font-medium uppercase text-[#f1f3fc]">{row.name}</td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-0.5 ${row.badgeClass}`}>{row.statusLabel}</span>
                    </td>
                    <td className="px-6 py-4 text-slate-400">{row.ip}</td>
                    <td className="px-6 py-4">
                      <div className="h-1.5 w-24 bg-[#1b2028]">
                        <div className={row.barClass} style={{ width: `${row.load}%` }} />
                      </div>
                    </td>
                    <td className="px-6 py-4 text-slate-400">{row.uptime}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="col-span-12 flex flex-col gap-8 lg:col-span-4">
          <div className="flex flex-1 flex-col bg-[#0f141a] p-6">
            <h4 className="mb-6 font-label text-xs uppercase tracking-[0.2em] text-[#8ff5ff]">
              Global Latency (24H)
            </h4>
            <div className="mb-4 flex flex-1 items-end gap-1 px-2">
              {derived.latencyBars.map((height, index) => (
                <div
                  key={index}
                  className={`flex-1 transition-colors hover:bg-[#8ff5ff]/40 ${index === 4 ? "border-t-2 border-[#8ff5ff] bg-[#8ff5ff]/20" : "bg-[#8ff5ff]/10"}`}
                  style={{ height: `${height}%` }}
                />
              ))}
            </div>
            <div className="flex justify-between font-label text-[8px] uppercase text-slate-600">
              <span>00:00</span>
              <span>06:00</span>
              <span>12:00</span>
              <span>18:00</span>
            </div>
          </div>

          <div className="flex flex-1 flex-col bg-[#0f141a] p-6">
            <h4 className="mb-6 font-label text-xs uppercase tracking-[0.2em] text-[#af88ff]">
              System Load Density
            </h4>
            <div className="flex flex-1 items-center justify-center">
              <div className="relative flex h-24 w-24 items-center justify-center rounded-full border-4 border-white/5">
                <div className="absolute inset-0 animate-spin rounded-full border-4 border-[#af88ff] border-t-transparent [animation-duration:3000ms]" />
                <span className="font-headline text-xl font-bold text-[#f1f3fc]">
                  {loading ? "..." : derived.densityValue === null ? "N/A" : `${derived.densityValue}%`}
                </span>
              </div>
            </div>
            <div className="mt-4 text-center">
              <p className="font-label text-[10px] uppercase tracking-widest text-slate-500">
                GPU Load Density
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-8 xl:grid-cols-2">
        <div className="bg-[#0f141a] p-6">
          <div className="mb-4 flex items-center justify-between">
            <h4 className="font-label text-xs uppercase tracking-[0.2em] text-[#8ff5ff]">
              Host Metrics
            </h4>
            <span className="font-label text-[10px] uppercase text-slate-500">CPU / Memory / GPU</span>
          </div>
          <SystemMetrics windowMinutes={10} stepSeconds={15} />
          <div className="mt-6">
            <GpuMetrics windowMinutes={10} stepSeconds={15} />
          </div>
        </div>

        <div className="bg-[#0f141a] p-6">
          <div className="mb-4 flex items-center justify-between">
            <h4 className="font-label text-xs uppercase tracking-[0.2em] text-[#8ff5ff]">
              Network Throughput
            </h4>
            <span className="font-label text-[10px] uppercase text-slate-500">{derived.primaryNic}</span>
          </div>
          <NetworkTrafficCard
            nic={derived.primaryNic}
            windowMinutes={10}
            stepSeconds={10}
            refreshMs={10000}
          />
        </div>
      </section>
    </div>
  );
}

function MetricPanel({ label, value, footer, tone, progress }) {
  const tones = {
    primary: "border-[#8ff5ff] text-[#8ff5ff]",
    error: "border-[#ff716c] text-[#ff716c]",
    tertiary: "border-[#af88ff] text-[#af88ff]",
    neutral: "border-[#8ff5ff] text-[#f1f3fc]",
  };

  return (
    <div className={`relative border-l-2 bg-[#0f141a] p-5 ${tones[tone]}`}>
      <p className="mb-1 font-label text-[10px] uppercase tracking-tighter text-[#a8abb3]">{label}</p>
      <h3 className="font-headline text-3xl font-bold">{value}</h3>
      {typeof progress === "number" ? (
        <div className="mt-4 h-1 w-full bg-[#1b2028]">
          <div className="h-full bg-[#8ff5ff]" style={{ width: `${Math.max(0, Math.min(progress, 100))}%` }} />
        </div>
      ) : (
        <div className="mt-4 flex items-center gap-2">
          <span className={`h-2 w-2 rounded-full ${tone === "error" ? "bg-[#ff716c]" : "bg-[#8ff5ff]"} ${tone !== "tertiary" ? "animate-pulse" : ""}`} />
          <span className="font-label text-[9px] uppercase tracking-widest text-slate-500">{footer}</span>
        </div>
      )}
    </div>
  );
}

function SourceDiagnosticsPanel({ diagnostics, loading }) {
  const entries = diagnostics?.sources ? Object.entries(diagnostics.sources) : [];
  const statusClass = (status) => {
    if (status === "up") return "text-[#8ff5ff]";
    if (status === "missing") return "text-amber-300";
    if (status === "down") return "text-[#ff716c]";
    return "text-slate-500";
  };

  return (
    <section className="mb-8 bg-[#0f141a] p-5">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h4 className="font-label text-xs uppercase tracking-[0.2em] text-[#8ff5ff]">
          Diagnóstico de Fuentes
        </h4>
        <span className="font-label text-[10px] uppercase text-slate-500">
          {loading ? "Comprobando..." : diagnostics?.overall || "sin datos reales"}
        </span>
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
        {(entries.length ? entries : ["backend", "prometheus", "alertmanager", "windows_exporter", "gpu"].map((name) => [name, { status: "unknown", detail: "sin datos reales" }])).map(([name, item]) => (
          <div key={name} className="border border-white/5 bg-[#151a21] px-4 py-3">
            <div className="mb-1 flex items-center justify-between gap-3">
              <span className="font-label text-[10px] uppercase tracking-widest text-slate-500">
                {name.replace(/_/g, " ")}
              </span>
              <span className={`font-label text-[10px] uppercase ${statusClass(item.status)}`}>
                {item.status || "unknown"}
              </span>
            </div>
            <p className="truncate text-xs text-[#a8abb3]" title={String(item.detail || "")}>
              {item.detail || "sin datos reales"}
            </p>
          </div>
        ))}
      </div>
    </section>
  );
}

function StatusPing({ className, tone, animated = false }) {
  const toneClass = tone === "error" ? "bg-[#ff716c] shadow-[0_0_10px_rgba(255,113,108,0.5)]" : "bg-[#8ff5ff] shadow-[0_0_12px_rgba(143,245,255,0.4)]";
  return (
    <div className={`absolute h-3 w-3 rounded-full ${toneClass} ${animated ? "animate-pulse" : ""} ${className}`} />
  );
}

function buildHealthFeed(health) {
  if (!health) return [];
  return [
    { id: "backend", tone: health.backend === "down" ? "error" : "primary", time: "LIVE", title: `Backend ${String(health.backend || "unknown").toUpperCase()}`, detail: "FastAPI service health" },
    { id: "database", tone: health.database === "down" ? "error" : "primary", time: "LIVE", title: `Database ${String(health.database || "unknown").toUpperCase()}`, detail: "Primary persistence layer" },
  ];
}

function buildInventoryRows(health, nics, hostLoad) {
  const services = [
    { name: "Backend API", key: "backend", ip: "internal://backend", uptime: "service" },
    { name: "Database", key: "database", ip: "internal://database", uptime: "service" },
    { name: "Prometheus Collector", key: "prometheus", ip: "internal://prometheus", uptime: "service" },
    { name: "Alertmanager Relay", key: "alertmanager", ip: "internal://alertmanager", uptime: "service" },
  ];

  const rows = services.map((service) => {
    const status = health?.[service.key] || "unknown";
    const isUnknown = status === "unknown";
    const isCritical = status === "down";
    const isWarn = status === "degraded";
    const load = isCritical ? 100 : isWarn ? 68 : isUnknown ? 0 : 100;
    return {
      name: service.name,
      statusLabel: isCritical ? "DOWN" : isWarn ? "DEGRADED" : isUnknown ? "N/A" : "UP",
      statusTextClass: isCritical ? "text-[#ff716c]" : isWarn ? "text-[#af88ff]" : isUnknown ? "text-slate-500" : "text-[#8ff5ff]",
      badgeClass: isCritical
        ? "bg-[#ff716c]/10 text-[#ff716c]"
        : isWarn
          ? "bg-[#af88ff]/10 text-[#af88ff]"
          : isUnknown
            ? "bg-slate-500/10 text-slate-400"
            : "bg-[#8ff5ff]/10 text-[#8ff5ff]",
      ip: service.ip,
      load,
      barClass: isCritical ? "h-full bg-[#ff716c]" : isWarn ? "h-full bg-[#af88ff]" : isUnknown ? "h-full bg-slate-600" : "h-full bg-[#8ff5ff]",
      uptime: status === "up" ? "ACTIVE" : status === "degraded" ? "DEGRADED" : status === "down" ? "DOWN" : "N/A",
    };
  });

  const nicName = nics[0]?.name;
  if (nicName) {
    rows.push({
      name: nicName,
      statusLabel: "NOMINAL",
      statusTextClass: "text-[#8ff5ff]",
      badgeClass: "bg-[#8ff5ff]/10 text-[#8ff5ff]",
      ip: "windows://nic",
      load: Number.isFinite(Number(hostLoad)) ? Math.max(0, Math.min(Number(hostLoad), 100)) : 0,
      barClass: "h-full bg-[#8ff5ff]",
      uptime: "LIVE",
    });
  }

  return rows;
}

function buildLatencyBars(alerts, latencyMs) {
  const parsed = Number(latencyMs);
  if (!Number.isFinite(parsed)) return [0, 0, 0, 0, 0, 0, 0, 0, 0];
  const normalized = Math.max(8, Math.min(100, parsed / 5));
  return [0, 0, 0, 0, normalized, 0, 0, 0, alerts.length ? Math.min(100, normalized + alerts.length * 2) : 0];
}

function formatShortTime(value) {
  if (!value) return "LIVE";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "LIVE";
  return date.toLocaleTimeString("es-ES", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function feedBorder(tone) {
  if (tone === "error") return "border-[#ff716c]";
  if (tone === "primary") return "border-[#8ff5ff]";
  return "border-slate-700";
}

function feedText(tone) {
  if (tone === "error") return "text-[#ff716c]";
  if (tone === "primary") return "text-[#8ff5ff]";
  return "text-slate-400";
}
