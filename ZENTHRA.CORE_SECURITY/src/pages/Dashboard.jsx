import { useEffect, useMemo, useState } from "react";
import { getAlerts, getHostSummary } from "@/api/nexusApi";
import { useAuth } from "@/hooks/useAuth";

const AUTO_REFRESH_MS = 10000;
const METRICS_REFRESH_MS = 15000;

export default function Dashboard() {
  const { user } = useAuth();
  const [alerts, setAlerts] = useState([]);
  const [hostMetrics, setHostMetrics] = useState({
    cpu: null,
    ram: null,
    bandwidth: null,
    latency: null,
    gpu: null,
    gpuSource: "",
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let mounted = true;

    const fetchAlerts = async () => {
      try {
        if (mounted) setError("");
        const data = await getAlerts();
        if (mounted) {
          setAlerts(Array.isArray(data) ? data : []);
        }
      } catch (err) {
        if (mounted) {
          setError(err?.message || "Error al cargar alertas");
          setAlerts([]);
        }
      } finally {
        if (mounted) setLoading(false);
      }
    };

    fetchAlerts();
    const intervalId = setInterval(fetchAlerts, AUTO_REFRESH_MS);

    return () => {
      mounted = false;
      clearInterval(intervalId);
    };
  }, []);

  useEffect(() => {
    let mounted = true;

    const fetchMetrics = async () => {
      const summary = await getHostSummary().catch(() => null);

      if (mounted) {
        setHostMetrics({
          cpu: summary?.cpu_percent?.available ? summary.cpu_percent.value : null,
          ram: summary?.memory_percent?.available ? summary.memory_percent.value : null,
          bandwidth: summary?.network_mbps?.available ? summary.network_mbps.value : null,
          latency: summary?.latency_ms?.available ? summary.latency_ms.value : null,
          gpu:
            summary?.gpu?.available && typeof summary.gpu.utilization_percent === "number"
              ? summary.gpu.utilization_percent
              : null,
          gpuSource: summary?.gpu?.source || "",
        });
      }
    };

    fetchMetrics();
    const intervalId = setInterval(fetchMetrics, METRICS_REFRESH_MS);

    return () => {
      mounted = false;
      clearInterval(intervalId);
    };
  }, []);

  const stats = useMemo(() => {
    const severities = { critical: 0, high: 0, medium: 0 };
    const incidentsBySource = {};

    alerts.forEach((alert) => {
      const severity = (alert.labels?.severity || "").toLowerCase();
      if (severity === "critical") severities.critical += 1;
      else if (severity === "warning" || severity === "high") severities.high += 1;
      else severities.medium += 1;

      const source = alert.labels?.instance || alert.labels?.job || "unknown";
      incidentsBySource[source] = (incidentsBySource[source] || 0) + 1;
    });

    return {
      total: alerts.length,
      critical: severities.critical,
      high: severities.high,
      medium: severities.medium,
      activeVectors: alerts.length,
      cpuLoad: clampPercent(hostMetrics.cpu),
      ramUsage: clampPercent(hostMetrics.ram),
      bandwidth: nullableNumber(hostMetrics.bandwidth),
      latency: nullableNumber(hostMetrics.latency),
      gpuLoad: clampPercent(hostMetrics.gpu),
      gpuSource: hostMetrics.gpuSource,
      topSources: Object.entries(incidentsBySource)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 3),
    };
  }, [alerts, hostMetrics]);

  const analystName = (user?.email || "sentinel-04")
    .split("@")[0]
    .replace(/[-_.]+/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());

  const incidentRows = useMemo(() => {
    return alerts.slice(0, 6).map((alert, index) => {
      const severity = (alert.labels?.severity || "medium").toLowerCase();
      const normalizedSeverity =
        severity === "critical"
          ? "critical"
          : severity === "warning" || severity === "high"
            ? "high"
            : "medium";

      return {
        id: `#INC-${String(9482 - index).padStart(4, "0")}`,
        type: alert.annotations?.summary || alert.labels?.alertname || "Unknown Incident",
        source: alert.labels?.instance || alert.labels?.job || "INTERNAL_NODE",
        severity: normalizedSeverity,
        status:
          normalizedSeverity === "critical"
            ? "In Progress"
            : normalizedSeverity === "high"
              ? "Investigating"
              : "Queued",
        time: alert.startsAt
          ? new Date(alert.startsAt).toLocaleTimeString("es-ES", {
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
              hour12: false,
            })
          : "--:--:--",
      };
    });
  }, [alerts]);

  const primarySource = stats.topSources[0]?.[0] || "N/A";
  const uptime = loading ? "SYNCING..." : "N/A";
  const systemState = error ? "Degraded" : "Optimal";

  return (
    <div className="pb-6">
      <section className="mb-6 grid grid-cols-12 gap-6">
        <div className="relative col-span-12 overflow-hidden bg-[#0f141a] p-8 lg:col-span-8">
          <div className="pointer-events-none absolute inset-0 bg-gradient-to-r from-[#8ff5ff]/10 to-transparent opacity-20" />
          <div className="pointer-events-none absolute bottom-0 right-0 top-0 w-1/3 bg-[radial-gradient(circle_at_center,rgba(143,245,255,0.18),transparent_70%)] opacity-60" />

          <div className="relative z-10">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <span className="h-2 w-2 animate-pulse rounded-full bg-[#8ff5ff]" />
              <span className="font-label text-xs uppercase tracking-widest text-[#8ff5ff]">
                System: {systemState}
              </span>
              <span className="ml-0 font-label text-xs text-[#a8abb3] opacity-60 md:ml-4">
                UPTIME: {uptime}
              </span>
            </div>

            <h2 className="font-headline text-3xl font-bold text-[#f1f3fc] md:text-4xl">
              Welcome back, Analyst {analystName}
            </h2>
            <p className="mt-2 max-w-xl text-[#a8abb3]">
              Intrusion detection systems are operating within monitored parameters.
              {stats.total > 0
                ? ` ${stats.total} suspicious patterns identified in the last sync, ${stats.critical} critical incidents detected.`
                : " No active incidents detected in the latest sync."}
            </p>
          </div>
        </div>

        <div className="col-span-12 grid grid-cols-1 gap-3 lg:col-span-4">
          <ActionPanel
            tone="error"
            code="CRITICAL_OVERRIDE"
            title="Initiate Lockdown"
            icon="lock"
          />
          <ActionPanel
            tone="primary"
            code="GLOBAL_SCAN"
            title="Scan Network"
            icon="search_check"
          />
          <ActionPanel
            tone="tertiary"
            code="DATA_AGGREGATION"
            title="Generate Report"
            icon="description"
          />
        </div>
      </section>

      <section className="grid grid-cols-12 gap-6 pb-6">
        <div className="relative col-span-12 h-[500px] overflow-hidden bg-[#0f141a] xl:col-span-8">
          <div className="absolute left-6 top-4 z-10 flex items-center gap-4">
            <span className="border border-[#8ff5ff]/20 bg-[#1b2028] px-3 py-1 font-label text-xs text-[#8ff5ff]">
              LIVE_THREAT_MAP
            </span>
            <div className="flex gap-2">
              <span className="flex items-center gap-1 font-label text-[10px] text-[#a8abb3]">
                <span className="h-1.5 w-1.5 rounded-full bg-[#ff716c]" />
                Critical
              </span>
              <span className="flex items-center gap-1 font-label text-[10px] text-[#a8abb3]">
                <span className="h-1.5 w-1.5 rounded-full bg-[#8ff5ff]" />
                Signal
              </span>
            </div>
          </div>

          <div className="relative h-full w-full overflow-hidden">
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_30%,rgba(143,245,255,0.16),transparent_18%),radial-gradient(circle_at_72%_42%,rgba(255,113,108,0.20),transparent_14%),radial-gradient(circle_at_58%_68%,rgba(175,136,255,0.18),transparent_16%),linear-gradient(180deg,rgba(10,14,20,0.2),rgba(10,14,20,0.85))]" />
            <div className="absolute inset-0 opacity-40 [background-image:linear-gradient(rgba(143,245,255,0.08)_1px,transparent_1px),linear-gradient(90deg,rgba(143,245,255,0.08)_1px,transparent_1px)] [background-size:48px_48px]" />
            <div className="absolute left-[12%] top-[28%] h-3 w-3 animate-pulse rounded-full bg-[#8ff5ff] shadow-[0_0_18px_rgba(143,245,255,0.6)]" />
            <div className="absolute left-[48%] top-[38%] h-4 w-4 animate-pulse rounded-full bg-[#ff716c] shadow-[0_0_22px_rgba(255,113,108,0.7)]" />
            <div className="absolute left-[67%] top-[55%] h-3 w-3 rounded-full bg-[#8ff5ff] shadow-[0_0_18px_rgba(143,245,255,0.55)]" />
            <div className="absolute left-[18%] top-[30%] h-px w-[34%] rotate-[7deg] bg-gradient-to-r from-[#8ff5ff]/50 to-transparent" />
            <div className="absolute left-[50%] top-[40%] h-px w-[20%] rotate-[20deg] bg-gradient-to-r from-[#ff716c]/80 to-transparent" />

            <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
              <div className="h-[80%] w-[80%] animate-pulse rounded-full border border-[#8ff5ff]/10 opacity-20" />
              <div className="absolute h-[60%] w-[60%] rounded-full border border-[#8ff5ff]/5 opacity-10" />
            </div>

            <div className="absolute right-1/4 top-1/4 flex flex-col items-end">
              <div className="mb-1 border border-[#ff716c] bg-[#9f0519]/80 px-3 py-1.5 font-label text-[10px] text-white backdrop-blur-md">
                SOURCE: {primarySource}
              </div>
              <div className="h-0.5 w-[200px] bg-gradient-to-l from-[#ff716c] to-transparent" />
            </div>
          </div>

          <div className="glass-panel absolute bottom-6 right-6 flex flex-col gap-2 border-l border-[#8ff5ff]/30 p-4">
            <span className="font-label text-[10px] text-[#a8abb3]">ACTIVE_VECTORS</span>
            <span className="font-headline text-2xl font-bold text-[#8ff5ff]">
              {stats.activeVectors.toLocaleString("en-US")}
            </span>
            <span className="font-label text-[10px] text-[#00deec]">
              {loading ? "Syncing..." : "Latest sync only"}
            </span>
          </div>
        </div>

        <div className="col-span-12 space-y-6 xl:col-span-4">
          <div className="h-full bg-[#0f141a] p-6">
            <div className="mb-8 flex items-center justify-between">
              <span className="font-label text-xs uppercase tracking-widest text-[#a8abb3]">
                Network_Health
              </span>
              <span className="material-symbols-outlined text-sm text-[#8ff5ff]">
                settings_input_component
              </span>
            </div>

            <div className="space-y-8">
              <Gauge label="CPU LOAD" value={formatPercent(stats.cpuLoad)} width={gaugeWidth(stats.cpuLoad)} color="#8ff5ff" />
              <Gauge label="RAM USAGE" value={formatPercent(stats.ramUsage)} width={gaugeWidth(stats.ramUsage)} color="#af88ff" />
              <Gauge label="GPU LOAD" value={formatPercent(stats.gpuLoad)} width={gaugeWidth(stats.gpuLoad)} color="#ffa8a3" />
              <Gauge label="BANDWIDTH" value={stats.bandwidth === null ? "N/A" : `${stats.bandwidth.toFixed(2)} Mb/s`} width={gaugeWidth(stats.bandwidth)} color="#00deec" />
              <Gauge label="LATENCY" value={stats.latency === null ? "N/A" : `${stats.latency.toFixed(0)}ms`} width={gaugeWidth(stats.latency)} color="#8ff5ff" />
            </div>

            <div className="mt-10 border-t border-[#8ff5ff]/20 bg-[#1b2028] p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-lg text-[#8ff5ff]">
                    router
                  </span>
                  <span className="font-label text-xs">GATEWAY_7_STATUS</span>
                </div>
                <span className="font-label text-xs font-bold text-[#8ff5ff]">
                  {error ? "DEGRADED" : "ONLINE"}
                </span>
              </div>
            </div>
          </div>
        </div>

        <div className="col-span-12 bg-[#0f141a] p-6">
          <div className="mb-6 flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
            <h3 className="flex items-center gap-2 font-headline text-xl font-bold">
              <span className="material-symbols-outlined text-[#8ff5ff]">view_list</span>
              Incident Queue
            </h3>

            <div className="flex gap-4">
              <div className="flex items-center gap-2 border border-[#44484f] bg-[#1b2028] px-3 py-1 font-label text-[10px]">
                FILTER: ALL_SEVERITY
                <span className="material-symbols-outlined text-xs">keyboard_arrow_down</span>
              </div>
              <div className="flex items-center gap-2 border border-[#44484f] bg-[#1b2028] px-3 py-1 font-label text-[10px]">
                SORT: TIMESTAMP
                <span className="material-symbols-outlined text-xs">keyboard_arrow_down</span>
              </div>
            </div>
          </div>

          {error && (
            <div className="mb-4 border-l-2 border-[#ff716c] bg-[#9f0519]/10 px-4 py-3 text-sm text-[#ffa8a3]">
              {error}
            </div>
          )}

          <div className="overflow-x-auto">
            <table className="w-full border-separate border-spacing-y-2 text-left font-label text-xs">
              <thead>
                <tr className="text-[#a8abb3] opacity-60">
                  <th className="pb-4 pl-4 font-normal uppercase tracking-widest">ID</th>
                  <th className="pb-4 font-normal uppercase tracking-widest">Incident Type</th>
                  <th className="pb-4 font-normal uppercase tracking-widest">Source IP</th>
                  <th className="pb-4 font-normal uppercase tracking-widest">Severity</th>
                  <th className="pb-4 font-normal uppercase tracking-widest">Status</th>
                  <th className="pb-4 pr-4 text-right font-normal uppercase tracking-widest">
                    Time Detected
                  </th>
                </tr>
              </thead>

              <tbody>
                {!loading && incidentRows.length === 0 && (
                  <tr className="bg-[#1b2028]">
                    <td colSpan={6} className="px-4 py-5 text-[#a8abb3]">
                      No active incidents in the current synchronization window.
                    </td>
                  </tr>
                )}

                {incidentRows.map((row) => (
                  <tr
                    key={`${row.id}-${row.source}`}
                    className="group cursor-pointer bg-[#1b2028] transition-colors hover:bg-[#20262f]"
                  >
                    <td className={`border-l-2 py-4 pl-4 ${severityAccent(row.severity)}`}>
                      {row.id}
                    </td>
                    <td className="py-4 font-headline font-bold text-[#f1f3fc]">
                      {row.type}
                    </td>
                    <td className="py-4 opacity-70">{row.source}</td>
                    <td className="py-4">
                      <SeverityBadge severity={row.severity} />
                    </td>
                    <td className="py-4">
                      <span className="flex items-center gap-1.5">
                        <span className={`h-1.5 w-1.5 rounded-full ${statusDot(row.severity)}`} />
                        {row.status}
                      </span>
                    </td>
                    <td className="py-4 pr-4 text-right opacity-60">{row.time}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  );
}

function nullableNumber(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function clampPercent(value) {
  const parsed = nullableNumber(value);
  if (parsed === null) return null;
  return Math.max(0, Math.min(parsed, 100));
}

function formatPercent(value) {
  return value === null ? "N/A" : `${value.toFixed(1)}%`;
}

function gaugeWidth(value) {
  if (value === null) return "0%";
  return `${Math.max(0, Math.min(Number(value) || 0, 100))}%`;
}

function ActionPanel({ tone, code, title, icon }) {
  const tones = {
    error: "border-[#ff716c] bg-[#9f0519]/20 text-[#ff716c] hover:bg-[#9f0519]/30",
    primary: "border-[#8ff5ff] bg-[#1b2028] text-[#8ff5ff] hover:bg-[#20262f]",
    tertiary: "border-[#af88ff] bg-[#1b2028] text-[#af88ff] hover:bg-[#20262f]",
  };

  return (
    <button
      type="button"
      className={`group flex items-center justify-between border-l-4 px-6 py-4 text-left transition-all ${tones[tone]}`}
    >
      <div>
        <span className="block font-label text-[10px] opacity-70">{code}</span>
        <span className="font-headline text-lg font-bold">{title}</span>
      </div>
      <span className="material-symbols-outlined text-3xl opacity-50 transition-opacity group-hover:opacity-100">
        {icon}
      </span>
    </button>
  );
}

function Gauge({ label, value, width, color }) {
  return (
    <div>
      <div className="mb-2 flex items-end justify-between">
        <span className="font-headline font-medium">{label}</span>
        <span className="font-label text-sm" style={{ color }}>
          {value}
        </span>
      </div>
      <div className="h-2 w-full overflow-hidden bg-[#20262f]">
        <div className="h-full" style={{ width, backgroundColor: color }} />
      </div>
    </div>
  );
}

function SeverityBadge({ severity }) {
  const styles = {
    critical: "border border-[#ff716c]/30 bg-[#ff716c]/20 text-[#ff716c]",
    high: "border border-[#8ff5ff]/30 bg-[#8ff5ff]/20 text-[#8ff5ff]",
    medium: "border border-[#af88ff]/30 bg-[#af88ff]/20 text-[#af88ff]",
  };

  return (
    <span className={`px-2 py-0.5 text-[10px] font-bold ${styles[severity]}`}>
      {severity.toUpperCase()}
    </span>
  );
}

function severityAccent(severity) {
  if (severity === "critical") return "border-[#ff716c]";
  if (severity === "high") return "border-[#8ff5ff]";
  return "border-[#af88ff]";
}

function statusDot(severity) {
  if (severity === "critical") return "bg-[#ff716c] animate-pulse";
  if (severity === "high") return "bg-[#8ff5ff]";
  return "bg-[#a8abb3]";
}
