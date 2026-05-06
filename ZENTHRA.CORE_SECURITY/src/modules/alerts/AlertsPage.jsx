import { useEffect, useMemo, useState } from "react";
import { getAlerts, getHostSummary, getRuntimeLogs } from "@/api/nexusApi";

const AUTO_REFRESH_MS = 15000;
const TRAFFIC_LABELS = ["08:00", "10:00", "12:00", "14:00", "16:00", "18:00", "20:00"];

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([]);
  const [logs, setLogs] = useState([]);
  const [metrics, setMetrics] = useState({ cpu: null, memoryPercent: null, latencyMs: null });
  const [traffic, setTraffic] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let mounted = true;

    const loadLiveData = async () => {
      try {
        if (mounted) setError("");

        const [alertsResult, logsResult, metricsResult] = await Promise.allSettled([
          getAlerts(),
          getRuntimeLogs({ limit: 50 }),
          loadHostSnapshot(),
        ]);

        if (!mounted) return;

        setAlerts(
          alertsResult.status === "fulfilled" && Array.isArray(alertsResult.value)
            ? alertsResult.value
            : []
        );
        setLogs(
          logsResult.status === "fulfilled" && Array.isArray(logsResult.value?.items)
            ? logsResult.value.items
            : []
        );
        const hostSnapshot =
          metricsResult.status === "fulfilled"
            ? metricsResult.value
            : { metrics: { cpu: null, memoryPercent: null, latencyMs: null }, traffic: [] };
        setMetrics(hostSnapshot.metrics);
        setTraffic(hostSnapshot.traffic);

        const failures = [alertsResult, logsResult, metricsResult].filter(
          (item) => item.status === "rejected"
        );
        if (failures.length) {
          setError("Algunas fuentes reales no respondieron. Mostrando solo datos disponibles.");
        }
      } catch (err) {
        if (mounted) {
          setError(err?.message || "Error al cargar datos reales");
          setAlerts([]);
          setLogs([]);
          setTraffic([]);
          setMetrics({ cpu: null, memoryPercent: null, latencyMs: null });
        }
      } finally {
        if (mounted) setLoading(false);
      }
    };

    loadLiveData();
    const intervalId = setInterval(loadLiveData, AUTO_REFRESH_MS);

    return () => {
      mounted = false;
      clearInterval(intervalId);
    };
  }, []);

  const derived = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0 };

    alerts.forEach((alert) => {
      const severity = (alert.labels?.severity || "").toLowerCase();
      if (severity === "critical") counts.critical += 1;
      else if (severity === "warning" || severity === "high") counts.high += 1;
      else counts.medium += 1;
    });

    const threatScore = Math.min(100, counts.critical * 30 + counts.high * 15 + counts.medium * 5);
    const strokeOffset = 552.92 - (552.92 * threatScore) / 100;
    const trackerRows = buildTrackerRows(alerts, logs);
    const trafficBars = buildTrafficBars(traffic);

    return {
      counts,
      strokeOffset,
      threatLevel:
        counts.critical > 0 ? "HIGH" : counts.high > 0 ? "ELEVATED" : alerts.length ? "GUARDED" : "NO DATA",
      alertLabel:
        counts.critical > 0
          ? "LVL 04 ALERT"
          : counts.high > 0
            ? "LVL 03 WATCH"
            : alerts.length
              ? "LVL 02 STABLE"
              : "AWAITING DATA",
      threatSummary:
        alerts.length > 0
          ? "Live Alertmanager stream connected"
          : "No live incidents received from Alertmanager",
      trackerRows,
      trafficBars,
      cpu: formatPercent(metrics.cpu),
      memory: formatPercent(metrics.memoryPercent),
      latency: metrics.latencyMs === null ? "N/A" : `${metrics.latencyMs.toFixed(0)}ms`,
      terminalLines: buildTerminalLines(alerts, logs, error),
    };
  }, [alerts, logs, metrics, traffic, error]);

  return (
    <div className="min-h-full">
      <div className="mx-auto grid max-w-7xl grid-cols-12 gap-6">
        <section className="glass-panel relative col-span-12 overflow-hidden p-6 lg:col-span-4">
          <div className="accent-glow absolute left-0 top-0 h-full w-1 bg-[#ff716c]" />
          <p className="mb-4 font-['JetBrains_Mono'] text-[10px] uppercase tracking-[0.2em] text-[#a8abb3]">
            Core/System/Status
          </p>

          <div className="relative flex h-48 w-48 items-center justify-center mx-auto">
            <svg className="h-full w-full -rotate-90">
              <circle className="text-white/5" cx="96" cy="96" r="88" fill="transparent" stroke="currentColor" strokeWidth="4" />
              <circle
                className="text-[#ff716c] drop-shadow-[0_0_8px_rgba(255,113,108,0.6)]"
                cx="96"
                cy="96"
                r="88"
                fill="transparent"
                stroke="currentColor"
                strokeDasharray="552.92"
                strokeDashoffset={derived.strokeOffset}
                strokeWidth="6"
              />
            </svg>

            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="font-headline text-5xl font-extrabold text-[#ff716c]">
                {loading ? "SYNC" : derived.threatLevel}
              </span>
              <span className="mt-1 font-['JetBrains_Mono'] text-[10px] text-[#9f0519]">
                {loading ? "UPDATING" : derived.alertLabel}
              </span>
            </div>
          </div>

          <h3 className="mt-6 text-center font-headline text-lg font-bold text-[#f1f3fc]">
            Global Threat Level
          </h3>
          <p className="mt-1 text-center font-['JetBrains_Mono'] text-xs text-[#a8abb3]">
            {error || derived.threatSummary}
          </p>
        </section>

        <section className="glass-panel col-span-12 overflow-hidden p-6 lg:col-span-8">
          <div className="mb-6 flex items-end justify-between">
            <div>
              <p className="font-['JetBrains_Mono'] text-[10px] uppercase tracking-[0.2em] text-[#8ff5ff]">
                Live/Incident/Log
              </p>
              <h3 className="font-headline text-xl font-bold text-[#f1f3fc]">
                Active Threats Tracker
              </h3>
            </div>
            <span className="border border-[#8ff5ff]/20 px-3 py-1 font-['JetBrains_Mono'] text-[10px] tracking-widest text-[#8ff5ff]">
              REAL DATA
            </span>
          </div>

          <div className="space-y-3">
            {derived.trackerRows.map((row, index) => (
              <ThreatRow key={`${row.title}-${index}`} row={row} />
            ))}
          </div>
        </section>

        <section className="glass-panel col-span-12 p-6 lg:col-span-7">
          <div className="mb-8 flex items-center justify-between">
            <div>
              <p className="font-['JetBrains_Mono'] text-[10px] uppercase tracking-[0.2em] text-[#8ff5ff]">
                Network/Flow/Data
              </p>
              <h3 className="font-headline text-xl font-bold text-[#f1f3fc]">
                Traffic Analysis
              </h3>
            </div>
            <div className="flex gap-4">
              <LegendPill color="bg-[#8ff5ff]" label="Inbound" />
              <LegendPill color="bg-[#af88ff]" label="Outbound" />
            </div>
          </div>

          <div className="relative flex h-48 items-end gap-1 px-2">
            {derived.trafficBars.map((bar) => (
              <div
                key={bar.label}
                title={bar.title}
                className={`group relative flex-1 transition-all duration-300 ${
                  bar.hasData ? "bg-[#8ff5ff]/20 hover:bg-[#8ff5ff]/40" : "bg-white/5"
                }`}
                style={{ height: `${bar.height}%` }}
              >
                <div className={`absolute top-0 h-1 w-full ${bar.hasData ? "bg-[#8ff5ff] shadow-[0_0_10px_#8ff5ff]" : "bg-slate-700"}`} />
              </div>
            ))}

            <div className="pointer-events-none absolute inset-0 flex flex-col justify-between">
              <div className="h-px w-full border-t border-white/5" />
              <div className="h-px w-full border-t border-white/5" />
              <div className="h-px w-full border-t border-white/5" />
              <div className="h-px w-full border-t border-white/5" />
            </div>
          </div>

          <div className="mt-4 flex justify-between font-['JetBrains_Mono'] text-[10px] text-slate-600">
            {TRAFFIC_LABELS.map((label) => (
              <span key={label}>{label}</span>
            ))}
          </div>
        </section>

        <section className="col-span-12 grid grid-cols-2 gap-4 lg:col-span-5">
          <MetricCard icon="memory" tone="primary" status={metrics.cpu === null ? "NO DATA" : "LIVE"} label="CPU LOAD" value={derived.cpu} />
          <MetricCard icon="memory_alt" tone="primary" status={metrics.memoryPercent === null ? "NO DATA" : "LIVE"} label="MEMORY" value={derived.memory} />
          <section className="glass-panel col-span-2 flex flex-col justify-between border-l-2 border-[#af88ff] p-4">
            <div className="flex items-start justify-between">
              <span className="material-symbols-outlined text-lg text-[#af88ff]">settings_input_antenna</span>
              <span className="font-['JetBrains_Mono'] text-[10px] text-[#af88ff]">
                {metrics.latencyMs === null ? "NO DATA" : "LIVE"}
              </span>
            </div>
            <div>
              <p className="font-['JetBrains_Mono'] text-[10px] uppercase text-[#a8abb3]">LATENCY</p>
              <h4 className="font-headline text-2xl font-bold text-[#f1f3fc]">{derived.latency}</h4>
            </div>
          </section>
        </section>

        <section className="glass-panel col-span-12 flex h-64 flex-col overflow-hidden border-t-2 border-[#8ff5ff] p-0">
          <div className="flex items-center justify-between border-b border-white/5 bg-[#1b2028] px-4 py-2">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-sm text-[#8ff5ff]">terminal</span>
              <span className="font-['JetBrains_Mono'] text-[10px] font-bold tracking-widest text-[#f1f3fc]">
                LIVE_BACKEND_LOGS
              </span>
            </div>
            <span className="font-['JetBrains_Mono'] text-[10px] text-slate-500">
              {logs.length} entries
            </span>
          </div>

          <div className="flex min-h-0 flex-1">
            <div className="flex-1 overflow-y-auto bg-black/40 p-4 font-['JetBrains_Mono'] text-[11px] text-[#8ff5ff]/80">
              {derived.terminalLines.map((line, index) => (
                <p key={index} className={`mb-1 ${line.tone}`}>
                  <span className="text-slate-600">{line.time}</span> {line.message}
                </p>
              ))}
            </div>

            <div className="flex w-72 flex-col gap-3 border-l border-white/5 bg-[#151a21] p-4">
              <TerminalAction label="Refresh Logs" />
              <TerminalAction label="Open Monitoring" />
              <TerminalAction label="Investigate Alerts" danger />
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

async function loadHostSnapshot() {
  const summary = await getHostSummary();
  const networkValue = summary?.network_mbps?.available
    ? Number(summary.network_mbps.value)
    : null;
  return {
    metrics: {
      cpu: summary?.cpu_percent?.available ? Number(summary.cpu_percent.value) : null,
      memoryPercent: summary?.memory_percent?.available ? Number(summary.memory_percent.value) : null,
      latencyMs: summary?.latency_ms?.available ? Number(summary.latency_ms.value) : null,
    },
    traffic: Number.isFinite(networkValue) ? [networkValue] : [],
  };
}

function buildTrackerRows(alerts, logs) {
  const alertRows = [...alerts]
    .sort((a, b) => new Date(b.startsAt || 0).getTime() - new Date(a.startsAt || 0).getTime())
    .slice(0, 3)
    .map((alert) => {
      const severity = normalizeSeverity(alert.labels?.severity);
      return {
        title: alert.annotations?.summary || alert.labels?.alertname || "Security Event",
        source: alert.labels?.instance || alert.labels?.job || "UNKNOWN_SOURCE",
        timestamp: formatTime(alert.startsAt),
        severity,
        icon: severity === "critical" ? "warning" : severity === "high" ? "shield_with_heart" : "info",
      };
    });

  if (alertRows.length) return alertRows;

  const logRows = logs.slice(0, 3).map((log) => ({
    title: log.message || "Backend log event",
    source: log.logger || log.source_file || "backend",
    timestamp: formatTime(log.timestamp),
    severity: normalizeSeverity(log.severity),
    icon: log.severity === "critical" ? "warning" : "terminal",
  }));

  if (logRows.length) return logRows;

  return [
    {
      title: "No live alerts or backend logs received",
      source: "REAL_DATA_PIPELINE",
      timestamp: "--:--:--",
      severity: "medium",
      icon: "info",
    },
  ];
}

function buildTrafficBars(values) {
  if (!values.length) {
    return TRAFFIC_LABELS.map((label) => ({
      label,
      height: 6,
      hasData: false,
      title: "Sin trafico real recibido desde Prometheus",
    }));
  }

  if (values.length === 1) {
    return TRAFFIC_LABELS.map((label, index) => ({
      label,
      height: index === TRAFFIC_LABELS.length - 1 ? 100 : 6,
      hasData: index === TRAFFIC_LABELS.length - 1,
      title:
        index === TRAFFIC_LABELS.length - 1
          ? `${values[0].toFixed(2)} Mb/s`
          : "Sin muestra historica agregada",
    }));
  }

  const maxValue = Math.max(...values, 0.000001);
  return TRAFFIC_LABELS.map((label, index) => {
    const value = values[index] ?? values[values.length - 1] ?? 0;
    return {
      label,
      height: Math.max(8, Math.min(100, (value / maxValue) * 100)),
      hasData: true,
      title: `${value.toFixed(2)} Mb/s`,
    };
  });
}

function buildTerminalLines(alerts, logs, error) {
  if (error) {
    return [{ time: `[${formatTime(new Date())}]`, message: error.toUpperCase(), tone: "text-[#af88ff]" }];
  }

  const alertLines = alerts.slice(0, 4).map((alert) => ({
    time: `[${formatTime(alert.startsAt)}]`,
    message: `${alert.labels?.alertname || "ALERT"} ${alert.annotations?.summary || ""}`.trim().toUpperCase(),
    tone: normalizeSeverity(alert.labels?.severity) === "critical" ? "text-[#ff716c]" : "",
  }));
  const logLines = logs.slice(0, 6 - alertLines.length).map((log) => ({
    time: `[${formatTime(log.timestamp)}]`,
    message: String(log.message || log.raw || "BACKEND LOG").toUpperCase(),
    tone: log.severity === "critical" ? "text-[#ff716c]" : log.severity === "high" ? "text-[#af88ff]" : "",
  }));

  const lines = [...alertLines, ...logLines];
  return lines.length
    ? lines
    : [{ time: "[--:--:--]", message: "NO REAL LOG OR ALERT DATA AVAILABLE YET", tone: "text-slate-500" }];
}

function ThreatRow({ row }) {
  const palette = {
    critical: { border: "border-[#ff716c]", icon: "text-[#ff716c]", badge: "bg-[#9f0519]/20 text-[#ff716c]" },
    high: { border: "border-[#8ff5ff]", icon: "text-[#8ff5ff]", badge: "bg-[#8ff5ff]/10 text-[#8ff5ff]" },
    medium: { border: "border-[#af88ff]", icon: "text-[#af88ff]", badge: "bg-[#af88ff]/10 text-[#af88ff]" },
  }[row.severity];

  return (
    <div className={`flex items-center border-l-2 bg-[#151a21] p-3 ${palette.border}`}>
      <div className="mr-4">
        <span className={`material-symbols-outlined ${palette.icon}`} style={{ fontVariationSettings: "'FILL' 1" }}>
          {row.icon}
        </span>
      </div>
      <div className="min-w-0 flex-1">
        <h4 className="truncate font-headline text-sm font-bold text-[#f1f3fc]">{row.title}</h4>
        <p className="truncate font-['JetBrains_Mono'] text-[10px] text-[#a8abb3]">
          SOURCE: {row.source} | TIMESTAMP: {row.timestamp}
        </p>
      </div>
      <div className={`ml-3 px-2 py-0.5 font-['JetBrains_Mono'] text-[10px] font-bold ${palette.badge}`}>
        {row.severity.toUpperCase()}
      </div>
    </div>
  );
}

function LegendPill({ color, label }) {
  return (
    <div className="flex items-center gap-2">
      <div className={`h-2 w-2 rounded-full ${color}`} />
      <span className="font-['JetBrains_Mono'] text-[10px] uppercase text-[#a8abb3]">{label}</span>
    </div>
  );
}

function MetricCard({ icon, tone, status, label, value }) {
  const color = tone === "primary" ? "#8ff5ff" : "#af88ff";
  return (
    <section className="glass-panel flex flex-col justify-between border-l-2 p-4" style={{ borderLeftColor: color }}>
      <div className="flex items-start justify-between">
        <span className="material-symbols-outlined text-lg" style={{ color }}>{icon}</span>
        <span className="font-['JetBrains_Mono'] text-[10px]" style={{ color }}>{status}</span>
      </div>
      <div>
        <p className="font-['JetBrains_Mono'] text-[10px] uppercase text-[#a8abb3]">{label}</p>
        <h4 className="font-headline text-2xl font-bold text-[#f1f3fc]">{value}</h4>
      </div>
    </section>
  );
}

function TerminalAction({ label, danger = false }) {
  return (
    <button
      type="button"
      className={`w-full border py-2.5 font-headline text-xs font-bold uppercase tracking-widest transition-all ${
        danger
          ? "border-[#ff716c]/40 bg-[#ff716c]/10 text-[#ff716c] hover:bg-[#ff716c]/20"
          : "border-[#8ff5ff]/20 bg-[#1b2028] text-[#8ff5ff] hover:bg-[#8ff5ff]/10"
      }`}
    >
      {label}
    </button>
  );
}

function normalizeSeverity(value) {
  const severity = (value || "").toLowerCase();
  if (severity === "critical") return "critical";
  if (severity === "warning" || severity === "high") return "high";
  return "medium";
}

function formatPercent(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? `${Math.max(0, Math.min(parsed, 100)).toFixed(1)}%` : "N/A";
}

function formatTime(value) {
  if (!value) return "--:--:--";
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return "--:--:--";
  return date.toLocaleTimeString("es-ES", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}
