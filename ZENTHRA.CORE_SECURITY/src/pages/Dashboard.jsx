import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowUpRight,
  Bot,
  Check,
  ChevronRight,
  CircleDot,
  Clock,
  Network,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  X,
} from "lucide-react";

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
  const [range, setRange] = useState("24H");
  const [copilotOpen, setCopilotOpen] = useState(false);
  const [contained, setContained] = useState(false);
  const [notice, setNotice] = useState("");

  useEffect(() => {
    let mounted = true;

    const fetchAlerts = async () => {
      try {
        if (mounted) setError("");
        const data = await getAlerts();
        if (mounted) setAlerts(Array.isArray(data) ? data : []);
      } catch (err) {
        if (mounted) {
          setError(err?.message || "No se pudieron cargar alertas reales.");
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
      if (!mounted) return;

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
    };

    fetchMetrics();
    const intervalId = setInterval(fetchMetrics, METRICS_REFRESH_MS);

    return () => {
      mounted = false;
      clearInterval(intervalId);
    };
  }, []);

  const stats = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0 };
    const sourceCounts = {};

    alerts.forEach((alert) => {
      const severity = normalizeSeverity(alert.labels?.severity);
      counts[severity] += 1;
      const source = alert.labels?.instance || alert.labels?.job || "unknown";
      sourceCounts[source] = (sourceCounts[source] || 0) + 1;
    });

    const postureScore = Math.max(
      1,
      Math.min(99, 94 - counts.critical * 12 - counts.high * 7 - counts.medium * 2)
    );
    const threatScore = Math.min(100, counts.critical * 30 + counts.high * 15 + counts.medium * 6);

    return {
      total: alerts.length,
      counts,
      postureScore,
      threatScore,
      cpu: clampPercent(hostMetrics.cpu),
      ram: clampPercent(hostMetrics.ram),
      gpu: clampPercent(hostMetrics.gpu),
      bandwidth: nullableNumber(hostMetrics.bandwidth),
      latency: nullableNumber(hostMetrics.latency),
      gpuSource: hostMetrics.gpuSource,
      topSources: Object.entries(sourceCounts)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 4),
    };
  }, [alerts, hostMetrics]);

  const incidentRows = useMemo(
    () =>
      alerts.slice(0, 5).map((alert, index) => {
        const severity = normalizeSeverity(alert.labels?.severity);
        return {
          id: `INC-${String(9000 + index).padStart(4, "0")}`,
          severity,
          title: alert.annotations?.summary || alert.labels?.alertname || "Incidente sin titulo",
          meta: alert.labels?.instance || alert.labels?.job || "Origen no identificado",
          score:
            severity === "critical"
              ? 96 - index
              : severity === "high"
                ? 84 - index
                : 62 - index,
          time: alert.startsAt ? formatShortAge(alert.startsAt) : "ahora",
        };
      }),
    [alerts]
  );

  const analystName = (user?.email || "operator")
    .split("@")[0]
    .replace(/[-_.]+/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());

  const showNotice = (message) => {
    setNotice(message);
    window.setTimeout(() => setNotice(""), 2500);
  };

  return (
    <div className="relative min-h-full">
      <section className="mb-5 flex flex-col justify-between gap-5 xl:flex-row xl:items-end">
        <div>
          <div className="mb-2 flex items-center gap-2 font-label text-[10px] uppercase text-[#8c909f]">
            <CircleDot size={13} className="text-[#4ae176]" />
            Global security posture
          </div>
          <h2 className="font-headline text-4xl font-bold tracking-normal text-white">
            Command center
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-[#aeb7ca]">
            Deteccion, investigacion y respuesta unificadas para {analystName}.
          </p>
        </div>

        <div className="flex items-center gap-3 border border-white/10 bg-[#10182b] p-3">
          <PostureRing score={stats.postureScore} />
          <div>
            <div className="font-semibold text-white">{postureLabel(stats.postureScore)}</div>
            <div className="mt-1 text-xs text-[#8c909f]">
              {loading ? "Sincronizando" : `${stats.total} senales activas`}
            </div>
          </div>
        </div>
      </section>

      <section className="mb-4 grid grid-cols-1 border border-white/10 bg-[#0d1422] md:grid-cols-2 xl:grid-cols-4">
        <MetricTile label="Amenazas activas" value={stats.total} delta={deltaText(stats)} tone="danger" />
        <MetricTile
          label="Tiempo medio respuesta"
          value={stats.total ? "4m 12s" : "N/A"}
          delta={stats.total ? "SLA operativo" : "Sin incidentes"}
        />
        <MetricTile
          label="Activos monitorizados"
          value={stats.topSources.length ? stats.topSources.length : "N/A"}
          delta="Fuentes con senal"
        />
        <MetricTile
          label="Autonomia AI"
          value={stats.total ? "76%" : "Standby"}
          delta="Gobernada por ARES"
          tone="success"
        />
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.7fr)_minmax(340px,1fr)]">
        <article className="overflow-hidden border border-white/10 bg-[#10182b]">
          <PanelHeader
            eyebrow="Threat landscape"
            title="Attack signal graph"
            action={
              <div className="flex">
                {["1H", "24H", "7D"].map((item) => (
                  <button
                    key={item}
                    type="button"
                    onClick={() => setRange(item)}
                    className={[
                      "border border-white/10 px-3 py-1.5 font-label text-[10px]",
                      range === item
                        ? "bg-[#10281b] text-[#9ef0b6]"
                        : "bg-[#0b1020] text-[#8c909f] hover:text-white",
                    ].join(" ")}
                  >
                    {item}
                  </button>
                ))}
              </div>
            }
          />
          <div className="relative grid min-h-[360px] place-items-center overflow-hidden bg-[#0a1018]">
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(74,225,118,0.16),transparent_42%),linear-gradient(rgba(173,198,255,0.06)_1px,transparent_1px),linear-gradient(90deg,rgba(173,198,255,0.06)_1px,transparent_1px)] bg-[length:auto,38px_38px,38px_38px]" />
            <SignalGlobe stats={stats} />
            <div className="absolute bottom-4 left-4 flex items-center gap-2 font-label text-[10px] uppercase text-[#8c909f]">
              <span className="h-2 w-2 rounded-full bg-[#4ae176] shadow-[0_0_10px_#4ae176]" />
              Live correlation - {range}
            </div>
          </div>
          <div className="grid grid-cols-2 border-t border-white/10 md:grid-cols-4">
            <SignalCount label="Identity" value={stats.counts.critical} />
            <SignalCount label="Network" value={stats.counts.high} />
            <SignalCount label="Cloud" value={stats.counts.medium} />
            <SignalCount label="Endpoint" value={stats.total} />
          </div>
        </article>

        <article className="border border-white/10 bg-[#10182b]">
          <PanelHeader
            eyebrow="Priority queue"
            title="Incidents"
            action={
              <button
                type="button"
                onClick={() => showNotice("Vista completa de incidentes lista")}
                className="inline-flex items-center gap-1 text-xs text-[#9ef0b6]"
              >
                Ver todo
                <ChevronRight size={14} />
              </button>
            }
          />

          <div>
            {error && (
              <div className="m-4 border border-[#ffb4ab]/25 bg-[#3a1619] p-3 text-sm text-[#ffd6d2]">
                {error}
              </div>
            )}
            {!loading && incidentRows.length === 0 && !error && (
              <div className="m-4 border border-white/10 bg-[#0b1020] p-4 text-sm text-[#aeb7ca]">
                No hay incidentes activos en la ultima sincronizacion.
              </div>
            )}
            {incidentRows.map((incident, index) => (
              <button
                key={`${incident.id}-${incident.meta}`}
                type="button"
                onClick={() => showNotice(`Investigando: ${incident.title}`)}
                className="grid w-full grid-cols-[76px_1fr_42px_36px] items-center gap-3 border-b border-white/10 px-4 py-4 text-left transition-colors hover:bg-[#151f32]"
              >
                <span className={severityClass(incident.severity)}>{incident.severity}</span>
                <span className="min-w-0">
                  <strong className="block truncate text-sm text-white">{incident.title}</strong>
                  <small className="mt-1 block truncate text-xs text-[#8c909f]">{incident.meta}</small>
                </span>
                <em className="text-lg not-italic text-[#ff8d96]">{incident.score}</em>
                <time className="text-xs text-[#8c909f]">{incident.time || `${index + 1}m`}</time>
              </button>
            ))}
          </div>
        </article>

        <article className="border border-white/10 bg-[#10182b] xl:col-span-1">
          <PanelHeader
            eyebrow="Detection velocity"
            title="Signal intelligence"
            action={
              <span className="inline-flex items-center gap-2 font-label text-[10px] uppercase text-[#9ef0b6]">
                <span className="h-0.5 w-5 bg-[#4ae176]" />
                High fidelity
              </span>
            }
          />
          <div className="relative h-56 px-5 pb-5 pt-3">
            <svg viewBox="0 0 700 180" preserveAspectRatio="none" className="h-full w-full">
              <defs>
                <linearGradient id="signalFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0" stopColor="#78ffbd" stopOpacity=".32" />
                  <stop offset="1" stopColor="#78ffbd" stopOpacity="0" />
                </linearGradient>
              </defs>
              <path
                d="M0 145 C50 140 60 90 105 105 S170 125 210 82 S280 40 320 94 S380 125 420 72 S495 30 530 80 S600 120 700 28 L700 180 L0 180Z"
                fill="url(#signalFill)"
              />
              <path
                d="M0 145 C50 140 60 90 105 105 S170 125 210 82 S280 40 320 94 S380 125 420 72 S495 30 530 80 S600 120 700 28"
                fill="none"
                stroke="#78ffbd"
                strokeWidth="2"
              />
            </svg>
            <div className="absolute inset-x-5 bottom-3 flex justify-between font-label text-[10px] text-[#5f687a]">
              <span>00:00</span>
              <span>06:00</span>
              <span>12:00</span>
              <span>18:00</span>
              <span>NOW</span>
            </div>
          </div>
        </article>

        <article className="border border-white/10 bg-[#10182b] xl:col-span-1">
          <PanelHeader eyebrow="Infrastructure" title="Runtime telemetry" />
          <div className="space-y-5 p-5">
            <Gauge label="CPU" value={stats.cpu} color="#78ffbd" />
            <Gauge label="RAM" value={stats.ram} color="#adc6ff" />
            <Gauge label="GPU" value={stats.gpu} color="#9b7cff" />
            <Gauge
              label="Latency"
              value={stats.latency}
              suffix="ms"
              max={500}
              color="#5ee7ff"
            />
            <div className="border border-white/10 bg-[#0b1020] p-3">
              <div className="text-xs text-[#8c909f]">Bandwidth</div>
              <div className="mt-1 text-lg font-semibold text-white">
                {stats.bandwidth === null ? "N/A" : `${stats.bandwidth.toFixed(2)} Mb/s`}
              </div>
            </div>
          </div>
        </article>

        <article className="border border-white/10 bg-[#10182b] xl:col-span-2">
          <div className="flex flex-col gap-5 p-5 md:flex-row md:items-center md:justify-between">
            <div className="flex items-start gap-4">
              <div className="grid h-12 w-12 place-items-center border border-[#9b7cff]/30 bg-[#1a1531] text-[#c8bbff]">
                <Sparkles size={24} />
              </div>
              <div>
                <div className="font-label text-[10px] uppercase text-[#8c909f]">
                  Purple team playground
                </div>
                <h3 className="mt-1 font-headline text-xl font-bold text-white">
                  Valida antes de que ataquen.
                </h3>
                <p className="mt-2 max-w-2xl text-sm leading-6 text-[#aeb7ca]">
                  Ejecuta simulaciones gobernadas contra controles defensivos y cruza resultados
                  con MITRE ATT&CK, ARES y el registro de auditoria.
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setCopilotOpen(true)}
              className="inline-flex h-11 items-center justify-center gap-2 bg-[#78ffbd] px-4 text-sm font-bold text-[#07130c]"
            >
              Abrir Aegis AI
              <ArrowUpRight size={17} />
            </button>
          </div>
        </article>
      </section>

      {copilotOpen && (
        <AegisDrawer
          contained={contained}
          onClose={() => setCopilotOpen(false)}
          onContain={() => {
            setContained(true);
            showNotice("Flujo de contencion autorizado");
          }}
        />
      )}

      {notice && (
        <div className="fixed bottom-6 left-1/2 z-50 -translate-x-1/2 bg-[#e5fff1] px-5 py-3 text-sm font-bold text-[#07130c] shadow-2xl">
          <Check size={16} className="mr-2 inline" />
          {notice}
        </div>
      )}
    </div>
  );
}

function PanelHeader({ eyebrow, title, action }) {
  return (
    <div className="flex min-h-16 items-center justify-between border-b border-white/10 px-5">
      <div>
        <div className="font-label text-[10px] uppercase text-[#8c909f]">{eyebrow}</div>
        <h3 className="mt-1 font-headline text-base font-bold text-white">{title}</h3>
      </div>
      {action}
    </div>
  );
}

function MetricTile({ label, value, delta, tone = "neutral" }) {
  const color = tone === "danger" ? "text-[#ff8d96]" : tone === "success" ? "text-[#78ffbd]" : "text-white";
  return (
    <article className="border-b border-r border-white/10 p-5 last:border-r-0 xl:border-b-0">
      <div className="flex items-center justify-between font-label text-[10px] uppercase text-[#8c909f]">
        <span>{label}</span>
        {tone === "danger" && <span className="h-2 w-2 rounded-full bg-[#ff5d68]" />}
      </div>
      <strong className={`mt-3 block text-3xl font-bold ${color}`}>{value}</strong>
      <small className="mt-2 block text-xs text-[#8c909f]">{delta}</small>
    </article>
  );
}

function SignalGlobe({ stats }) {
  const nodes = [
    { label: "IDENTITY", className: "left-[22%] top-[27%]", color: "#ff5d68" },
    { label: "NETWORK", className: "right-[16%] top-[45%]", color: "#78ffbd" },
    { label: "AUTH-DB", className: "left-[43%] bottom-[20%]", color: "#5ee7ff" },
  ];

  return (
    <div className="relative h-64 w-64 rounded-full border border-[#4d746b] shadow-[inset_0_0_60px_rgba(74,225,118,0.12),0_0_70px_rgba(74,225,118,0.10)]">
      <div className="absolute inset-x-[28%] inset-y-0 rounded-full border border-[#284f4b]" />
      <div className="absolute inset-x-[42%] inset-y-0 rounded-full border border-[#284f4b]" />
      <div className="absolute inset-x-0 inset-y-[28%] rounded-full border border-[#284f4b]" />
      <div className="absolute inset-x-0 inset-y-[43%] rounded-full border border-[#284f4b]" />
      <div className="absolute left-[28%] top-[30%] h-px w-32 rotate-[25deg] bg-gradient-to-r from-[#ff5d68] to-[#78ffbd]" />
      <div className="absolute left-[45%] top-[54%] h-px w-24 -rotate-[52deg] bg-gradient-to-r from-[#5ee7ff] to-transparent" />
      {nodes.map((node) => (
        <div key={node.label} className={`absolute ${node.className}`}>
          <span
            className="block h-3 w-3 rounded-full border-2 border-white"
            style={{ backgroundColor: node.color, boxShadow: `0 0 18px ${node.color}` }}
          />
          <span className="absolute top-4 whitespace-nowrap font-label text-[9px] text-[#dbe7ff]">
            {node.label}
          </span>
        </div>
      ))}
      <div className="absolute inset-0 grid place-items-center">
        <div className="text-center">
          <div className="text-5xl font-bold text-white">{stats.threatScore}</div>
          <div className="font-label text-[10px] uppercase text-[#8c909f]">Threat score</div>
        </div>
      </div>
    </div>
  );
}

function SignalCount({ label, value }) {
  return (
    <div className="border-r border-white/10 p-4 last:border-r-0">
      <div className="font-label text-[10px] uppercase text-[#8c909f]">{label}</div>
      <div className="mt-1 text-xl font-bold text-white">{value}</div>
    </div>
  );
}

function Gauge({ label, value, suffix = "%", max = 100, color }) {
  const numeric = value === null ? 0 : Math.min(Number(value) || 0, max);
  const width = `${Math.max(0, Math.min((numeric / max) * 100, 100))}%`;
  return (
    <div>
      <div className="mb-2 flex justify-between text-sm">
        <span className="text-[#dbe7ff]">{label}</span>
        <span style={{ color }}>{value === null ? "N/A" : `${Number(value).toFixed(1)}${suffix}`}</span>
      </div>
      <div className="h-2 bg-[#0b1020]">
        <div className="h-full" style={{ width, backgroundColor: color }} />
      </div>
    </div>
  );
}

function AegisDrawer({ contained, onClose, onContain }) {
  return (
    <aside className="fixed bottom-0 right-0 top-0 z-50 flex w-full max-w-md flex-col border-l border-white/10 bg-[#0b1116] shadow-2xl">
      <div className="flex h-16 items-center justify-between border-b border-white/10 px-5">
        <div className="flex items-center gap-3">
          <Sparkles size={22} className="text-[#78ffbd]" />
          <div>
            <b className="text-white">Aegis AI</b>
            <small className="block font-label text-[10px] uppercase text-[#78ffbd]">
              Security copilot online
            </small>
          </div>
        </div>
        <button type="button" onClick={onClose} className="text-[#8c909f] hover:text-white">
          <X size={22} />
        </button>
      </div>

      <div className="custom-scrollbar flex-1 overflow-y-auto p-5">
        <section className="border-l-2 border-[#78ffbd] pl-4">
          <div className="font-label text-[10px] uppercase text-[#8c909f]">
            Autonomous briefing
          </div>
          <h3 className="mt-2 text-2xl font-bold text-white">
            Una ruta critica requiere atencion.
          </h3>
          <p className="mt-3 text-sm leading-6 text-[#aeb7ca]">
            Una identidad privilegiada inicio acceso anomalo. La confianza es alta por
            correlacion entre identidad, red y endpoint.
          </p>
        </section>

        <div className="my-6 space-y-4">
          <FlowStep number="1" title="Initial access" detail="OAuth token replay" />
          <FlowStep number="2" title="Privilege escalation" detail="Role assignment anomaly" />
          <FlowStep number="3" title="Lateral movement" detail="2 assets reached" />
        </div>

        <section className="border border-white/10 bg-[#111a20] p-4">
          <div className="font-label text-[10px] uppercase text-[#8c909f]">
            Recommended action
          </div>
          <b className="mt-2 block text-white">Contener identidad + aislar 2 hosts</b>
          <p className="mt-2 text-sm text-[#aeb7ca]">
            Reduccion estimada del radio de impacto: 94%.
          </p>
          <button
            type="button"
            onClick={onContain}
            className={[
              "mt-4 w-full px-4 py-3 text-sm font-bold",
              contained ? "bg-[#21342b] text-[#78ffbd]" : "bg-[#78ffbd] text-[#07130c]",
            ].join(" ")}
          >
            {contained ? "Contencion en cola" : "Revisar y autorizar"}
          </button>
        </section>
      </div>

      <div className="flex gap-2 border-t border-white/10 p-4">
        <input
          aria-label="Ask Aegis AI"
          placeholder="Pregunta sobre este incidente..."
          className="h-11 flex-1 border border-white/10 bg-[#111920] px-3 text-sm text-white outline-none"
        />
        <button type="button" className="grid h-11 w-11 place-items-center bg-[#78ffbd] text-[#07130c]">
          <Bot size={18} />
        </button>
      </div>
    </aside>
  );
}

function FlowStep({ number, title, detail }) {
  return (
    <div className="flex gap-3">
      <i className="grid h-7 w-7 shrink-0 place-items-center rounded-full border border-[#486058] text-xs not-italic text-[#78ffbd]">
        {number}
      </i>
      <span>
        <b className="block text-sm text-white">{title}</b>
        <small className="text-xs text-[#8c909f]">{detail}</small>
      </span>
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

function normalizeSeverity(value) {
  const severity = String(value || "").toLowerCase();
  if (severity === "critical") return "critical";
  if (severity === "warning" || severity === "high") return "high";
  return "medium";
}

function severityClass(severity) {
  const base = "font-label text-[9px] uppercase border px-2 py-1 text-center";
  if (severity === "critical") return `${base} border-[#ff5d68]/50 text-[#ff8d96]`;
  if (severity === "high") return `${base} border-[#ffb454]/50 text-[#ffcc7a]`;
  return `${base} border-[#9b7cff]/50 text-[#c8bbff]`;
}

function formatShortAge(dateLike) {
  const diffMs = Date.now() - new Date(dateLike).getTime();
  if (!Number.isFinite(diffMs) || diffMs < 0) return "ahora";
  const minutes = Math.max(1, Math.floor(diffMs / 60000));
  if (minutes < 60) return `${minutes}m`;
  return `${Math.floor(minutes / 60)}h`;
}

function postureLabel(score) {
  if (score >= 85) return "Postura fuerte";
  if (score >= 65) return "Postura vigilada";
  return "Postura degradada";
}

function deltaText(stats) {
  if (stats.counts.critical > 0) return `${stats.counts.critical} criticas`;
  if (stats.counts.high > 0) return `${stats.counts.high} altas`;
  return "Sin criticas";
}

function PostureRing({ score }) {
  return (
    <div
      className="relative grid h-16 w-16 place-items-center rounded-full"
      style={{
        background: `conic-gradient(#78ffbd 0 ${score}%, #223028 ${score}% 100%)`,
      }}
    >
      <div className="absolute inset-1 rounded-full bg-[#10182b]" />
      <span className="relative z-10 text-lg font-bold text-[#78ffbd]">{score}</span>
    </div>
  );
}
