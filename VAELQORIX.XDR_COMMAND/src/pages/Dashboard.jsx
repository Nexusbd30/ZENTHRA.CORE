import { createElement, useEffect, useMemo, useState } from "react";
import {
  ArrowRight,
  Bot,
  Check,
  ChevronRight,
  Clock3,
  Crosshair,
  Fingerprint,
  Network,
  Radar,
  ServerCog,
  ShieldCheck,
  Sparkles,
  X,
  Zap,
} from "lucide-react";

import { getAlerts, getHostSummary } from "@/api/vaelqorixApi";
import { useAuth } from "@/hooks/useAuth";

const AUTO_REFRESH_MS = 10000;
const METRICS_REFRESH_MS = 15000;
const RANGES = ["1H", "24H", "7D"];

export default function Dashboard() {
  const { user } = useAuth();
  const [alerts, setAlerts] = useState([]);
  const [hostMetrics, setHostMetrics] = useState({
    cpu: null,
    ram: null,
    bandwidth: null,
    latency: null,
    gpu: null,
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
    const postureScore = Math.max(1, Math.min(99, 94 - counts.critical * 12 - counts.high * 7 - counts.medium * 2));
    return {
      total: alerts.length,
      counts,
      postureScore,
      threatScore: Math.min(100, counts.critical * 30 + counts.high * 15 + counts.medium * 6),
      cpu: clampPercent(hostMetrics.cpu),
      ram: clampPercent(hostMetrics.ram),
      gpu: clampPercent(hostMetrics.gpu),
      bandwidth: nullableNumber(hostMetrics.bandwidth),
      latency: nullableNumber(hostMetrics.latency),
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
          score: severity === "critical" ? 96 - index : severity === "high" ? 84 - index : 62 - index,
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
    <div className="mx-auto min-h-full max-w-[1680px]">
      <section className="mb-5 flex flex-col gap-4 border-b border-[var(--vx-line-soft)] pb-5 xl:flex-row xl:items-end xl:justify-between">
        <div>
          <div className="vx-eyebrow flex items-center gap-2 text-[var(--vx-safe)]">
            <span className="vx-status-dot" /> Centro de operaciones - sincronizacion activa
          </div>
          <h2 className="vx-title mt-2 text-2xl sm:text-[1.75rem]">Buenos dias, {analystName}</h2>
          <p className="mt-1.5 max-w-2xl text-sm text-[var(--vx-text-muted)]">
            Prioriza el riesgo, valida la evidencia y ejecuta la siguiente accion segura.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="flex h-10 items-center gap-2 border border-[var(--vx-line)] bg-[var(--vx-panel)] px-3 text-xs text-[var(--vx-text-muted)]">
            <Clock3 size={14} /> Actualizado ahora
          </span>
          <div className="vx-segmented" aria-label="Rango temporal">
            {RANGES.map((item) => (
              <button key={item} type="button" aria-pressed={range === item} onClick={() => setRange(item)}>
                {item}
              </button>
            ))}
          </div>
        </div>
      </section>

      <section className="vx-kpi-grid mb-4" aria-label="Indicadores clave">
        <MetricTile label="Incidentes activos" value={loading ? "-" : stats.total} detail={deltaText(stats)} tone={stats.counts.critical ? "critical" : "neutral"} icon={Crosshair} />
        <MetricTile label="Riesgo priorizado" value={stats.threatScore} suffix="/100" detail="Correlacion multivector" tone={stats.threatScore > 70 ? "critical" : "warning"} icon={Radar} />
        <MetricTile label="Postura de seguridad" value={stats.postureScore} suffix="%" detail={postureLabel(stats.postureScore)} tone="safe" icon={ShieldCheck} />
        <MetricTile label="Fuentes conectadas" value={stats.topSources.length || "N/A"} detail="Identidad - red - cloud - endpoint" tone="info" icon={Network} />
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.65fr)_minmax(360px,0.9fr)]">
        <article className="vx-panel overflow-hidden">
          <PanelHeader
            eyebrow="Correlacion en vivo"
            title="Cadena de ataque"
            action={<span className="flex items-center gap-2 text-xs font-medium text-[var(--vx-safe)]"><span className="vx-status-dot" /> Alta fidelidad</span>}
          />
          <AttackPath stats={stats} range={range} />
          <div className="grid grid-cols-2 border-t border-[var(--vx-line-soft)] sm:grid-cols-4">
            <SignalCount icon={Fingerprint} label="Identidad" value={stats.counts.critical} />
            <SignalCount icon={Network} label="Red" value={stats.counts.high} />
            <SignalCount icon={ServerCog} label="Cloud" value={stats.counts.medium} />
            <SignalCount icon={Zap} label="Endpoint" value={stats.total} />
          </div>
        </article>

        <article className="vx-panel min-w-0 overflow-hidden">
          <PanelHeader
            eyebrow="Cola priorizada"
            title="Incidentes que requieren decision"
            action={<button type="button" onClick={() => showNotice("Vista completa de incidentes lista")} className="flex items-center gap-1 text-xs font-semibold text-[var(--vx-cyan)]">Ver todo <ChevronRight size={14} /></button>}
          />
          {error && <div className="m-4 border border-[var(--vx-critical)]/30 bg-[#2b141a] p-3 text-sm text-[#ffb4bd]">{error}</div>}
          {!loading && incidentRows.length === 0 && !error && <div className="m-4 border border-[var(--vx-line)] bg-[#0b1017] p-4 text-sm text-[var(--vx-text-muted)]">No hay incidentes activos en la ultima sincronizacion.</div>}
          <div className="divide-y divide-[var(--vx-line-soft)]">
            {incidentRows.map((incident) => (
              <button key={`${incident.id}-${incident.meta}`} type="button" onClick={() => showNotice(`Investigando: ${incident.title}`)} className="group grid w-full grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3 px-4 py-3.5 text-left transition-colors hover:bg-[var(--vx-panel-hover)]">
                <span className={severityClass(incident.severity)}>{incident.score}</span>
                <span className="min-w-0">
                  <span className="block truncate text-sm font-semibold text-[var(--vx-text)]">{incident.title}</span>
                  <span className="mt-1 flex items-center gap-2 text-xs text-[var(--vx-text-dim)]">
                    <span className="uppercase">{incident.severity}</span>
                    <span aria-hidden="true">-</span>
                    <span className="truncate">{incident.meta}</span>
                    <span aria-hidden="true">-</span>
                    <time>{incident.time}</time>
                  </span>
                </span>
                <ArrowRight size={15} className="text-[var(--vx-text-dim)] group-hover:text-white" />
              </button>
            ))}
          </div>
        </article>

        <article className="vx-panel overflow-hidden">
          <PanelHeader eyebrow="Volumen y confianza" title="Inteligencia de senales" />
          <SignalChart />
        </article>
        <article className="vx-panel overflow-hidden">
          <PanelHeader eyebrow="Infraestructura" title="Telemetria de ejecucion" />
          <div className="grid gap-x-6 gap-y-4 p-4 sm:grid-cols-2">
            <Gauge label="CPU" value={stats.cpu} color="var(--vx-cyan)" />
            <Gauge label="RAM" value={stats.ram} color="var(--vx-info)" />
            <Gauge label="GPU" value={stats.gpu} color="var(--vx-accent)" />
            <Gauge label="Latencia" value={stats.latency} suffix="ms" max={500} color="var(--vx-warning)" />
          </div>
          <div className="flex items-center justify-between border-t border-[var(--vx-line-soft)] px-4 py-3 text-sm">
            <span className="text-[var(--vx-text-muted)]">Ancho de banda</span>
            <strong className="font-mono text-white">{stats.bandwidth === null ? "N/A" : `${stats.bandwidth.toFixed(2)} Mb/s`}</strong>
          </div>
        </article>

        <article className="vx-panel xl:col-span-2">
          <div className="flex flex-col gap-5 p-5 md:flex-row md:items-center md:justify-between">
            <div className="flex items-start gap-4">
              <div className="grid h-11 w-11 shrink-0 place-items-center border border-[var(--vx-accent)]/35 bg-[var(--vx-accent-soft)] text-[#c8c1ff]">
                <Sparkles size={21} />
              </div>
              <div>
                <div className="vx-eyebrow">Siguiente mejor accion - ARES</div>
                <h3 className="vx-title mt-1 text-lg">Valida la contencion antes de ejecutarla</h3>
                <p className="mt-1 max-w-2xl text-sm leading-6 text-[var(--vx-text-muted)]">
                  Revisa la cadena causal, el radio de impacto y los controles de autorizacion humana.
                </p>
              </div>
            </div>
            <button type="button" onClick={() => setCopilotOpen(true)} className="vx-button-primary shrink-0">
              Abrir ARESX <ArrowRight size={16} />
            </button>
          </div>
        </article>
      </section>

      {copilotOpen && (
        <AresXDrawer
          contained={contained}
          onClose={() => setCopilotOpen(false)}
          onContain={() => {
            setContained(true);
            showNotice("Flujo de contencion autorizado");
          }}
        />
      )}
      {notice && (
        <div role="status" className="fixed bottom-6 left-1/2 z-50 flex -translate-x-1/2 items-center gap-2 border border-[var(--vx-safe)]/30 bg-[#dff9e9] px-4 py-3 text-sm font-bold text-[#0b2114] shadow-2xl">
          <Check size={16} /> {notice}
        </div>
      )}
    </div>
  );
}

function PanelHeader({ eyebrow, title, action }) {
  return (
    <div className="vx-panel-header">
      <div>
        <div className="vx-eyebrow">{eyebrow}</div>
        <h3 className="vx-title mt-0.5 text-base">{title}</h3>
      </div>
      {action}
    </div>
  );
}

function MetricTile({ label, value, suffix, detail, tone, icon: Icon }) {
  const colors = {
    critical: "var(--vx-critical)",
    warning: "var(--vx-warning)",
    safe: "var(--vx-safe)",
    info: "var(--vx-cyan)",
    neutral: "var(--vx-text)",
  };
  return (
    <article className="vx-kpi">
      <div className="flex items-center justify-between gap-2">
        <span className="vx-eyebrow">{label}</span>
        {createElement(Icon, { size: 16, style: { color: colors[tone] } })}
      </div>
      <div className="mt-2 flex items-baseline gap-1">
        <strong className="font-headline text-[1.75rem] leading-none" style={{ color: colors[tone] }}>
          {value}
        </strong>
        {suffix && <span className="text-xs text-[var(--vx-text-dim)]">{suffix}</span>}
      </div>
      <p className="mt-2 truncate text-xs text-[var(--vx-text-muted)]">{detail}</p>
    </article>
  );
}

function AttackPath({ stats, range }) {
  const stages = [
    { label: "Acceso inicial", code: "TA0001", value: stats.counts.medium, tone: "info" },
    { label: "Credenciales", code: "TA0006", value: stats.counts.critical, tone: "critical" },
    { label: "Movimiento lateral", code: "TA0008", value: stats.counts.high, tone: "warning" },
    { label: "Impacto", code: "TA0040", value: stats.total, tone: "accent" },
  ];
  const toneColor = {
    info: "var(--vx-cyan)",
    critical: "var(--vx-critical)",
    warning: "var(--vx-warning)",
    accent: "var(--vx-accent)",
  };
  return (
    <div className="vx-data-grid relative min-h-[310px] overflow-hidden bg-[#0a0f16] p-5 sm:p-7">
      <div className="relative flex min-h-[245px] flex-col justify-center">
        <div className="mb-7 flex items-end justify-between gap-4">
          <div>
            <div className="vx-eyebrow">Puntuacion de riesgo compuesto</div>
            <div className="mt-1 flex items-end gap-3">
              <strong className="font-headline text-5xl font-semibold leading-none text-white">{stats.threatScore}</strong>
              <span className="pb-1 text-sm text-[var(--vx-text-muted)]">de 100 - {range}</span>
            </div>
          </div>
          <span className="hidden max-w-[220px] text-right text-xs leading-5 text-[var(--vx-text-dim)] sm:block">
            Senales correlacionadas por identidad, red, cloud y endpoint.
          </span>
        </div>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-4 sm:gap-0">
          {stages.map((stage, index) => (
            <div key={stage.code} className="relative sm:pr-3">
              {index < stages.length - 1 && <div className="absolute left-[calc(50%+20px)] right-[-2px] top-4 hidden h-px bg-[var(--vx-line)] sm:block" />}
              <div className="relative flex items-center gap-3 sm:block">
                <span className="relative z-10 grid h-8 w-8 shrink-0 place-items-center border bg-[#0a0f16] font-mono text-xs font-bold" style={{ borderColor: toneColor[stage.tone], color: toneColor[stage.tone] }}>
                  {stage.value}
                </span>
                <div className="sm:mt-3">
                  <div className="text-sm font-semibold text-white">{stage.label}</div>
                  <div className="mt-0.5 font-mono text-[10px] text-[var(--vx-text-dim)]">{stage.code}</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function SignalCount({ icon: Icon, label, value }) {
  return (
    <div className="flex items-center gap-3 border-b border-r border-[var(--vx-line-soft)] p-3 last:border-r-0 sm:border-b-0">
      {createElement(Icon, { size: 16, className: "text-[var(--vx-text-dim)]" })}
      <div>
        <div className="vx-eyebrow">{label}</div>
        <div className="mt-0.5 text-base font-semibold text-white">{value}</div>
      </div>
    </div>
  );
}

function SignalChart() {
  return (
    <div className="relative h-[186px] px-4 pb-4 pt-3">
      <div className="absolute inset-x-4 bottom-9 top-4 flex flex-col justify-between" aria-hidden="true">
        {[0, 1, 2, 3].map((line) => (
          <span key={line} className="border-t border-[var(--vx-line-soft)]" />
        ))}
      </div>
      <svg viewBox="0 0 700 145" preserveAspectRatio="none" className="relative h-[140px] w-full" aria-label="Tendencia de senales">
        <defs>
          <linearGradient id="vxSignalFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#58d8f5" stopOpacity=".2" />
            <stop offset="1" stopColor="#58d8f5" stopOpacity="0" />
          </linearGradient>
        </defs>
        <path d="M0 125 C45 119 64 86 105 94 S165 112 210 76 S278 42 322 82 S383 102 425 67 S491 39 535 70 S610 94 700 30 L700 145 L0 145Z" fill="url(#vxSignalFill)" />
        <path d="M0 125 C45 119 64 86 105 94 S165 112 210 76 S278 42 322 82 S383 102 425 67 S491 39 535 70 S610 94 700 30" fill="none" stroke="#58d8f5" strokeWidth="2" />
      </svg>
      <div className="flex justify-between font-mono text-[10px] text-[var(--vx-text-dim)]">
        <span>00:00</span>
        <span>06:00</span>
        <span>12:00</span>
        <span>18:00</span>
        <span>AHORA</span>
      </div>
    </div>
  );
}

function Gauge({ label, value, suffix = "%", max = 100, color }) {
  const numeric = value === null ? 0 : Math.min(Number(value) || 0, max);
  const width = `${Math.max(0, Math.min((numeric / max) * 100, 100))}%`;
  return (
    <div>
      <div className="mb-2 flex justify-between text-xs">
        <span className="text-[var(--vx-text-muted)]">{label}</span>
        <span className="font-mono" style={{ color }}>
          {value === null ? "N/A" : `${Number(value).toFixed(1)}${suffix}`}
        </span>
      </div>
      <div className="h-1.5 bg-[#080c12]">
        <div className="h-full" style={{ width, backgroundColor: color }} />
      </div>
    </div>
  );
}

function AresXDrawer({ contained, onClose, onContain }) {
  return (
    <aside className="fixed inset-y-0 right-0 z-50 flex w-full max-w-md flex-col border-l border-[var(--vx-line)] bg-[#0b1017] shadow-2xl">
      <div className="flex h-[72px] items-center justify-between border-b border-[var(--vx-line)] px-5">
        <div className="flex items-center gap-3">
          <div className="grid h-9 w-9 place-items-center bg-[var(--vx-accent-soft)] text-[#c8c1ff]">
            <Sparkles size={18} />
          </div>
          <div>
            <b className="text-white">ARESX</b>
            <small className="vx-eyebrow block text-[var(--vx-safe)]">Copiloto operativo</small>
          </div>
        </div>
        <button type="button" onClick={onClose} className="vx-icon-button" aria-label="Cerrar ARESX">
          <X size={18} />
        </button>
      </div>
      <div className="vx-scrollbar flex-1 overflow-y-auto p-5">
        <section className="border-l-2 border-[var(--vx-accent)] pl-4">
          <div className="vx-eyebrow">Resumen autonomo</div>
          <h3 className="vx-title mt-2 text-xl">Una ruta critica requiere atencion</h3>
          <p className="mt-3 text-sm leading-6 text-[var(--vx-text-muted)]">
            Una identidad privilegiada inicio acceso anomalo. La confianza es alta por correlacion entre identidad, red y endpoint.
          </p>
        </section>
        <div className="my-6 space-y-4">
          <FlowStep number="01" title="Acceso inicial" detail="OAuth token replay" />
          <FlowStep number="02" title="Escalada de privilegios" detail="Role assignment anomaly" />
          <FlowStep number="03" title="Movimiento lateral" detail="2 activos alcanzados" />
        </div>
        <section className="border border-[var(--vx-line)] bg-[var(--vx-panel)] p-4">
          <div className="vx-eyebrow">Accion recomendada</div>
          <b className="mt-2 block text-white">Contener identidad + aislar 2 hosts</b>
          <p className="mt-2 text-sm text-[var(--vx-text-muted)]">Reduccion estimada del radio de impacto: 94%.</p>
          <button type="button" onClick={onContain} className={contained ? "vx-button-secondary mt-4 w-full text-[var(--vx-safe)]" : "vx-button-primary mt-4 w-full"}>
            {contained ? "Contencion en cola" : "Revisar y autorizar"}
          </button>
        </section>
      </div>
      <div className="flex gap-2 border-t border-[var(--vx-line)] p-4">
        <input aria-label="Ask ARESX" placeholder="Pregunta sobre este incidente..." className="h-11 flex-1 border border-[var(--vx-line)] bg-[var(--vx-panel)] px-3 text-sm text-white outline-none focus:border-[var(--vx-cyan)]" />
        <button type="button" className="vx-icon-button h-11 w-11 border-[var(--vx-accent)] text-[#c8c1ff]">
          <Bot size={18} />
        </button>
      </div>
    </aside>
  );
}

function FlowStep({ number, title, detail }) {
  return (
    <div className="flex gap-3">
      <i className="grid h-7 w-7 shrink-0 place-items-center border border-[var(--vx-line)] font-mono text-[10px] not-italic text-[var(--vx-cyan)]">{number}</i>
      <span>
        <b className="block text-sm text-white">{title}</b>
        <small className="text-xs text-[var(--vx-text-muted)]">{detail}</small>
      </span>
    </div>
  );
}

function nullableNumber(value) {
  if (value === null || value === undefined || value === "") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function clampPercent(value) {
  const parsed = nullableNumber(value);
  return parsed === null ? null : Math.max(0, Math.min(parsed, 100));
}

function normalizeSeverity(value) {
  const severity = String(value || "").toLowerCase();
  if (severity === "critical") return "critical";
  if (severity === "warning" || severity === "high") return "high";
  return "medium";
}

function severityClass(severity) {
  const base = "grid h-9 w-9 place-items-center border font-mono text-xs font-bold";
  if (severity === "critical") return `${base} border-[var(--vx-critical)]/50 bg-[#2b141a] text-[var(--vx-critical)]`;
  if (severity === "high") return `${base} border-[var(--vx-warning)]/50 bg-[#291f13] text-[var(--vx-warning)]`;
  return `${base} border-[var(--vx-accent)]/50 bg-[var(--vx-accent-soft)] text-[#b9b0ff]`;
}

function formatShortAge(dateLike) {
  const diffMs = Date.now() - new Date(dateLike).getTime();
  if (!Number.isFinite(diffMs) || diffMs < 0) return "ahora";
  const minutes = Math.max(1, Math.floor(diffMs / 60000));
  return minutes < 60 ? `${minutes}m` : `${Math.floor(minutes / 60)}h`;
}

function postureLabel(score) {
  if (score >= 85) return "Postura fuerte";
  if (score >= 65) return "Postura vigilada";
  return "Postura degradada";
}

function deltaText(stats) {
  if (stats.counts.critical > 0) return `${stats.counts.critical} criticas - actuar ahora`;
  if (stats.counts.high > 0) return `${stats.counts.high} altas - revisar`;
  return "Sin criticas activas";
}
