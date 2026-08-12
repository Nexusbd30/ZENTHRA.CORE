import { createElement } from "react";
import { useNavigate } from "react-router-dom";
import {
  Activity,
  ArrowRight,
  Bell,
  Bot,
  Braces,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Cpu,
  Database,
  Fingerprint,
  Gauge,
  Globe2,
  LockKeyhole,
  Network,
  RadioTower,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Zap,
} from "lucide-react";

import logo from "../assets/logos/vaelqorix-logo.jpeg";

const kpis = [
  { label: "Risk score", value: "82", delta: "+7.4%", tone: "text-[#ffb4ab]" },
  { label: "Active alerts", value: "147", delta: "23 critical", tone: "text-[#ffd166]" },
  { label: "MTTR", value: "11m", delta: "-18%", tone: "text-[#78ffbd]" },
  { label: "Coverage", value: "96%", delta: "2.4M events", tone: "text-[#adc6ff]" },
];

const severity = [
  { label: "Critical", value: 18, width: "72%", color: "bg-[#ff5c5c]" },
  { label: "High", value: 41, width: "64%", color: "bg-[#ffb454]" },
  { label: "Medium", value: 63, width: "48%", color: "bg-[#8ea7ff]" },
  { label: "Low", value: 25, width: "28%", color: "bg-[#78ffbd]" },
];

const incidents = [
  { id: "INC-7429", title: "Lateral movement attempt", source: "endpoint-eu-17", score: "94", state: "Contained" },
  { id: "INC-7418", title: "Suspicious OAuth consent", source: "identity graph", score: "88", state: "Triage" },
  { id: "INC-7404", title: "Beacon over uncommon DNS", source: "edge telemetry", score: "81", state: "Investigate" },
  { id: "INC-7392", title: "Privilege escalation chain", source: "cloud workload", score: "77", state: "Queued" },
];

const telemetry = [
  { label: "Endpoints", value: "18.4k", icon: Cpu },
  { label: "Network flows", value: "7.8M", icon: Network },
  { label: "Identities", value: "43.1k", icon: Fingerprint },
  { label: "Cloud events", value: "1.2M", icon: Database },
];

const events = [
  { time: "09:41", text: "AI analyst correlated 6 signals into incident INC-7429." },
  { time: "09:36", text: "SOAR playbook isolated endpoint-eu-17." },
  { time: "09:28", text: "New Entra risk event mapped to identity graph." },
  { time: "09:17", text: "Alertmanager received Prometheus saturation warning." },
];

const attackPaths = [
  { label: "Email gateway", status: "clean", x: "12%", y: "26%" },
  { label: "Identity", status: "watch", x: "34%", y: "54%" },
  { label: "Endpoint", status: "critical", x: "58%", y: "34%" },
  { label: "Cloud", status: "watch", x: "78%", y: "62%" },
];

export default function Home() {
  const navigate = useNavigate();

  return (
    <main className="min-h-screen bg-[#070a10] text-[#eef3ff]">
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute inset-0 bg-[linear-gradient(90deg,rgba(173,198,255,0.08),transparent_28%,rgba(120,255,189,0.06)_62%,transparent)]" />
        <div className="grid-bg absolute inset-0 opacity-60" />
      </div>

      <section className="relative z-10 mx-auto flex min-h-screen w-full max-w-[1680px] flex-col px-4 py-4 sm:px-6 lg:px-8">
        <header className="flex min-h-16 items-center justify-between border border-white/10 bg-[#0b111c]/92 px-4 shadow-none backdrop-blur-xl sm:px-5">
          <div className="flex min-w-0 items-center gap-3">
            <img src={logo} alt="VAELQORIX" className="h-10 w-10 shrink-0 object-contain" />
            <div className="min-w-0">
              <div className="font-headline text-base font-black uppercase tracking-normal text-white">
                VAELQORIX
              </div>
              <div className="truncate font-label text-[10px] uppercase text-[#8c909f]">
                XDR Command / SOC Operations
              </div>
            </div>
          </div>

          <div className="hidden items-center gap-2 lg:flex">
            <HeaderPill icon={CheckCircle2} label="Backend" value="localhost:8000" tone="text-[#78ffbd]" />
            <HeaderPill icon={RadioTower} label="Telemetry" value="Live" tone="text-[#adc6ff]" />
            <HeaderPill icon={Clock3} label="Shift" value="Blue Team" tone="text-[#ffd166]" />
          </div>

          <button
            type="button"
            onClick={() => navigate("/login")}
            className="inline-flex h-10 shrink-0 items-center justify-center gap-2 bg-[#dbe7ff] px-4 text-sm font-bold text-[#07101d] transition-colors hover:bg-white"
          >
            Login
            <ArrowRight size={16} />
          </button>
        </header>

        <div className="grid flex-1 gap-4 pt-4 xl:grid-cols-[280px_minmax(0,1fr)_360px]">
          <aside className="hidden min-h-0 border border-white/10 bg-[#0b111c]/88 p-4 lg:block">
            <div className="mb-5 flex items-center justify-between">
              <p className="font-label text-[10px] uppercase text-[#8c909f]">Operations</p>
              <span className="h-2 w-2 bg-[#78ffbd]" />
            </div>

            <nav className="space-y-1">
              <SideItem icon={Gauge} label="Executive overview" active />
              <SideItem icon={Siren} label="Threat operations" />
              <SideItem icon={Braces} label="Detection engineering" />
              <SideItem icon={Bot} label="AI analyst" />
              <SideItem icon={Globe2} label="External attack surface" />
              <SideItem icon={LockKeyhole} label="Identity protection" />
            </nav>

            <div className="mt-6 border border-white/10 bg-[#10182b] p-4">
              <p className="font-label text-[10px] uppercase text-[#8c909f]">Autonomous guardrails</p>
              <div className="mt-4 space-y-3">
                <Guardrail label="ARES kill switch" state="Armed" />
                <Guardrail label="Provider policy" state="Tenant scoped" />
                <Guardrail label="Audit stream" state="Immutable" />
              </div>
            </div>
          </aside>

          <div className="min-w-0 space-y-4">
            <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
              <section className="border border-white/10 bg-[#0b111c]/92 p-5 backdrop-blur-xl sm:p-6">
                <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
                  <div className="max-w-3xl">
                    <div className="mb-4 inline-flex items-center gap-2 border border-[#78ffbd]/25 bg-[#10281b] px-3 py-2 font-label text-[10px] uppercase text-[#9ef0b6]">
                      <span className="h-2 w-2 bg-[#78ffbd]" />
                      Unified SOC dashboard
                    </div>
                    <h1 className="font-headline text-3xl font-bold leading-tight tracking-normal text-white sm:text-4xl lg:text-5xl">
                      Command center para detectar, priorizar y responder en tiempo real.
                    </h1>
                    <p className="mt-4 max-w-2xl text-sm leading-6 text-[#aeb7ca] sm:text-base">
                      Vista ejecutiva y operativa de alertas, telemetria, identidad, red,
                      infraestructura y AI Security en una superficie compacta.
                    </p>
                  </div>

                  <div className="grid min-w-[220px] grid-cols-2 gap-2">
                    <ActionButton label="Entrar" onClick={() => navigate("/login")} primary />
                    <ActionButton label="Panel" onClick={() => navigate("/dashboard")} />
                    <ActionButton label="Alertas" onClick={() => navigate("/dashboard/alerts")} />
                    <ActionButton label="Logs" onClick={() => navigate("/dashboard/logs")} />
                  </div>
                </div>
              </section>

              <section className="border border-white/10 bg-[#0b111c]/92 p-5">
                <div className="mb-4 flex items-center justify-between">
                  <p className="font-label text-[10px] uppercase text-[#8c909f]">AI readiness</p>
                  <Zap size={18} className="text-[#78ffbd]" />
                </div>
                <div className="flex items-end gap-3">
                  <span className="font-headline text-5xl font-bold text-white">91</span>
                  <span className="mb-2 text-sm font-semibold text-[#78ffbd]">+12 today</span>
                </div>
                <p className="mt-3 text-sm leading-6 text-[#aeb7ca]">
                  Model routing, tenant policy and SOC approvals are ready for controlled response.
                </p>
                <div className="mt-5 grid grid-cols-6 gap-1">
                  {[65, 78, 58, 88, 72, 96].map((height, index) => (
                    <span
                      key={index}
                      className="block bg-[#adc6ff]/80"
                      style={{ height: `${height}px` }}
                    />
                  ))}
                </div>
              </section>
            </div>

            <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              {kpis.map((item) => (
                <article key={item.label} className="border border-white/10 bg-[#10182b]/92 p-4">
                  <div className="flex items-center justify-between">
                    <p className="font-label text-[10px] uppercase text-[#8c909f]">{item.label}</p>
                    <Activity size={16} className="text-[#46516a]" />
                  </div>
                  <div className="mt-4 flex items-end justify-between gap-3">
                    <span className="font-headline text-4xl font-bold tracking-normal text-white">
                      {item.value}
                    </span>
                    <span className={`text-sm font-semibold ${item.tone}`}>{item.delta}</span>
                  </div>
                </article>
              ))}
            </section>

            <div className="grid gap-4 2xl:grid-cols-[minmax(0,1fr)_420px]">
              <section className="min-h-[430px] border border-white/10 bg-[#0b111c]/92 p-5">
                <PanelTitle icon={Network} title="Attack surface map" meta="Live correlation" />
                <div className="relative mt-5 h-[340px] overflow-hidden border border-white/10 bg-[#050912]">
                  <div className="absolute inset-0 grid-bg opacity-90" />
                  <svg className="absolute inset-0 h-full w-full" role="img" aria-label="Attack path links">
                    <line x1="12%" y1="26%" x2="34%" y2="54%" stroke="#51617d" strokeWidth="1" />
                    <line x1="34%" y1="54%" x2="58%" y2="34%" stroke="#ffb454" strokeWidth="1.5" />
                    <line x1="58%" y1="34%" x2="78%" y2="62%" stroke="#51617d" strokeWidth="1" />
                    <line x1="18%" y1="76%" x2="58%" y2="34%" stroke="#31405a" strokeWidth="1" />
                  </svg>
                  <div className="absolute bottom-7 left-7 right-7 h-14 border border-[#22304a] bg-[#09101d]/90 px-4 py-3">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-label uppercase text-[#8c909f]">Correlation path</span>
                      <span className="font-semibold text-[#ffb4ab]">4 linked detections</span>
                    </div>
                    <div className="mt-2 h-1 bg-[#1c2638]">
                      <div className="h-full w-[74%] bg-[#ffb454]" />
                    </div>
                  </div>
                  {attackPaths.map((node) => (
                    <MapNode key={node.label} {...node} />
                  ))}
                </div>
              </section>

              <section className="border border-white/10 bg-[#0b111c]/92 p-5">
                <PanelTitle icon={ShieldAlert} title="Severity distribution" meta="Last 24h" />
                <div className="mt-5 space-y-4">
                  {severity.map((item) => (
                    <div key={item.label}>
                      <div className="mb-2 flex items-center justify-between text-sm">
                        <span className="text-[#dbe7ff]">{item.label}</span>
                        <span className="font-label text-xs text-[#8c909f]">{item.value}</span>
                      </div>
                      <div className="h-2 bg-[#1a2334]">
                        <div className={`h-full ${item.color}`} style={{ width: item.width }} />
                      </div>
                    </div>
                  ))}
                </div>

                <div className="mt-7 border border-white/10 bg-[#10182b] p-4">
                  <p className="font-label text-[10px] uppercase text-[#8c909f]">Decision queue</p>
                  <div className="mt-4 flex items-center justify-between">
                    <span className="font-headline text-3xl font-bold text-white">12</span>
                    <span className="text-sm font-semibold text-[#ffd166]">Require approval</span>
                  </div>
                </div>
              </section>
            </div>
          </div>

          <aside className="min-w-0 space-y-4">
            <section className="border border-white/10 bg-[#0b111c]/92 p-5">
              <PanelTitle icon={Bell} title="Incident queue" meta="Priority" />
              <div className="mt-4 space-y-3">
                {incidents.map((incident) => (
                  <button
                    key={incident.id}
                    type="button"
                    onClick={() => navigate("/dashboard")}
                    className="group w-full border border-white/10 bg-[#10182b] p-3 text-left transition-colors hover:border-[#adc6ff]/40"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="font-label text-[10px] uppercase text-[#8c909f]">{incident.id}</p>
                        <p className="mt-1 truncate text-sm font-semibold text-white">{incident.title}</p>
                        <p className="mt-1 text-xs text-[#8c909f]">{incident.source}</p>
                      </div>
                      <span className="shrink-0 text-sm font-bold text-[#ffb4ab]">{incident.score}</span>
                    </div>
                    <div className="mt-3 flex items-center justify-between text-xs">
                      <span className="text-[#adc6ff]">{incident.state}</span>
                      <ChevronRight size={14} className="text-[#46516a] group-hover:text-[#adc6ff]" />
                    </div>
                  </button>
                ))}
              </div>
            </section>

            <section className="border border-white/10 bg-[#0b111c]/92 p-5">
              <PanelTitle icon={RadioTower} title="Telemetry intake" meta="Now" />
              <div className="mt-4 grid grid-cols-2 gap-3">
                {telemetry.map((item) => (
                  <div key={item.label} className="border border-white/10 bg-[#10182b] p-3">
                    <item.icon size={18} className="text-[#78ffbd]" />
                    <p className="mt-3 font-headline text-2xl font-bold text-white">{item.value}</p>
                    <p className="mt-1 text-xs text-[#8c909f]">{item.label}</p>
                  </div>
                ))}
              </div>
            </section>

            <section className="border border-white/10 bg-[#0b111c]/92 p-5">
              <PanelTitle icon={Clock3} title="Activity stream" meta="SOC feed" />
              <div className="mt-4 space-y-4">
                {events.map((event) => (
                  <div key={`${event.time}-${event.text}`} className="grid grid-cols-[46px_minmax(0,1fr)] gap-3">
                    <span className="font-label text-xs text-[#8c909f]">{event.time}</span>
                    <p className="border-l border-[#2b354a] pl-3 text-sm leading-5 text-[#dbe7ff]">
                      {event.text}
                    </p>
                  </div>
                ))}
              </div>
            </section>
          </aside>
        </div>
      </section>
    </main>
  );
}

function HeaderPill({ icon, label, value, tone }) {
  return (
    <div className="flex h-10 items-center gap-2 border border-white/10 bg-[#10182b] px-3">
      {createElement(icon, { size: 15, className: tone })}
      <span className="font-label text-[10px] uppercase text-[#8c909f]">{label}</span>
      <span className="text-xs font-semibold text-white">{value}</span>
    </div>
  );
}

function SideItem({ icon, label, active = false }) {
  return (
    <button
      type="button"
      className={`flex h-10 w-full items-center gap-3 px-3 text-sm transition-colors ${
        active
          ? "bg-[#dbe7ff] font-semibold text-[#07101d]"
          : "text-[#aeb7ca] hover:bg-[#10182b] hover:text-white"
      }`}
    >
      {createElement(icon, { size: 17 })}
      <span className="truncate">{label}</span>
    </button>
  );
}

function Guardrail({ label, state }) {
  return (
    <div className="flex items-center justify-between gap-3 text-sm">
      <span className="truncate text-[#aeb7ca]">{label}</span>
      <span className="shrink-0 text-xs font-semibold text-[#78ffbd]">{state}</span>
    </div>
  );
}

function ActionButton({ label, onClick, primary = false }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`h-11 px-3 text-sm font-bold transition-colors ${
        primary
          ? "bg-[#dbe7ff] text-[#07101d] hover:bg-white"
          : "border border-white/10 text-[#dbe7ff] hover:border-[#adc6ff]/50"
      }`}
    >
      {label}
    </button>
  );
}

function PanelTitle({ icon, title, meta }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <div className="flex min-w-0 items-center gap-2">
        {createElement(icon, { size: 18, className: "shrink-0 text-[#adc6ff]" })}
        <h2 className="truncate font-headline text-base font-bold tracking-normal text-white">{title}</h2>
      </div>
      <span className="shrink-0 font-label text-[10px] uppercase text-[#8c909f]">{meta}</span>
    </div>
  );
}

function MapNode({ label, status, x, y }) {
  const tone =
    status === "critical"
      ? "border-[#ff5c5c] bg-[#331417] text-[#ffd6d2]"
      : status === "watch"
        ? "border-[#ffb454] bg-[#2d2412] text-[#ffdc9d]"
        : "border-[#78ffbd] bg-[#10281b] text-[#bfffd6]";

  return (
    <div
      className={`absolute min-w-[126px] -translate-x-1/2 -translate-y-1/2 border px-3 py-2 shadow-lg ${tone}`}
      style={{ left: x, top: y }}
    >
      <div className="flex items-center gap-2">
        <span className="h-2 w-2 bg-current" />
        <span className="truncate text-xs font-semibold">{label}</span>
      </div>
    </div>
  );
}
