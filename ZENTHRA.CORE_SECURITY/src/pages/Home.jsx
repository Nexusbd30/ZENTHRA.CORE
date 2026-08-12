import { useNavigate } from "react-router-dom";
import { Activity, ArrowRight, Bot, Network, ShieldCheck } from "lucide-react";

import logo from "../assets/logos/vaelqorix-logo.jpeg";

const capabilities = [
  { label: "XDR Command", detail: "Incidentes y postura en una sola vista", icon: ShieldCheck },
  { label: "AI Security", detail: "Briefing operativo y respuesta gobernada", icon: Bot },
  { label: "Telemetry", detail: "Prometheus, runtime logs e infraestructura", icon: Activity },
  { label: "Identity Graph", detail: "Senales de identidad, red y endpoint", icon: Network },
];

export default function Home() {
  const navigate = useNavigate();

  return (
    <main className="min-h-screen overflow-hidden bg-[#070b12] text-white">
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute inset-0 bg-[linear-gradient(135deg,rgba(94,231,255,0.10),transparent_34%),linear-gradient(315deg,rgba(120,255,189,0.08),transparent_30%)]" />
        <div className="grid-bg absolute inset-0 opacity-70" />
      </div>

      <section className="relative z-10 grid min-h-screen lg:grid-cols-[minmax(0,1fr)_460px]">
        <div className="flex flex-col px-6 py-6 sm:px-10 lg:px-12">
          <header className="flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <img
                src={logo}
                alt="VAELQORIX"
                className="h-12 w-12 object-contain drop-shadow-[0_0_16px_rgba(94,231,255,0.35)]"
              />
              <div>
                <div className="font-headline text-lg font-black uppercase tracking-normal text-white">
                  VAELQORIX
                </div>
                <div className="font-label text-[10px] uppercase text-[#8c909f]">
                  Intelligence. Protect. Evolve.
                </div>
              </div>
            </div>

            <button
              type="button"
              onClick={() => navigate("/login")}
              className="hidden h-10 items-center gap-2 border border-white/10 bg-[#10182b] px-4 text-sm text-[#dbe7ff] transition-colors hover:border-[#5ee7ff]/40 sm:inline-flex"
            >
              Acceder
              <ArrowRight size={16} />
            </button>
          </header>

          <div className="flex flex-1 items-center py-16">
            <div className="max-w-4xl">
              <div className="mb-5 inline-flex items-center gap-2 border border-[#78ffbd]/25 bg-[#10281b] px-3 py-2 font-label text-[10px] uppercase text-[#9ef0b6]">
                <span className="h-2 w-2 rounded-full bg-[#78ffbd]" />
                Command center online
              </div>
              <h1 className="font-headline text-5xl font-bold leading-tight tracking-normal text-white sm:text-6xl xl:text-7xl">
                Centro operativo XDR para defensa, inteligencia y respuesta.
              </h1>
              <p className="mt-6 max-w-2xl text-base leading-7 text-[#aeb7ca]">
                VAELQORIX concentra alertas, telemetria, identidad, infraestructura y AI
                Security en una consola clara para operar sin ruido.
              </p>

              <div className="mt-9 flex flex-col gap-3 sm:flex-row">
                <button
                  type="button"
                  onClick={() => navigate("/login")}
                  className="inline-flex h-12 items-center justify-center gap-2 bg-[#adc6ff] px-5 text-sm font-bold text-[#071227] transition-colors hover:bg-[#dbe7ff]"
                >
                  Entrar al panel
                  <ArrowRight size={18} />
                </button>
                <button
                  type="button"
                  onClick={() => navigate("/dashboard")}
                  className="inline-flex h-12 items-center justify-center gap-2 border border-white/10 px-5 text-sm font-semibold text-[#dbe7ff] transition-colors hover:border-[#78ffbd]/40"
                >
                  Ver command center
                </button>
              </div>
            </div>
          </div>

          <div className="grid gap-3 pb-4 sm:grid-cols-2 xl:grid-cols-4">
            {capabilities.map((item) => (
              <article key={item.label} className="border border-white/10 bg-[#10182b]/86 p-4">
                <item.icon size={20} className="text-[#78ffbd]" />
                <h2 className="mt-3 text-sm font-bold text-white">{item.label}</h2>
                <p className="mt-1 text-xs leading-5 text-[#8c909f]">{item.detail}</p>
              </article>
            ))}
          </div>
        </div>

        <aside className="hidden border-l border-white/10 bg-[#090e18]/80 p-8 lg:flex lg:flex-col lg:justify-between">
          <div className="relative overflow-hidden border border-white/10 bg-[#10182b] p-6">
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(94,231,255,0.16),transparent_56%)]" />
            <div className="relative flex aspect-square items-center justify-center">
              <img
                src={logo}
                alt="VAELQORIX emblem"
                className="h-72 w-72 object-contain drop-shadow-[0_0_30px_rgba(94,231,255,0.28)]"
              />
            </div>
          </div>

          <div className="space-y-3">
            <StatusRow label="Backend" value="localhost:8000" />
            <StatusRow label="Frontend" value="localhost:5173" />
            <StatusRow label="Mode" value="Phase 2 UI" />
          </div>
        </aside>
      </section>
    </main>
  );
}

function StatusRow({ label, value }) {
  return (
    <div className="flex items-center justify-between border border-white/10 bg-[#10182b] px-4 py-3">
      <span className="font-label text-[10px] uppercase text-[#8c909f]">{label}</span>
      <span className="text-sm font-semibold text-white">{value}</span>
    </div>
  );
}
