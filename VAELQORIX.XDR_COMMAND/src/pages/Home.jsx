import { useNavigate } from "react-router-dom";

import logo from "../assets/logos/vaelqorix-logo.jpeg";

const heroBackground =
  "https://lh3.googleusercontent.com/aida-public/AB6AXuAtERyv5AvhMf-eI80HqF3FfxSquprTMiiH27uooOiwgI4o71Ys7gp6JzzdJ0eBCBpaUd7YOE1zpBcpx613KIwlr2wwF3bEA9TlM2IwLHHQ1nBi-ujWKgK2YwstD5TyNSWb96Y8et90FUMEsZOjyQhrci0rdsZyCa59PbjfFgBMtCZLCq_cZ2lLCtbWDbVtE1ANbT7x2fB80Qc4GR1T-MtCU9CEtKIrjN7jqQyyVSB-stpM9shIDkc2XA";

export default function Home() {
  const navigate = useNavigate();

  return (
    <div className="soc-landing min-h-screen bg-surface font-body-md text-on-surface">
      <div className="fixed inset-0 z-0">
        <div
          className="absolute inset-0 bg-cover bg-center"
          style={{ backgroundImage: `url('${heroBackground}')` }}
        />
        <div className="absolute inset-0 bg-gradient-to-b from-surface/90 via-surface/82 to-surface/94" />
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-primary-container/10 via-transparent to-transparent" />
      </div>

      <header className="fixed left-0 right-0 top-0 z-40 flex h-16 items-center justify-between border-b border-outline-variant bg-surface/80 px-8 backdrop-blur-xl">
        <div className="flex items-center gap-2 text-on-surface-variant">
          <span className="material-symbols-outlined text-sm">shield</span>
          <span className="font-label-caps text-label-caps">VAELQORIX</span>
        </div>
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-3 border-r border-outline-variant pr-4">
            <span className="material-symbols-outlined cursor-pointer text-on-surface-variant hover:text-primary">
              search
            </span>
            <span className="material-symbols-outlined cursor-pointer text-on-surface-variant hover:text-primary">
              notifications
            </span>
          </div>
          <button
            type="button"
            onClick={() => navigate("/login")}
            className="rounded border border-outline-variant px-4 py-2 font-code-sm text-code-sm font-bold text-primary transition-colors hover:border-primary hover:bg-primary hover:text-on-primary"
          >
            LOGIN
          </button>
        </div>
      </header>

      <main className="relative z-10 min-h-screen pt-16">
        <section className="relative -mt-16 flex min-h-[90vh] flex-col items-center justify-center overflow-hidden">
          <div className="relative z-10 mx-auto flex max-w-5xl flex-col items-center px-8 pb-12 pt-24 text-center">
            <div className="mb-8 inline-flex items-center gap-2 rounded-full border border-outline-variant bg-surface-container-high px-4 py-2 font-code-sm text-code-sm text-secondary shadow-[0_0_15px_rgba(78,222,163,0.15)] backdrop-blur-md">
              <div className="h-2 w-2 animate-pulse rounded-full bg-secondary" />
              SYSTEM ONLINE: VERSION 4.2.1
            </div>
            <h1 className="mb-6 font-headline-lg text-[56px] leading-[64px] tracking-tighter text-on-surface drop-shadow-lg">
              Defensa de Elite para un <br />
              <span className="bg-gradient-to-r from-primary to-primary-container bg-clip-text text-transparent">
                Mundo Digital
              </span>
            </h1>
            <p className="mb-12 max-w-3xl font-body-md text-headline-md font-light text-on-surface-variant">
              Advanced threat detection, real-time telemetry, and tactical response orchestrated
              from a singular, high-performance command deck.
            </p>
          </div>

          <div className="pointer-events-none absolute bottom-0 left-0 right-0 z-10 flex h-32 items-end bg-gradient-to-t from-surface to-transparent px-8 pb-4 opacity-50">
            <div className="flex w-full justify-between font-code-sm text-[10px] uppercase tracking-widest text-primary">
              <span>ENCRYPTION: AES-256-GCM</span>
              <span>UPTIME: 99.999%</span>
              <span>LATENCY: &lt; 5MS</span>
              <span>NODES ACTIVE: 14,204</span>
            </div>
          </div>
        </section>

        <section className="relative z-20 px-8 py-24">
          <div className="mx-auto max-w-7xl">
            <div className="mb-16 flex items-end justify-between">
              <div>
                <h2 className="mb-2 font-headline-md text-headline-md text-on-surface">
                  Tactical Capabilities
                </h2>
                <p className="text-body-md text-on-surface-variant">
                  Deploy enterprise-grade countermeasures with sub-second precision.
                </p>
              </div>
              <div className="text-right">
                <div className="font-code-sm text-code-sm text-outline">[SYS.CAP.MODULES]</div>
              </div>
            </div>
            <div className="grid grid-cols-1 gap-1 md:grid-cols-3">
              <FeatureCard
                icon="dashboard_customize"
                tone="text-primary"
                border="hover:border-primary/50"
                title="Command Center"
                text="A unified pane of glass for global operations. Correlate disparate data streams into actionable intelligence instantly."
              />
              <FeatureCard
                icon="crisis_alert"
                tone="text-error"
                border="hover:border-error/50"
                title="Incident Monitor"
                text="Automated anomaly detection powered by heuristic algorithms. Prioritize threats automatically based on blast radius."
              />
              <FeatureCard
                icon="hub"
                tone="text-secondary"
                border="hover:border-secondary/50"
                title="Network Topology"
                text="Real-time visual mapping of organizational assets. Identify lateral movement and isolate compromised sectors with a click."
              />
            </div>
          </div>
        </section>

        <section className="relative overflow-hidden border-y border-outline-variant bg-surface/45 px-8 py-24 backdrop-blur-sm">
          <div className="pointer-events-none absolute right-0 top-0 h-full w-1/2 bg-gradient-to-l from-primary/5 to-transparent" />
          <div className="mx-auto flex max-w-7xl flex-col items-center gap-16 lg:flex-row">
            <div className="relative w-full lg:w-5/12">
              <div className="absolute -inset-4 z-0 rotate-2 rounded border border-primary/20 opacity-50" />
              <div className="absolute -inset-4 z-0 -rotate-2 rounded border border-secondary/20 opacity-50" />
              <div
                aria-label="VAELQORIX"
                className="relative z-10 aspect-square w-full rounded border border-surface-variant bg-cover bg-center shadow-2xl transition-all duration-700"
                style={{ backgroundImage: `url('${logo}')` }}
              />
            </div>
            <div className="w-full lg:w-7/12">
              <span className="material-symbols-outlined mb-6 text-[64px] text-surface-variant">

              </span>
              <div className="grid grid-cols-2 gap-8 border-t border-outline-variant pt-8">
                <div>
                  <div className="mb-2 font-headline-lg text-[48px] tracking-tighter text-primary">
                    94%
                  </div>
                  <div className="font-code-sm text-code-sm uppercase tracking-wider text-on-surface-variant">
                    Reduction in False Positives
                  </div>
                </div>
                <div>
                  <div className="mb-2 font-headline-lg text-[48px] tracking-tighter text-secondary">
                    &lt; 2ms
                  </div>
                  <div className="font-code-sm text-code-sm uppercase tracking-wider text-on-surface-variant">
                    Ingestion Latency
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="relative flex flex-col items-center overflow-hidden px-8 py-32 text-center">
          <div className="pointer-events-none absolute inset-0 opacity-20">
            <svg height="100%" width="100%" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <pattern height="40" id="grid" patternUnits="userSpaceOnUse" width="40">
                  <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#2e3638" strokeWidth="1" />
                </pattern>
              </defs>
              <rect fill="url(#grid)" height="100%" width="100%" />
            </svg>
          </div>
        </section>

        <footer className="border-t border-outline-variant bg-surface/60 px-8 py-8 backdrop-blur-sm">
          <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-4 font-code-sm text-code-sm text-on-surface-variant md:flex-row">
            <div>Â© 2024 VAELQORIX Systems. End-to-end Encrypted.</div>
            <div className="flex gap-6">
              <a className="transition-colors hover:text-primary" href="#">SEC PROTOCOLS</a>
              <a className="transition-colors hover:text-primary" href="#">API DOCS</a>
              <a className="transition-colors hover:text-primary" href="#">SYSTEM STATUS</a>
            </div>
          </div>
        </footer>
      </main>
    </div>
  );
}

function FeatureCard({ icon, tone, border, title, text }) {
  return (
    <div
      className={`group relative overflow-hidden border border-surface-variant bg-surface-container-low p-8 transition-colors ${border}`}
    >
      <div className="absolute right-0 top-0 -mr-16 -mt-16 h-32 w-32 rounded-bl-full bg-primary/5 transition-transform group-hover:scale-110" />
      <span
        className={`material-symbols-outlined mb-6 text-[40px] drop-shadow-[0_0_8px_rgba(0,229,255,0.3)] ${tone}`}
      >
        {icon}
      </span>
      <h3 className="mb-3 font-code-md text-body-md font-bold uppercase tracking-wider text-on-surface">
        {title}
      </h3>
      <p className="text-body-md leading-relaxed text-on-surface-variant">{text}</p>
    </div>
  );
}
