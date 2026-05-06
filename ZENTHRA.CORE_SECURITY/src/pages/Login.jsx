import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { getCurrentUser, loginUser } from "@/api/nexusApi";
import { useAuth } from "@/hooks/useAuth";
import { useNotification } from "@/hooks/useNotification";

const OFFLINE_MSG = "No se puede conectar con el servidor.";

export default function Login() {
  const { login, resetSession } = useAuth();
  const { notify } = useNotification();
  const navigate = useNavigate();
  const location = useLocation();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  const from = location.state?.from?.pathname || "/dashboard";

  useEffect(() => {
    document.body.classList.add("bg-background");
    return () => {
      document.body.classList.remove("bg-background");
    };
  }, []);

  const handleSubmit = async (event) => {
    event.preventDefault();

    if (!email.includes("@")) {
      notify("warning", "Ingresa un correo electrónico válido");
      return;
    }

    setLoading(true);

    try {
      const data = await loginUser({ username: email, password });
      if (!data?.access_token) {
        throw new Error("Token no recibido del servidor");
      }

      let currentUser = null;
      try {
        currentUser = await getCurrentUser();
      } catch {
        currentUser = { email };
      }

      login({ token: data.access_token, user: currentUser });
      navigate(from, { replace: true });
    } catch (err) {
      if (resetSession) resetSession();

      const baseMessage =
        err?.response?.data?.detail ||
        err?.message ||
        "Credenciales inválidas o servidor no disponible.";

      if (baseMessage.includes(OFFLINE_MSG)) {
        notify(
          "error",
          "Backend offline: no es posible iniciar sesión ahora mismo. Verifica que FastAPI esté levantado."
        );
      } else {
        notify("error", baseMessage);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0e14] font-body text-[#f1f3fc] selection:bg-[#8ff5ff] selection:text-[#003f43]">
      <div className="pointer-events-none fixed inset-0 z-0 overflow-hidden">
        <div className="grid-pattern absolute inset-0" />
        <div className="absolute inset-0 bg-gradient-to-tr from-[#0a0e14] via-[#0a0e14] to-[#8ff5ff]/5" />
        <div className="absolute -left-[10%] -top-[10%] h-[40%] w-[40%] rounded-full bg-[#af88ff]/6 blur-[120px]" />
        <div className="absolute -bottom-[12%] right-[5%] h-[28rem] w-[28rem] rounded-full bg-[#00eefc]/5 blur-[140px]" />
      </div>

      <header className="relative z-10 w-full px-6 py-6 md:px-8">
        <div className="flex items-center justify-between gap-6">
          <div className="font-headline text-lg font-bold uppercase tracking-[0.2em] text-[#8ff5ff] md:text-xl">
            zentrha.core
          </div>

          <div className="flex items-center gap-4 md:gap-6">
            <div className="hidden gap-8 font-label text-[11px] uppercase tracking-widest text-slate-400 md:flex">
              <span className="border-b-2 border-[#8ff5ff] pb-1 text-[#8ff5ff]">
                Terminal
              </span>
              <span className="transition-colors hover:text-[#8ff5ff]">Nodes</span>
              <span className="transition-colors hover:text-[#8ff5ff]">Uplink</span>
            </div>
            <div className="flex gap-3">
              <span className="material-symbols-outlined text-[#8ff5ff]">
                security
              </span>
              <span className="material-symbols-outlined text-[#8ff5ff]">
                language
              </span>
            </div>
          </div>
        </div>
      </header>

      <main className="relative z-10 flex min-h-[calc(100vh-8rem)] items-center justify-center px-6 pb-28 pt-8 md:pb-36 md:pt-12">
        <div className="absolute bottom-24 left-12 hidden flex-col gap-4 lg:flex">
          <div className="flex items-center gap-3">
            <div className="h-1 w-1 animate-pulse rounded-full bg-[#8ff5ff]" />
            <span className="font-label text-[10px] uppercase tracking-widest text-[#a8abb3]">
              System secure
            </span>
          </div>
          <div className="flex items-center gap-3">
            <div className="h-1 w-1 rounded-full bg-[#af88ff]" />
            <span className="font-label text-[10px] uppercase tracking-widest text-[#a8abb3]">
              Encryption: AES-256 Enabled
            </span>
          </div>
          <div className="flex items-center gap-3">
            <div className="h-1 w-1 rounded-full bg-[#00deec]" />
            <span className="font-label text-[10px] uppercase tracking-widest text-[#a8abb3]">
              Nodes: 14 Secure / 0 Threat
            </span>
          </div>
        </div>

        <div className="flex w-full max-w-7xl flex-col items-center justify-center gap-12 xl:flex-row xl:gap-16">
          <section className="hidden max-w-md xl:flex xl:flex-col">
            <div className="mb-2">
              <span className="font-label text-xs uppercase tracking-[0.3em] text-[#8ff5ff]">
                ZENTHRA SECURITY
              </span>
            </div>
            <h1 className="mb-6 font-headline text-5xl font-bold leading-[1.05] tracking-tight text-[#f1f3fc] 2xl:text-6xl">
              THE DIGITAL
              <br />
              <span className="text-[#8ff5ff]">ZENTHRA SECURITY</span>
            </h1>
            <p className="mb-8 max-w-xs text-sm leading-relaxed text-[#a8abb3]">
              Access point for the high-frequency tactical defense network.
              Authorized personnel only.
            </p>
            <div className="h-px w-24 bg-[#8ff5ff]/30" />
          </section>

          <section className="glass-panel glow-border relative w-full max-w-md overflow-hidden border border-white/5 border-l-2 border-l-[#8ff5ff] p-8 md:p-12">
            <div className="absolute left-0 top-0 h-px w-full bg-[#8ff5ff]/20" />

            <div className="mb-10">
              <div className="mb-2 flex items-end justify-between gap-4">
                <h2 className="font-headline text-2xl font-semibold text-[#f1f3fc]">
                  Secure Access
                </h2>
                <span className="font-label text-[10px] uppercase tracking-tight text-[#00deec]">
                  Auth.v4
                </span>
              </div>
              <p className="font-label text-[11px] uppercase tracking-widest text-[#a8abb3]">
                Awaiting Identity Verification
              </p>
            </div>

            <form className="space-y-8" onSubmit={handleSubmit}>
              <div className="space-y-2">
                <label
                  htmlFor="analyst-id"
                  className="ml-1 block font-label text-[10px] uppercase tracking-widest text-[#a8abb3]"
                >
                  Analyst ID
                </label>
                <div className="group relative">
                  <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-lg text-[#a8abb3] transition-colors group-focus-within:text-[#8ff5ff]">
                    badge
                  </span>
                  <input
                    id="analyst-id"
                    type="email"
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    placeholder="operator@zenthra.core"
                    autoComplete="username"
                    className="w-full rounded-sm border border-transparent border-b-[#44484f] bg-[#20262f] py-4 pl-12 pr-4 font-label text-xs tracking-widest text-[#f1f3fc] placeholder:text-[#72757d]/60 focus:border-[#00deec] focus:bg-[#20262f]/80 focus:outline-none"
                    required
                  />
                </div>
              </div>

              <div className="space-y-2">
                <label
                  htmlFor="key-passcode"
                  className="ml-1 block font-label text-[10px] uppercase tracking-widest text-[#a8abb3]"
                >
                  Key Passcode
                </label>
                <div className="group relative">
                  <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-lg text-[#a8abb3] transition-colors group-focus-within:text-[#8ff5ff]">
                    fingerprint
                  </span>
                  <input
                    id="key-passcode"
                    type="password"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    placeholder="••••••••••••"
                    autoComplete="current-password"
                    className="w-full rounded-sm border border-transparent border-b-[#44484f] bg-[#20262f] py-4 pl-12 pr-4 font-label text-xs tracking-widest text-[#f1f3fc] placeholder:text-[#72757d]/60 focus:border-[#00deec] focus:bg-[#20262f]/80 focus:outline-none"
                    required
                  />
                </div>
              </div>

              <div className="pt-4">
                <button
                  type="submit"
                  disabled={loading}
                  className="group flex w-full items-center justify-center gap-3 rounded-sm bg-gradient-to-r from-[#8ff5ff] to-[#00eefc] py-4 font-label text-[11px] font-bold uppercase tracking-[0.2em] text-[#003f43] transition-all hover:shadow-[0_0_25px_rgba(143,245,255,0.3)] active:scale-95 disabled:cursor-not-allowed disabled:opacity-70"
                >
                  <span>{loading ? "Authorizing..." : "Access System"}</span>
                  <span className="material-symbols-outlined text-sm transition-transform group-hover:translate-x-1">
                    arrow_forward_ios
                  </span>
                </button>
              </div>

              <div className="flex items-center justify-between gap-4 pt-2">
                <button
                  type="button"
                  className="font-label text-[9px] uppercase tracking-widest text-[#72757d] transition-colors hover:text-[#8ff5ff]"
                >
                  Emergency Override
                </button>
                <div className="flex gap-2">
                  <div className="h-2 w-2 rounded-full border border-[#8ff5ff]/30" />
                  <div className="h-2 w-2 rounded-full bg-[#8ff5ff]/20" />
                </div>
              </div>
            </form>
          </section>
        </div>
      </main>

      <footer className="relative z-10 w-full px-6 pb-6 md:fixed md:bottom-0 md:px-12 md:py-8">
        <div className="flex flex-col items-start justify-between gap-4 font-['JetBrains_Mono'] text-[10px] uppercase tracking-widest text-[#8ff5ff] md:flex-row md:items-center">
          <div className="flex flex-wrap gap-4 opacity-80 transition-opacity hover:opacity-100 md:gap-8">
            <a href="#" className="transition-opacity hover:text-[#8ff5ff]">
              Privacy Policy
            </a>
            <a href="#" className="transition-opacity hover:text-[#8ff5ff]">
              System Status
            </a>
            <a href="#" className="transition-opacity hover:text-[#8ff5ff]">
              Security Compliance
            </a>
          </div>
          <div className="text-slate-500">
            © 2025 zenthra.core hybrid systems. All rights reserved.
          </div>
        </div>
      </footer>

      <div className="pointer-events-none fixed left-0 top-0 z-0 p-8 opacity-20">
        <div className="h-12 w-12 border-l border-t border-[#8ff5ff]" />
      </div>
      <div className="pointer-events-none fixed right-0 top-0 z-0 p-8 opacity-20">
        <div className="h-12 w-12 border-r border-t border-[#8ff5ff]" />
      </div>
      <div className="pointer-events-none fixed bottom-0 left-0 z-0 p-8 opacity-20">
        <div className="h-12 w-12 border-b border-l border-[#8ff5ff]" />
      </div>
      <div className="pointer-events-none fixed bottom-0 right-0 z-0 p-8 opacity-20">
        <div className="h-12 w-12 border-b border-r border-[#8ff5ff]" />
      </div>
    </div>
  );
}
