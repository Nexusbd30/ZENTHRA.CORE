import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { AlertTriangle, ArrowRight, Eye, EyeOff, LockKeyhole, Mail, ShieldCheck } from "lucide-react";

import { getCurrentUser, loginUser } from "@/api/nexusApi";
import { useAuth } from "@/hooks/useAuth";
import { useNotification } from "@/hooks/useNotification";
import logo from "@/assets/logos/vaelqorix-logo.jpeg";

const OFFLINE_MSG = "No se puede conectar con el servidor.";

export default function Login() {
  const { login, resetSession } = useAuth();
  const { notify } = useNotification();
  const navigate = useNavigate();
  const location = useLocation();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [formError, setFormError] = useState("");

  const from = location.state?.from?.pathname || "/dashboard";

  useEffect(() => {
    document.body.classList.add("bg-background");
    return () => {
      document.body.classList.remove("bg-background");
    };
  }, []);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setFormError("");

    if (!email.includes("@")) {
      const message = "Ingresa un correo electronico valido.";
      setFormError(message);
      notify("warning", message);
      return;
    }

    setLoading(true);

    try {
      const data = await loginUser({ username: email, password });
      if (!data?.access_token) {
        throw new Error("Token no recibido del servidor.");
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
        "Credenciales invalidas o servidor no disponible.";

      const message = baseMessage.includes(OFFLINE_MSG)
        ? "Backend offline: no es posible iniciar sesion ahora mismo. Verifica que FastAPI este levantado."
        : baseMessage;

      setFormError(message);
      notify("error", message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0b1020] font-body text-[#eef3ff]">
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute inset-0 bg-[linear-gradient(135deg,rgba(74,225,118,0.08),transparent_34%),linear-gradient(315deg,rgba(173,198,255,0.08),transparent_32%)]" />
        <div className="grid-bg absolute inset-0 opacity-70" />
      </div>

      <main className="relative z-10 grid min-h-screen lg:grid-cols-[minmax(0,1fr)_520px]">
        <section className="hidden border-r border-white/10 px-10 py-8 lg:flex lg:flex-col">
          <div className="flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center border border-[#adc6ff]/20 bg-[#10182b]">
              <img src={logo} alt="VAELQORIX" className="h-9 w-9 object-contain" />
            </div>
            <div>
              <div className="font-headline text-lg font-black uppercase text-[#adc6ff]">
                VAELQORIX
              </div>
              <div className="font-label text-[10px] uppercase text-[#8c909f]">
                XDR Command Console
              </div>
            </div>
          </div>

          <div className="flex flex-1 items-center">
            <div className="max-w-2xl">
              <div className="mb-5 inline-flex items-center gap-2 border border-[#4ae176]/25 bg-[#10281b] px-3 py-2 font-label text-[10px] uppercase text-[#9ef0b6]">
                <span className="h-2 w-2 rounded-full bg-[#4ae176]" />
                Frontend fase 2
              </div>
              <h1 className="font-headline text-5xl font-bold leading-tight text-white xl:text-6xl">
                Panel operativo claro para seguridad, alertas y respuesta.
              </h1>
              <p className="mt-5 max-w-xl text-base leading-7 text-[#aeb7ca]">
                Acceso a la consola interna de VAELQORIX. El panel muestra el estado del
                backend, la navegacion principal y los modulos de operacion sin depender
                de vistas ocultas.
              </p>

              <div className="mt-10 grid max-w-xl grid-cols-3 gap-3">
                <InfoTile label="Backend" value="Real API" />
                <InfoTile label="Fase" value="Frontend" />
                <InfoTile label="Sesion" value="JWT" />
              </div>
            </div>
          </div>

          <div className="grid max-w-xl grid-cols-3 gap-3 text-xs text-[#8c909f]">
            <span>Monitoring</span>
            <span>SecOps</span>
            <span>Enterprise AI</span>
          </div>
        </section>

        <section className="flex min-h-screen items-center justify-center px-5 py-8 sm:px-8">
          <div className="w-full max-w-md">
            <div className="mb-8 flex items-center gap-3 lg:hidden">
              <div className="flex h-11 w-11 items-center justify-center border border-[#adc6ff]/20 bg-[#10182b]">
                <img src={logo} alt="VAELQORIX" className="h-8 w-8 object-contain" />
              </div>
              <div>
                <div className="font-headline text-base font-black uppercase text-[#adc6ff]">
                  VAELQORIX
                </div>
                <div className="font-label text-[10px] uppercase text-[#8c909f]">
                  XDR Command
                </div>
              </div>
            </div>

            <div className="border border-white/10 bg-[#10182b]/92 p-6 shadow-2xl backdrop-blur-xl sm:p-8">
              <div className="mb-8">
                <div className="mb-4 inline-flex h-11 w-11 items-center justify-center border border-[#4ae176]/25 bg-[#10281b] text-[#9ef0b6]">
                  <ShieldCheck size={22} />
                </div>
                <h2 className="font-headline text-2xl font-bold text-white">
                  Acceso seguro
                </h2>
                <p className="mt-2 text-sm leading-6 text-[#aeb7ca]">
                  Inicia sesion con una cuenta autorizada para entrar al centro de mando.
                </p>
              </div>

              {formError && (
                <div className="mb-5 flex gap-3 border border-[#ffb4ab]/25 bg-[#3a1619] p-3 text-sm text-[#ffd6d2]">
                  <AlertTriangle size={18} className="mt-0.5 shrink-0" />
                  <span>{formError}</span>
                </div>
              )}

              <form className="space-y-5" onSubmit={handleSubmit}>
                <div>
                  <label htmlFor="email" className="mb-2 block text-sm font-medium text-[#dbe7ff]">
                    Correo
                  </label>
                  <div className="relative">
                    <Mail
                      size={18}
                      className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[#8c909f]"
                    />
                    <input
                      id="email"
                      type="email"
                      value={email}
                      onChange={(event) => setEmail(event.target.value)}
                      placeholder="operator@vaelqorix.ai"
                      autoComplete="username"
                      className="h-12 w-full border border-white/10 bg-[#0b1020] pl-10 pr-3 text-sm text-white outline-none transition-colors placeholder:text-[#687286] focus:border-[#adc6ff]/60"
                      required
                    />
                  </div>
                </div>

                <div>
                  <label
                    htmlFor="password"
                    className="mb-2 block text-sm font-medium text-[#dbe7ff]"
                  >
                    Contrasena
                  </label>
                  <div className="relative">
                    <LockKeyhole
                      size={18}
                      className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[#8c909f]"
                    />
                    <input
                      id="password"
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                      placeholder="Introduce tu contrasena"
                      autoComplete="current-password"
                      className="h-12 w-full border border-white/10 bg-[#0b1020] pl-10 pr-12 text-sm text-white outline-none transition-colors placeholder:text-[#687286] focus:border-[#adc6ff]/60"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword((value) => !value)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-[#8c909f] transition-colors hover:text-white"
                      aria-label={showPassword ? "Ocultar contrasena" : "Mostrar contrasena"}
                    >
                      {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                    </button>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="flex h-12 w-full items-center justify-center gap-2 bg-[#adc6ff] px-4 text-sm font-bold text-[#071227] transition-colors hover:bg-[#dbe7ff] disabled:cursor-not-allowed disabled:opacity-70"
                >
                  {loading ? "Validando..." : "Entrar al panel"}
                  {!loading && <ArrowRight size={18} />}
                </button>
              </form>

              <div className="mt-6 border-t border-white/10 pt-5 text-xs leading-5 text-[#8c909f]">
                Usa credenciales reales del backend. Si FastAPI no esta levantado, el inicio de
                sesion quedara bloqueado por seguridad.
              </div>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}

function InfoTile({ label, value }) {
  return (
    <div className="border border-white/10 bg-[#10182b] p-3">
      <div className="font-label text-[10px] uppercase text-[#8c909f]">{label}</div>
      <div className="mt-1 text-sm font-semibold text-white">{value}</div>
    </div>
  );
}
