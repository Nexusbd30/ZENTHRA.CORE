import { useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import { getCurrentUser, loginUser } from "@/api/vaelqorixApi";
import logo from "@/assets/logos/vaelqorix-logo.jpeg";
import { useAuth } from "@/hooks/useAuth";
import { useNotification } from "@/hooks/useNotification";

const OFFLINE_MSG = "No se puede conectar con el servidor.";
const backgroundImage =
  "https://lh3.googleusercontent.com/aida/AP1WRLvj_LFNlTOTfC-8iGNvuupC1H0WFiuzpbfQKgFitju7WyjLWmWzKP2AeaaY60LOin86WX4WRXFKciw1ThTMGUiTxcdv-kkLekI_2rO2z0-5xZO2NMeExeNQOQ1Vc6YbT1tmIKc3fNNWSp0i83Yr61NpVJWNZznDl7In7Js67m2zK5s5DV8DeTmmSg5MrF1p07q7ZLHmZ-RZIvvPLTolpbec_g7CwvrnXPH8NlmWixByyJ3s-cbkT1MKiwyB";

export default function Login() {
  const { login, resetSession } = useAuth();
  const { notify } = useNotification();
  const navigate = useNavigate();
  const location = useLocation();
  const otpRefs = useRef([]);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [formError, setFormError] = useState("");

  const from = location.state?.from?.pathname || "/dashboard";

  useEffect(() => {
    document.body.style.backgroundColor = "#0d1516";
    document.body.style.overscrollBehavior = "none";
    return () => {
      document.body.style.backgroundColor = "";
      document.body.style.overscrollBehavior = "";
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

  const handleOtpChange = (index, value) => {
    if (value && index < otpRefs.current.length - 1) {
      otpRefs.current[index + 1]?.focus();
    }
  };

  return (
    <main className="soc-landing flex min-h-screen w-full items-center justify-center bg-surface font-body-md text-on-surface">
      <div className="relative flex min-h-screen w-full flex-col items-center justify-center overflow-hidden p-4">
        <div className="pointer-events-none absolute inset-0 z-0">
          <img alt="Background" className="h-full w-full object-cover opacity-60" src={backgroundImage} />
          <div className="absolute inset-0 bg-black/40" />
        </div>
        <div className="pointer-events-none absolute inset-0 z-0 bg-[linear-gradient(to_right,var(--c-outline-variant)_1px,transparent_1px),linear-gradient(to_bottom,var(--c-outline-variant)_1px,transparent_1px)] bg-[size:64px_64px] opacity-20 [mask-image:radial-gradient(circle_at_center,black,transparent_80%)]" />
        <div className="pointer-events-none absolute inset-0 z-0 bg-gradient-to-b from-surface/90 via-surface/80 to-surface" />
        <div className="pointer-events-none absolute inset-0 z-0 bg-[radial-gradient(rgba(10,25,47,0.3),transparent,transparent)]" />

        <div className="relative z-10 flex w-full max-w-md transform flex-col gap-8 rounded-xl border border-outline-variant bg-surface-container/80 p-8 shadow-2xl backdrop-blur-md transition-all duration-500 hover:border-primary/50 hover:shadow-primary/10">
          <div className="flex flex-col items-center gap-4 text-center">
            <div className="h-16 w-16 overflow-hidden rounded-lg border border-outline-variant bg-surface p-2 shadow-inner">
              <img
                alt="VAELQORIX Logo"
                className="h-full w-full object-contain drop-shadow-[0_0_8px_rgba(0,82,54,0.6)]"
                src={logo}
              />
            </div>
            <div>
              <h1 className="font-headline-md uppercase tracking-widest text-on-surface">
                Vaelqorix
              </h1>
              <p className="mt-1 font-code-sm uppercase tracking-widest text-on-secondary-fixed-variant opacity-80">
                Intelligence - Protect - Evolve
              </p>
            </div>
          </div>

          {formError && (
            <div className="rounded-md border border-error/40 bg-error-container/40 p-3 text-body-sm text-on-error-container">
              {formError}
            </div>
          )}

          <form className="flex flex-col gap-6" onSubmit={handleSubmit}>
            <div className="flex flex-col gap-5 transition-opacity duration-300">
              <div className="flex flex-col gap-2">
                <label className="flex justify-between font-label-caps text-on-surface-variant" htmlFor="access-id">
                  <span>Access ID</span>
                  <span className="text-[10px] text-outline">SYS.OP.AUTH</span>
                </label>
                <div className="group relative">
                  <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-sm text-outline transition-colors group-focus-within:text-primary">
                    badge
                  </span>
                  <input
                    autoComplete="username"
                    className="w-full rounded-md border border-outline-variant bg-surface-container-lowest py-3 pl-10 pr-4 font-code-md text-on-surface shadow-inner placeholder:text-outline focus:border-primary-container focus:outline-none focus:ring-1 focus:ring-primary-container"
                    id="access-id"
                    onChange={(event) => setEmail(event.target.value)}
                    placeholder="operator@vaelqorix.ai"
                    required
                    type="email"
                    value={email}
                  />
                </div>
              </div>

              <div className="flex flex-col gap-2">
                <label className="flex justify-between font-label-caps text-on-surface-variant" htmlFor="passcode">
                  <span>Biometric / Key Passcode</span>
                  <span className="text-[10px] text-outline">ENCRYPTED</span>
                </label>
                <div className="group relative">
                  <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-sm text-outline transition-colors group-focus-within:text-primary">
                    fingerprint
                  </span>
                  <input
                    autoComplete="current-password"
                    className="w-full rounded-md border border-outline-variant bg-surface-container-lowest py-3 pl-10 pr-12 font-code-md text-on-surface shadow-inner placeholder:text-outline focus:border-primary-container focus:outline-none focus:ring-1 focus:ring-primary-container"
                    id="passcode"
                    onChange={(event) => setPassword(event.target.value)}
                    placeholder="************"
                    required
                    type={showPassword ? "text" : "password"}
                    value={password}
                  />
                  <button
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-outline transition-colors hover:text-primary"
                    onClick={() => setShowPassword((value) => !value)}
                    type="button"
                  >
                    <span className="material-symbols-outlined text-sm">visibility</span>
                  </button>
                </div>
              </div>

              <button
                className="mt-2 flex w-full items-center justify-center gap-2 rounded-md bg-[#0a192f] py-4 font-label-caps text-primary shadow-[0_0_20px_rgba(10,25,47,0.4)] transition-all hover:shadow-[0_0_30px_rgba(10,25,47,0.6)] disabled:cursor-not-allowed disabled:opacity-70"
                disabled={loading}
                type="submit"
              >
                <span>{loading ? "Validating Handshake" : "Initialize Handshake"}</span>
                {!loading && (
                  <span className="material-symbols-outlined text-sm transition-transform group-hover:translate-x-1">
                    arrow_forward_ios
                  </span>
                )}
              </button>
            </div>

            <div className="hidden flex-col gap-5">
              <div className="flex items-start gap-3 rounded-md border border-primary/30 bg-surface-container-high p-4">
                <span className="material-symbols-outlined mt-0.5 animate-pulse text-primary">
                  lock_person
                </span>
                <div>
                  <p className="font-body-sm text-on-surface">Multi-Factor Authentication Required</p>
                  <p className="mt-1 text-xs font-code-sm text-on-surface-variant">
                    A token has been sent to your registered device.
                  </p>
                </div>
              </div>
              <div className="flex flex-col gap-2">
                <label className="text-center font-label-caps text-on-surface-variant">
                  Enter 6-Digit Token
                </label>
                <div className="flex justify-between gap-2">
                  {Array.from({ length: 6 }).map((_, index) => (
                    <input
                      className="h-14 w-12 rounded-md border border-outline-variant bg-surface-container-lowest text-center font-code-md text-xl text-on-surface shadow-inner focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                      key={index}
                      maxLength={1}
                      onChange={(event) => handleOtpChange(index, event.target.value)}
                      ref={(element) => {
                        otpRefs.current[index] = element;
                      }}
                      type="text"
                    />
                  ))}
                </div>
              </div>
            </div>
          </form>

          <div className="flex flex-col items-center gap-2 border-t border-outline-variant/50 pt-6 text-center">
            <div className="flex items-center gap-1.5 text-[#1e3a8a]">
              <span className="material-symbols-outlined text-[12px]">gpp_good</span>
              <span className="font-code-sm text-[10px] uppercase tracking-wider">
                End-to-End Encrypted Link Active
              </span>
            </div>
            <p className="max-w-[280px] text-[10px] font-body-sm leading-relaxed text-on-surface-variant">
              Unauthorized access to this system is strictly prohibited and logged.
            </p>
          </div>
        </div>

        <div className="absolute left-4 top-4 h-8 w-8 border-l border-t border-outline-variant/50" />
        <div className="absolute right-4 top-4 h-8 w-8 border-r border-t border-outline-variant/50" />
        <div className="absolute bottom-4 left-4 h-8 w-8 border-b border-l border-outline-variant/50" />
        <div className="absolute bottom-4 right-4 h-8 w-8 border-b border-r border-outline-variant/50" />
      </div>
    </main>
  );
}
