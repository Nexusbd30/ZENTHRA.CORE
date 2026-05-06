// =============================================================
// 🧾 REGISTER — ZENTHRA.CORE_SECURITY (v4.0 Blue Team Pro)
// =============================================================
// - Crea usuarios vía POST /users/
// - Por defecto: rol "user" y is_active=true
// - UI alineada con el Login (fondo + card)
// =============================================================

import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import nexusApi from "@/api/nexusApi";

export default function Register() {
  const navigate = useNavigate();

  // 📋 Estados
  const [email, setEmail] = useState("");
  const [fullName, setFullName] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // 🎨 Mismo fondo global que el Login
  useEffect(() => {
    document.body.style.backgroundColor = "#0f172a";
    document.body.style.backgroundImage =
      "url(\"data:image/svg+xml,%3Csvg width='52' height='26' viewBox='0 0 52 26' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='%231e293b' fill-opacity='0.35'%3E%3Cpath d='M10 10c0-2.21-1.79-4-4-4-3.314 0-6-2.686-6-6h2c0 2.21 1.79 4 4 4 3.314 0 6 2.686 6 6 0 2.21 1.79 4 4 4 3.314 0 6 2.686 6 6 0 2.21 1.79 4 4 4v2c-3.314 0-6-2.686-6-6 0-2.21-1.79-4-4-4-3.314 0-6-2.686-6-6zm25.464-1.95l8.486 8.486-1.414 1.414-8.486-8.486 1.414-1.414z'/%3E%3C/g%3E%3C/svg%3E\")";
    document.body.style.backgroundRepeat = "repeat";
    document.body.style.backgroundSize = "auto";
    document.body.style.color = "#E6F1FF";

    return () => {
      document.body.style.background = "";
      document.body.style.backgroundImage = "";
      document.body.style.color = "";
    };
  }, []);

  // 🧩 Registro de usuario
  const handleRegister = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    setSuccess("");

    try {
      if (!email.includes("@")) {
        throw new Error("Ingresa un correo electrónico válido.");
      }

      const response = await nexusApi.post("/users/", {
        email,
        full_name: fullName,
        password,
        is_active: true,
        role: "user",
      });

      if (response?.data?.id) {
        setSuccess("✅ Usuario creado correctamente. Redirigiendo al login...");
      } else {
        setSuccess("✅ Usuario creado correctamente.");
      }

      setTimeout(() => navigate("/login"), 1800);
    } catch (err) {
      console.error(err);
      const msg =
        err?.response?.data?.detail ||
        err?.message ||
        "❌ No se pudo crear el usuario. Verifica los datos.";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  // 💅 Vista del formulario (mismo estilo que Login)
  return (
    <div className="min-h-screen flex items-center justify-center font-[Inter] text-white relative">
      <div className="absolute inset-0 bg-gradient-to-br from-black/40 via-transparent to-blue-900/30 pointer-events-none" />

      <div className="relative z-10 w-full max-w-md bg-[#0b1220]/95 rounded-xl shadow-lg border border-blue-500/40 p-8 backdrop-blur-md">
        <h1 className="text-3xl font-extrabold text-center mb-2 tracking-tight">
          Crear cuenta{" "}
          <span className="text-blue-400 font-black">ZENTHRA</span>
        </h1>
        <p className="text-center text-blue-200/80 text-sm mb-8">
          Alta de usuario para ZENTHRA.CORE_SECURITY
        </p>

        <form onSubmit={handleRegister} className="flex flex-col gap-4 text-sm">
          <div>
            <label className="block text-sm font-medium mb-1 text-blue-50">
              Correo electrónico
            </label>
            <input
              type="email"
              placeholder="tu.correo@empresa.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full h-11 px-4 bg-[#111827] border border-[#1d3350] text-white rounded-lg
                         placeholder:text-slate-500 focus:ring-2 focus:ring-blue-500 outline-none"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1 text-blue-50">
              Nombre completo
            </label>
            <input
              type="text"
              placeholder="Nombre y apellidos"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              className="w-full h-11 px-4 bg-[#111827] border border-[#1d3350] text-white rounded-lg
                         placeholder:text-slate-500 focus:ring-2 focus:ring-blue-500 outline-none"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1 text-blue-50">
              Contraseña
            </label>
            <input
              type="password"
              placeholder="••••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full h-11 px-4 bg-[#111827] border border-[#1d3350] text-white rounded-lg
                         placeholder:text-slate-500 focus:ring-2 focus:ring-blue-500 outline-none"
              required
            />
          </div>

          {error && (
            <p className="text-red-400 text-xs bg-red-500/10 border border-red-500/30 rounded-md px-3 py-2">
              {error}
            </p>
          )}
          {success && (
            <p className="text-emerald-300 text-xs bg-emerald-500/10 border border-emerald-500/30 rounded-md px-3 py-2">
              {success}
            </p>
          )}

          <button
            type="submit"
            disabled={loading}
            className={`w-full h-11 bg-blue-600 hover:bg-blue-500
                       text-white font-semibold rounded-lg shadow
                       shadow-blue-500/30 transition-all duration-200
                       ${loading ? "opacity-60 cursor-not-allowed" : ""}`}
          >
            {loading ? "Creando..." : "Registrar usuario"}
          </button>
        </form>

        <p className="text-center text-sm text-blue-200/80 mt-6">
          ¿Ya tienes cuenta?{" "}
          <button
            onClick={() => navigate("/login")}
            type="button"
            className="text-blue-400 font-semibold hover:underline"
          >
            Iniciar sesión
          </button>
        </p>

        <div className="mt-8 text-center text-xs text-blue-300/70">
          <p>© 2025 ZENTHRA SECURITY SYSTEM. Todos los derechos reservados.</p>
        </div>
      </div>
    </div>
  );
}
