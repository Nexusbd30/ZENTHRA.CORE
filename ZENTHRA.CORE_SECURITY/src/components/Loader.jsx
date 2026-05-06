// =============================================================
// 💠 Loader — ZENTHRA.CORE_SECURITY
// =============================================================
// Indicador de carga global del sistema.
// Inspirado en Cisco SecureX y AWS Console.
// Estilo azul neón con animación suave.
// =============================================================

import logo from "@/assets/logos/zenthra-logo.png";

export default function Loader() {
  return (
    <div className="flex flex-col items-center justify-center h-screen bg-gradient-to-b from-[#0f172a] via-[#1e3a8a] to-[#1e40af] text-blue-300">
      {/* ========================================================= */}
      {/* LOGO ZENTHRA */}
      {/* ========================================================= */}
      <img
        src={logo}
        alt="ZENTHRA Loader"
        className="w-20 h-20 mb-6 animate-pulse drop-shadow-[0_0_15px_rgba(56,189,248,0.6)]"
      />

      {/* ========================================================= */}
      {/* SPINNER */}
      {/* ========================================================= */}
      <div className="relative mb-4">
        <div className="w-16 h-16 border-4 border-blue-500 border-t-transparent rounded-full animate-spin drop-shadow-[0_0_10px_rgba(59,130,246,0.7)]"></div>
        <div className="absolute inset-0 rounded-full blur-lg bg-blue-500/10 animate-ping"></div>
      </div>

      {/* ========================================================= */}
      {/* TEXTO */}
      {/* ========================================================= */}
      <p className="text-lg font-medium tracking-wide animate-pulse">
        Inicializando sistema ZENTHRA...
      </p>
    </div>
  );
}