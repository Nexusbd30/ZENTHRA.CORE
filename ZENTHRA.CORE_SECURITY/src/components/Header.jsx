// =============================================================
// 💠 Header — ZENTHRA.CORE_SECURITY (v3.6)
// =============================================================
// Cabecera principal del sistema:
//  - Branding (logo + nombre)
//  - Fecha actual
//  - Sesión: email del usuario + botón "Cerrar sesión"
// =============================================================

export default function Header({ user, onLogout }) {
  const currentDate = new Date().toISOString().replace("T", " ").slice(0, 19);

  return (
    <header className="fixed top-0 left-64 right-0 h-16 bg-[#0b1326] flex items-center justify-between px-6 border-b border-[#424754]/20 z-30">
      <div className="flex items-center gap-8">
        <span className="text-xl font-bold tracking-tighter text-[#adc6ff] font-['Space_Grotesk']">
          MISSION-CRITICAL INTEL
        </span>
        <div className="hidden md:flex gap-3 text-xs uppercase tracking-widest text-[#424754]">
          <span className="px-2 py-1 border border-[#424754]/30 bg-[#171f33] rounded-sm">
            {currentDate}
          </span>
        </div>
      </div>
      <div className="flex items-center gap-4">
        <div className="text-right leading-tight">
          <p className="text-[11px] text-[#424754] uppercase">Operador</p>
          <p className="text-sm font-semibold text-[#adc6ff]">
            {user?.email || "usuario@zenthra"}
          </p>
        </div>
        <button
          type="button"
          onClick={onLogout}
          className="px-3 py-2 text-xs font-bold uppercase tracking-widest bg-[#2d3449] text-[#adc6ff] hover:bg-[#171f33] border border-[#424754]/40 rounded-sm transition-all"
        >
          Salir
        </button>
      </div>
    </header>
  );
}
