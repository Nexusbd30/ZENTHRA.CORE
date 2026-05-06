// =============================================================
// 🧱 UI COMPONENT — CARD (ZENTHRA.CORE_SECURITY)
// =============================================================
// Componente base de tarjetas reutilizable para el dashboard.
// Inspirado en shadcn/ui, pero sin dependencias externas.
// =============================================================

export function Card({ className = "", children }) {
  return (
    <div
      className={`rounded-2xl border border-blue-500/20 bg-gradient-to-b from-[#1e293b]/70 to-[#0f172a]/70 p-5 shadow-lg hover:shadow-blue-500/20 transition-all duration-300 ${className}`}
    >
      {children}
    </div>
  );
}

export function CardContent({ className = "", children }) {
  return (
    <div className={`flex flex-col justify-between h-full space-y-3 ${className}`}>
      {children}
    </div>
  );
}