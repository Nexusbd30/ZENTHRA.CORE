// =============================================================
// 💠 DashboardCard — ZENTHRA.CORE_SECURITY (v2.5 Observability+)
// =============================================================
// Tarjeta visual modular para métricas del panel principal.
// - Basada en tu componente UI/Card personalizado
// - Compatibilidad total con TailwindCSS + Framer Motion + lucide-react
// - Animaciones suaves y coherencia con el tema oscuro
// =============================================================

import { motion as Motion } from "framer-motion";
import { Card, CardContent } from "@/components/ui/card";

// =============================================================
// ⚙️ COMPONENTE PRINCIPAL
// =============================================================
export default function DashboardCard({
  title = "Título",
  value = "0",
  icon: Icon = null,
  color = "blue",
  subtitle = "",
}) {
  // ===========================================================
  // 🎨 Paleta ZENTHRA — Tonos suaves y translúcidos
  // ===========================================================
  const colorVariants = {
    blue: "from-blue-500/10 to-blue-500/5 border-blue-500/20 text-blue-400",
    green:
      "from-green-500/10 to-green-500/5 border-green-500/20 text-green-400",
    red: "from-red-500/10 to-red-500/5 border-red-500/20 text-red-400",
    yellow:
      "from-yellow-500/10 to-yellow-500/5 border-yellow-500/20 text-yellow-400",
    purple:
      "from-purple-500/10 to-purple-500/5 border-purple-500/20 text-purple-400",
    gray: "from-gray-700/20 to-gray-700/10 border-gray-600/20 text-gray-400",
  };

  const colorClass = colorVariants[color] || colorVariants.blue;

  // ===========================================================
  // 🧩 RENDER — Tarjeta animada y responsiva
  // ===========================================================
  return (
    <Motion.div
      initial={{ opacity: 0, y: 25 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      <Card
        className={`relative border ${colorClass} bg-gradient-to-br rounded-2xl p-5 hover:scale-[1.03] transition-transform duration-300 shadow-md hover:shadow-lg backdrop-blur-sm`}
      >
        <CardContent className="flex flex-col space-y-3">
          {/* Header */}
          <div className="flex justify-between items-center">
            <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-widest">
              {title}
            </h3>
            {Icon && (
              <Icon
                className={`w-6 h-6 ${
                  colorClass.includes("text-")
                    ? colorClass
                        .split(" ")
                        .find((c) => c.startsWith("text-")) || "text-gray-400"
                    : "text-gray-400"
                }`}
              />
            )}
          </div>

          {/* Valor principal */}
          <p className="text-3xl font-bold text-white drop-shadow-sm">
            {value}
          </p>

          {/* Subtítulo opcional */}
          {subtitle && (
            <p className="text-xs text-gray-500 font-medium">{subtitle}</p>
          )}
        </CardContent>
      </Card>
    </Motion.div>
  );
}
