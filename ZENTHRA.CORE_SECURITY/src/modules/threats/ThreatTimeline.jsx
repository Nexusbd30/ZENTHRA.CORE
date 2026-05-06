// =============================================================
// 🕒 ThreatTimeline — ZENTHRA.CORE_SECURITY (v1.0 Elite SOC)
// =============================================================
// Vista cronológica estilo SIEM:
//   - Lista amenazas ordenadas por fecha descendente
//   - Muestra badges de severidad y categoría
//   - Clic en un item → abre ThreatDetailsModal via onSelectThreat()
// =============================================================

import { useEffect, useState, useCallback } from "react";
import { Activity, AlertTriangle, Network, Database, Lock, Gauge } from "lucide-react";

import { listThreats } from "@/api/nexusApi";
import { useNotification } from "@/hooks/useNotification";

export default function ThreatTimeline({ onSelectThreat, refreshKey = 0, limit = 50 }) {
  const { notify } = useNotification();

  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);

  const fetchTimeline = useCallback(async () => {
    try {
      setLoading(true);
      const data = await listThreats(0, limit);
      const list = Array.isArray(data) ? data : [];

      // Orden DESC por fecha
      list.sort((a, b) => {
        const da = new Date(a.created_at || a.timestamp || 0).getTime();
        const db = new Date(b.created_at || b.timestamp || 0).getTime();
        return db - da;
      });

      setItems(list);
    } catch {
      notify("error", "❌ No se pudo cargar el timeline de amenazas.");
    } finally {
      setLoading(false);
    }
  }, [limit, notify]);

  useEffect(() => {
    fetchTimeline();
  }, [fetchTimeline, refreshKey]);

  // ---- Badge helpers ----

  const levelColors = {
    critical: "text-red-300 border-red-500/40 bg-red-500/10",
    high: "text-orange-300 border-orange-500/40 bg-orange-500/10",
    medium: "text-yellow-300 border-yellow-500/40 bg-yellow-500/10",
    low: "text-blue-300 border-blue-500/40 bg-blue-500/10",
  };

  const categoryConfig = (category) => {
    const c = String(category || "other").toLowerCase();
    switch (c) {
      case "availability":
        return { label: "Availability", icon: AlertTriangle };
      case "network":
        return { label: "Network", icon: Network };
      case "database":
        return { label: "Database", icon: Database };
      case "auth":
        return { label: "Auth", icon: Lock };
      case "performance":
        return { label: "Performance", icon: Gauge };
      default:
        return { label: "Other", icon: Activity };
    }
  };

  const formatTs = (ts) => {
    try {
      const d = new Date(ts);
      if (isNaN(d.getTime())) return "—";
      return d.toLocaleString();
    } catch {
      return String(ts) || "—";
    }
  };

  return (
    <div className="bg-[#020617]/60 border border-slate-700 rounded-2xl p-4 shadow-lg shadow-slate-900/30">
      <h2 className="text-lg font-semibold mb-3 text-slate-200">📅 Timeline de amenazas</h2>

      {loading && (
        <p className="text-xs text-gray-400 mb-2">Cargando timeline…</p>
      )}

      {items.length === 0 && !loading && (
        <p className="text-xs text-gray-500">No hay amenazas recientes.</p>
      )}

      <div className="space-y-4">
        {items.map((t) => {
          const lvl = String(t.level || "low").toLowerCase();
          const cat = categoryConfig(t.category);
          const Icon = cat.icon;

          return (
            <div
              key={t.id}
              onClick={() => onSelectThreat?.(t)}
              className="cursor-pointer bg-slate-900/40 border border-slate-700/50 rounded-xl p-3 hover:bg-slate-800/50 transition flex items-start gap-3"
            >
              {/* Línea temporal */}
              <div className="flex flex-col items-center">
                <div className="w-3 h-3 rounded-full bg-red-500 shadow-red-900/50 shadow"></div>
                <div className="flex-1 w-[2px] bg-slate-700/50 mt-1"></div>
              </div>

              {/* Contenido */}
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <p className="font-semibold text-slate-100">{t.title}</p>
                  <span
                    className={`px-2 py-0.5 text-[10px] font-bold rounded-full border ${levelColors[lvl]}`}
                  >
                    {lvl.toUpperCase()}
                  </span>
                </div>

                <div className="flex items-center gap-2 mt-1 text-xs text-slate-400">
                  <Icon size={12} />
                  <span>{cat.label}</span>
                </div>

                <p className="mt-1 text-xs text-gray-400 font-mono">
                  {formatTs(t.created_at || t.timestamp)}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
