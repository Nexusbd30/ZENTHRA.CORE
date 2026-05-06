// =============================================================
// 📊 ThreatTable — ZENTHRA.CORE_SECURITY (v4.3 Elite Secure+UX+Filters)
// =============================================================
// Responsabilidades:
//   - Obtener la lista de amenazas desde el backend (listThreats).
//   - Soportar refresh manual y autoRefresh opcional.
//   - Disparar onSelectThreat(threat) al hacer click en una fila.
//   - Eliminar amenazas con manejo de permisos (403) y errores.
//
// UX extra:
//   - Badge de nivel (critical/high/medium/low).
//   - Badge de categoría (availability/network/database/auth/other).
//   - Filtros SOC por nivel, origen y categoría.
//   - Estado offline vs “sin datos” claramente diferenciados.
// =============================================================

import { useEffect, useState, useCallback } from "react";
import {
  Trash2,
  Eye,
  AlertTriangle,
  Network,
  Database,
  Lock,
  Gauge,
} from "lucide-react";

import { listThreats, deleteThreat } from "@/api/nexusApi";
import { useNotification } from "@/hooks/useNotification";

const OFFLINE_MSG = "No se puede conectar con el servidor.";

export default function ThreatTable({
  onSelectThreat,
  refreshKey = 0,
  limit = 20,
  autoRefreshMs = 0,
}) {
  const { notify } = useNotification();

  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // 🎛️ Filtros SOC
  const [filterSeverity, setFilterSeverity] = useState("all");
  const [filterSource, setFilterSource] = useState("all");
  const [filterCategory, setFilterCategory] = useState("all");

  // -------------------------------------------------------------
  // 🧲 Cargar amenazas desde el backend
  // -------------------------------------------------------------
  const fetchThreats = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const data = await listThreats(0, limit);
      setThreats(Array.isArray(data) ? data : []);
    } catch (err) {
      let msg =
        err?.message || "Error al cargar las amenazas desde el servidor.";
      const isOffline = msg.includes(OFFLINE_MSG);

      if (isOffline) {
        msg = "Backend offline — no se pueden cargar las amenazas ahora mismo.";
        notify("warning", `⚠️ ${msg}`);
      } else {
        notify("error", `❌ ${msg}`);
      }

      setError(msg);
      setThreats([]);
    } finally {
      setLoading(false);
    }
  }, [limit, notify]);

  useEffect(() => {
    fetchThreats();
  }, [fetchThreats, refreshKey]);

  useEffect(() => {
    if (!autoRefreshMs || autoRefreshMs <= 0) return;
    const id = setInterval(fetchThreats, autoRefreshMs);
    return () => clearInterval(id);
  }, [autoRefreshMs, fetchThreats]);

  // -------------------------------------------------------------
  // 🗑️ Eliminar amenaza
  // -------------------------------------------------------------
  const handleDelete = async (threat) => {
    if (!window.confirm(`¿Eliminar la amenaza "${threat.title}"?`)) return;

    try {
      await deleteThreat(threat.id);
      notify("success", "✅ Amenaza eliminada correctamente");
      fetchThreats();
    } catch (err) {
      const msg =
        err?.message || "Error al eliminar la amenaza. Intenta de nuevo.";
      notify("error", `❌ ${msg}`);
    }
  };

  // -------------------------------------------------------------
  // 🔎 Helpers de presentación
  // -------------------------------------------------------------
  const formatTimestamp = (ts) => {
    if (!ts) return "—";
    try {
      const d = ts instanceof Date ? ts : new Date(ts);
      if (Number.isNaN(d.getTime())) return String(ts);
      return d.toLocaleString();
    } catch {
      return String(ts);
    }
  };

  const levelBadgeClass = (level) => {
    const lv = String(level || "").toLowerCase();
    switch (lv) {
      case "critical":
        return "text-red-300 border-red-500/40 bg-red-500/10";
      case "high":
        return "text-orange-300 border-orange-500/40 bg-orange-500/10";
      case "medium":
        return "text-yellow-300 border-yellow-500/40 bg-yellow-500/10";
      case "low":
      default:
        return "text-blue-300 border-blue-500/40 bg-blue-500/10";
    }
  };

  const categoryConfig = (category) => {
    const cat = String(category || "other").toLowerCase();
    switch (cat) {
      case "availability":
        return {
          label: "Availability",
          icon: AlertTriangle,
          className:
            "text-amber-300 bg-amber-500/10 border-amber-500/40",
        };
      case "network":
        return {
          label: "Network",
          icon: Network,
          className: "text-sky-300 bg-sky-500/10 border-sky-500/40",
        };
      case "database":
        return {
          label: "Database",
          icon: Database,
          className:
            "text-emerald-300 bg-emerald-500/10 border-emerald-500/40",
        };
      case "auth":
        return {
          label: "Auth",
          icon: Lock,
          className:
            "text-fuchsia-300 bg-fuchsia-500/10 border-fuchsia-500/40",
        };
      case "performance":
        return {
          label: "Performance",
          icon: Gauge,
          className:
            "text-lime-300 bg-lime-500/10 border-lime-500/40",
        };
      default:
        return {
          label: "Other",
          icon: AlertTriangle,
          className:
            "text-gray-300 bg-gray-500/10 border-gray-500/40",
        };
    }
  };

  // -------------------------------------------------------------
  // 🧮 Aplicar filtros SOC en cliente
  // -------------------------------------------------------------
  const filteredThreats = threats.filter((t) => {
    const sev = String(t.level || t.severity || "medium").toLowerCase();
    const src = String(t.source || t.origin || "").toLowerCase();
    const cat = String(t.category || "other").toLowerCase();

    // Filtro por severidad
    if (filterSeverity !== "all" && sev !== filterSeverity) {
      return false;
    }

    // Filtro por origen
    if (filterSource !== "all") {
      if (filterSource === "correlation") {
        if (src !== "prometheus/correlation") return false;
      } else if (filterSource === "manual") {
        // Consideramos como manual cualquier cosa que empiece por "manual" o "user"
        if (!src.startsWith("manual") && !src.startsWith("user")) return false;
      } else if (filterSource === "other") {
        if (src === "prometheus/correlation") return false;
      }
    }

    // Filtro por categoría
    if (filterCategory !== "all" && cat !== filterCategory) {
      return false;
    }

    return true;
  });

  // -------------------------------------------------------------
  // 🎨 Render
  // -------------------------------------------------------------
  return (
    <div className="bg-[#020617]/60 border border-red-500/20 rounded-2xl p-4 shadow-lg shadow-red-900/30">
      {/* Barra superior */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-4 text-sm">
        <div className="text-gray-300">
          {loading
            ? "Cargando amenazas..."
            : `Amenazas registradas: ${threats.length} · Mostrando: ${filteredThreats.length}`}
        </div>
        <button
          type="button"
          onClick={fetchThreats}
          disabled={loading}
          className="self-start md:self-auto text-xs px-3 py-1.5 rounded-lg border border-red-500/40 text-red-300 hover:bg-red-500/10 transition disabled:opacity-40"
        >
          Refrescar
        </button>
      </div>

      {/* Filtros SOC */}
      <div className="flex flex-col md:flex-row gap-3 mb-4 text-xs text-gray-200">
        <div className="flex items-center gap-2">
          <span className="text-[11px] uppercase tracking-wide text-gray-400">
            Severidad
          </span>
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="bg-slate-900/80 border border-slate-700 rounded-lg px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-red-500"
          >
            <option value="all">Todas</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] uppercase tracking-wide text-gray-400">
            Origen
          </span>
          <select
            value={filterSource}
            onChange={(e) => setFilterSource(e.target.value)}
            className="bg-slate-900/80 border border-slate-700 rounded-lg px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-red-500"
          >
            <option value="all">Todos</option>
            <option value="correlation">prometheus/correlation</option>
            <option value="manual">Manual / User</option>
            <option value="other">Otros</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] uppercase tracking-wide text-gray-400">
            Categoría
          </span>
          <select
            value={filterCategory}
            onChange={(e) => setFilterCategory(e.target.value)}
            className="bg-slate-900/80 border border-slate-700 rounded-lg px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-red-500"
          >
            <option value="all">Todas</option>
            <option value="availability">Availability</option>
            <option value="network">Network</option>
            <option value="database">Database</option>
            <option value="auth">Auth</option>
            <option value="performance">Performance</option>
            <option value="other">Other</option>
          </select>
        </div>
      </div>

      {/* Mensaje error/offline */}
      {error && (
        <div className="mb-4 text-xs text-amber-200 bg-amber-500/10 border border-amber-500/30 px-3 py-2 rounded-lg">
          ⚠️ {error}
        </div>
      )}

      {/* Tabla */}
      <div className="overflow-x-auto rounded-xl border border-white/5 bg-[#020617]/40">
        <table className="min-w-full text-sm">
          <thead className="bg-white/5 text-gray-300 uppercase text-xs">
            <tr>
              <th className="px-4 py-3 text-left">ID</th>
              <th className="px-4 py-3 text-left">Título</th>
              <th className="px-4 py-3 text-left">Origen</th>
              <th className="px-4 py-3 text-left">Categoría</th>
              <th className="px-4 py-3 text-left">Nivel</th>
              <th className="px-4 py-3 text-left">Detectado</th>
              <th className="px-4 py-3 text-right">Acciones</th>
            </tr>
          </thead>
          <tbody>
            {/* Sin amenazas (backend OK) */}
            {filteredThreats.length === 0 && !loading && !error && (
              <tr>
                <td
                  colSpan={7}
                  className="px-4 py-6 text-center text-gray-500 text-sm"
                >
                  No hay amenazas que coincidan con los filtros actuales.
                </td>
              </tr>
            )}

            {/* Filas de datos */}
            {filteredThreats.map((t) => {
              const ts =
                t.timestamp || t.created_at || t.createdAt || t.date || null;
              const level = t.level || t.severity || "low";
              const catCfg = categoryConfig(t.category);

              return (
                <tr
                  key={t.id}
                  className="border-t border-white/5 hover:bg-white/5 transition-colors cursor-pointer"
                  onClick={() => onSelectThreat?.(t)}
                >
                  <td className="px-4 py-3 font-mono text-xs text-gray-400">
                    {(t.id || "").toString().slice(0, 8)}…
                  </td>
                  <td className="px-4 py-3 text-sm font-semibold">
                    {t.title || "—"}
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-300">
                    {t.source || t.origin || "Desconocido"}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={
                        "inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[11px] font-semibold " +
                        catCfg.className
                      }
                    >
                      <catCfg.icon size={12} />
                      {catCfg.label}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={
                        "inline-flex items-center px-2 py-0.5 rounded-full border text-[11px] font-semibold " +
                        levelBadgeClass(level)
                      }
                    >
                      {String(level).toUpperCase()}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-300">
                    {formatTimestamp(ts)}
                  </td>
                  <td
                    className="px-4 py-3 text-right"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <div className="flex gap-2 justify-end">
                      <button
                        type="button"
                        onClick={() => onSelectThreat?.(t)}
                        className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-gray-200 text-xs flex items-center gap-1"
                        title="Ver detalles"
                      >
                        <Eye size={14} />
                        Ver
                      </button>
                      <button
                        type="button"
                        onClick={() => handleDelete(t)}
                        className="p-1.5 rounded-lg bg-red-700/80 hover:bg-red-600 text-white text-xs flex items-center gap-1"
                        title="Eliminar amenaza"
                      >
                        <Trash2 size={14} />
                        Eliminar
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}

            {/* Loading en tabla */}
            {loading && (
              <tr>
                <td
                  colSpan={7}
                  className="px-4 py-4 text-center text-gray-400 text-xs"
                >
                  Cargando datos de amenazas…
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
