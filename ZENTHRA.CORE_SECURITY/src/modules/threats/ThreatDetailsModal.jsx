// =============================================================
// 🧠 ThreatDetailsModal — ZENTHRA.CORE_SECURITY (v4.1 Elite+SOC)
// =============================================================
// - Muestra detalle completo de la amenaza (tabla → modal).
// - Si el objeto recibido está incompleto, llama a /threats/:id.
// - Offline-aware: si no hay backend, usa los datos que ya venían.
// - Botón para copiar el JSON completo (modo SOC).
// - Chips avanzados: nivel, categoría, score y origen (correlación/manual).
// =============================================================

import { useEffect, useRef, useState } from "react";
import { motion as Motion, AnimatePresence } from "framer-motion";
import {
  X,
  Shield,
  Server,
  ActivitySquare,
  Clock,
  Copy,
  Target,
  Gauge,
  Network,
  Database,
  Lock,
  AlertTriangle,
  User,
} from "lucide-react";

import { getThreatById } from "@/api/nexusApi";
import { useNotification } from "@/hooks/useNotification";

const OFFLINE_MSG = "No se puede conectar con el servidor.";

export default function ThreatDetailsModal({ threat, onClose }) {
  const { notify } = useNotification();
  const backdropRef = useRef(null);

  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(false);

  // ESC para cerrar
  useEffect(() => {
    if (!threat) return;

    const onKey = (e) => e.key === "Escape" && onClose?.();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [threat, onClose]);

  // Carga perezosa de detalle extra
  useEffect(() => {
    if (!threat) return;

    if (threat.description || threat.raw?.description) {
      setDetail(threat.raw ?? threat);
      return;
    }

    const fetchDetail = async () => {
      setLoading(true);
      try {
        const id = threat.id ?? threat.raw?.id;
        if (!id) {
          setDetail(threat.raw ?? threat);
          return;
        }

        const data = await getThreatById(id);
        setDetail({ ...threat.raw, ...threat, ...data });
      } catch (err) {
        setDetail(threat.raw ?? threat);

        let msg =
          err?.message ||
          "⚠️ No se pudieron ampliar los detalles de la amenaza.";

        if (msg.includes(OFFLINE_MSG)) {
          msg =
            "Backend offline — se muestran solo los datos ya cargados en la tabla.";
        }

        notify("warning", msg);
      } finally {
        setLoading(false);
      }
    };

    fetchDetail();
  }, [threat]);

  if (!threat) return null;

  const d = detail ?? threat;
  const level = String(d.level ?? d.severity ?? "low").toLowerCase();
  const category = String(d.category ?? "other").toLowerCase();
  const sourceRaw = String(d.source || d.origin || "").toLowerCase();

  const levelColors = {
    critical: "text-red-300 border-red-500/50 bg-red-500/10",
    high: "text-orange-300 border-orange-500/50 bg-orange-500/10",
    medium: "text-yellow-300 border-yellow-500/50 bg-yellow-500/10",
    low: "text-blue-300 border-blue-500/50 bg-blue-500/10",
  };

  const categoryConfig = () => {
    switch (category) {
      case "availability":
        return {
          label: "Availability",
          icon: AlertTriangle,
          className: "text-amber-300 border-amber-500/50 bg-amber-500/10",
        };
      case "network":
        return {
          label: "Network",
          icon: Network,
          className: "text-sky-300 border-sky-500/50 bg-sky-500/10",
        };
      case "database":
        return {
          label: "Database",
          icon: Database,
          className:
            "text-emerald-300 border-emerald-500/50 bg-emerald-500/10",
        };
      case "auth":
        return {
          label: "Auth",
          icon: Lock,
          className:
            "text-fuchsia-300 border-fuchsia-500/50 bg-fuchsia-500/10",
        };
      case "performance":
        return {
          label: "Performance",
          icon: Gauge,
          className: "text-lime-300 border-lime-500/50 bg-lime-500/10",
        };
      default:
        return {
          label: "Other",
          icon: Shield,
          className: "text-gray-300 border-gray-500/50 bg-gray-500/10",
        };
    }
  };

  const sourceConfig = () => {
    if (sourceRaw === "prometheus/correlation") {
      return {
        label: "Prometheus Correlation",
        className:
          "text-amber-200 border-amber-500/60 bg-amber-500/10",
      };
    }
    if (sourceRaw.startsWith("manual") || sourceRaw.startsWith("user")) {
      return {
        label: "Manual / User",
        className:
          "text-emerald-200 border-emerald-500/60 bg-emerald-500/10",
      };
    }
    if (!sourceRaw) {
      return {
        label: "Origen desconocido",
        className:
          "text-gray-300 border-gray-500/60 bg-gray-500/10",
      };
    }
    return {
      label: d.source || d.origin || "Otro origen",
      className:
        "text-sky-200 border-sky-500/60 bg-sky-500/10",
    };
  };

  const tsSource =
    d.timestamp || d.created_at || d.createdAt || d.date || null;
  const ts =
    tsSource instanceof Date ? tsSource : tsSource ? new Date(tsSource) : null;

  const timestamp =
    ts && !Number.isNaN(ts.getTime?.() ?? NaN)
      ? ts.toLocaleString?.() ?? String(ts)
      : typeof tsSource === "string"
      ? tsSource
      : "—";

  const updatedSource = d.updated_at || d.updatedAt || null;
  const updated =
    updatedSource instanceof Date
      ? updatedSource
      : updatedSource
      ? new Date(updatedSource)
      : null;

  const updatedStr =
    updated && !Number.isNaN(updated.getTime?.() ?? NaN)
      ? updated.toLocaleString?.() ?? String(updated)
      : updatedSource
      ? String(updatedSource)
      : "—";

  const copyJson = async () => {
    try {
      const payload = JSON.stringify(d, null, 2);
      await navigator.clipboard.writeText(payload);
      notify("success", "📋 Detalle copiado al portapapeles");
    } catch {
      notify("error", "❌ No se pudo copiar el detalle");
    }
  };

  const onBackdrop = (e) => {
    if (e.target === backdropRef.current) onClose?.();
  };

  const catCfg = categoryConfig();
  const srcCfg = sourceConfig();

  return (
    <AnimatePresence>
      {threat && (
        <Motion.div
          ref={backdropRef}
          onMouseDown={onBackdrop}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
        >
          <Motion.div
            onMouseDown={(e) => e.stopPropagation()}
            initial={{ scale: 0.95, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.95, opacity: 0 }}
            transition={{ duration: 0.22 }}
            className="bg-[#020617] border border-red-500/40 rounded-2xl shadow-2xl shadow-red-900/40 p-7 w-[560px] max-h-[85vh] overflow-y-auto relative text-white"
          >
            {/* Close */}
            <button
              onClick={onClose}
              className="absolute top-3 right-3 text-gray-400 hover:text-red-400 transition"
              title="Cerrar"
              type="button"
            >
              <X size={20} />
            </button>

            {/* Header */}
            <header className="mb-5">
              <div className="flex items-center gap-2 mb-1">
                <Shield size={22} className="text-red-400" />
                <h2 className="text-xl font-bold text-red-400">
                  Detalles de la amenaza
                </h2>
              </div>
              <p className="text-sm text-gray-300 font-semibold">
                {d.title || "Sin título"}
              </p>
              <p className="text-[11px] text-gray-500 font-mono break-all mt-1">
                ID: {d.id ?? d._id ?? "—"}
              </p>
            </header>

            {/* Chips */}
            <div className="flex flex-wrap gap-2 mb-5 text-[11px]">
              <span
                className={
                  "inline-flex items-center px-2.5 py-1 rounded-full border font-semibold " +
                  (levelColors[level] ||
                    "text-gray-300 border-gray-500/50 bg-gray-500/10")
                }
              >
                <ActivitySquare size={13} className="mr-1" />
                Nivel: {String(level).toUpperCase()}
              </span>

              <span
                className={
                  "inline-flex items-center px-2.5 py-1 rounded-full border font-semibold " +
                  catCfg.className
                }
              >
                <catCfg.icon size={13} className="mr-1" />
                Categoría: {catCfg.label}
              </span>

              <span
                className={
                  "inline-flex items-center px-2.5 py-1 rounded-full border font-semibold " +
                  srcCfg.className
                }
              >
                <Server size={13} className="mr-1" />
                Origen: {srcCfg.label}
              </span>

              {typeof d.score === "number" && (
                <span className="inline-flex items-center px-2.5 py-1 rounded-full border border-sky-500/50 bg-sky-500/10 text-sky-200 font-semibold">
                  <Gauge size={13} className="mr-1" />
                  Score: {d.score}
                </span>
              )}
            </div>

            {/* Info técnica */}
            <div className="space-y-3 text-sm">
              <div className="flex items-center justify-between border-b border-gray-700 pb-2">
                <span className="text-gray-400 flex items-center gap-2">
                  <Server size={16} /> Origen bruto:
                </span>
                <span className="font-semibold text-gray-100">
                  {d.source || d.origin || "Desconocido"}
                </span>
              </div>

              {d.created_by && (
                <div className="flex items-center justify-between border-b border-gray-700 pb-2">
                  <span className="text-gray-400 flex items-center gap-2">
                    <User size={16} /> Creado por:
                  </span>
                  <span className="font-mono text-gray-100">
                    {d.created_by}
                  </span>
                </div>
              )}

              {d.target_service && (
                <div className="flex items-center justify-between border-b border-gray-700 pb-2">
                  <span className="text-gray-400 flex items-center gap-2">
                    <Target size={16} /> Servicio objetivo:
                  </span>
                  <span className="font-semibold text-gray-100">
                    {d.target_service}
                  </span>
                </div>
              )}

              <div className="flex items-center justify-between border-b border-gray-700 pb-2">
                <span className="text-gray-400 flex items-center gap-2">
                  <Clock size={16} /> Detectado:
                </span>
                <span className="font-semibold text-gray-100">
                  {timestamp || "—"}
                </span>
              </div>

              <div className="flex items-center justify-between border-b border-gray-700 pb-2">
                <span className="text-gray-400 flex items-center gap-2">
                  <Clock size={16} /> Última actualización:
                </span>
                <span className="font-semibold text-gray-100">
                  {updatedStr}
                </span>
              </div>

              {d.source_ip && (
                <div className="flex items-center justify-between border-b border-gray-700 pb-2">
                  <span className="text-gray-400">IP origen:</span>
                  <span className="font-mono text-gray-100">
                    {d.source_ip}
                  </span>
                </div>
              )}

              {(d.database_name || d.database_host) && (
                <div className="border-b border-gray-700 pb-2 text-xs text-gray-300">
                  <span className="block text-gray-400 mb-1">
                    Base de datos afectada:
                  </span>
                  {d.database_name && (
                    <div>
                      <span className="text-gray-400">Nombre: </span>
                      <span className="font-mono">{d.database_name}</span>
                    </div>
                  )}
                  {d.database_host && (
                    <div>
                      <span className="text-gray-400">Host: </span>
                      <span className="font-mono">{d.database_host}</span>
                    </div>
                  )}
                </div>
              )}

              <div className="pt-2">
                <p className="text-gray-400 mb-1">Descripción:</p>
                <p className="text-gray-200 leading-relaxed whitespace-pre-line text-sm">
                  {d.description ||
                    "No se ha registrado una descripción detallada para este evento."}
                </p>
              </div>

              {/* Acciones SOC */}
              <div className="pt-3 flex items-center justify-between gap-3">
                {loading && (
                  <p className="text-xs text-gray-400">Ampliando detalles…</p>
                )}

                <div className="ml-auto flex gap-2">
                  <button
                    onClick={copyJson}
                    className="flex items-center gap-2 bg-neutral-800 hover:bg-neutral-700 px-3 py-1.5 rounded-lg text-xs transition"
                    type="button"
                    title="Copiar detalle JSON"
                  >
                    <Copy size={14} /> Copiar JSON
                  </button>
                  <button
                    onClick={onClose}
                    className="bg-red-600 hover:bg-red-700 px-4 py-1.5 rounded-lg font-semibold text-xs transition-all"
                    type="button"
                  >
                    Cerrar
                  </button>
                </div>
              </div>
            </div>
          </Motion.div>
        </Motion.div>
      )}
    </AnimatePresence>
  );
}

