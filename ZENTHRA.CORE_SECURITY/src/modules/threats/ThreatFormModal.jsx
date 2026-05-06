// =============================================================
// 🧩 ThreatFormModal — ZENTHRA.CORE_SECURITY (v4.1 Elite Secure)
// =============================================================
// Modal para registrar amenazas manuales:
//
//   - Usa createThreat() de nexusAPI (JWT mediante interceptores).
//   - Campos mínimos: título + fuente.
//   - Campos opcionales: nivel, categoría, score, descripción.
//   - Manejo de errores de permisos (403) y offline-aware.
// =============================================================

import { useEffect, useRef, useState } from "react";
import { motion as Motion, AnimatePresence } from "framer-motion";
import { X, ShieldPlus } from "lucide-react";

import { createThreat } from "@/api/nexusApi";
import { useNotification } from "@/hooks/useNotification";

const OFFLINE_MSG = "No se puede conectar con el servidor.";

export default function ThreatFormModal({ isOpen, onClose, onSuccess }) {
  const { notify } = useNotification();
  const dialogRef = useRef(null);

  const [formData, setFormData] = useState({
    title: "",
    source: "",
    level: "medium",
    category: "",
    score: "",
    description: "",
  });

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!isOpen) return;
    setFormData({
      title: "",
      source: "",
      level: "medium",
      category: "",
      score: "",
      description: "",
    });
    setSubmitting(false);
    setError(null);
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;

    const onKey = (e) => e.key === "Escape" && onClose?.();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [isOpen, onClose]);

  const isValid = formData.title.trim() && formData.source.trim();

  const handleBackdropClick = (e) => {
    if (dialogRef.current && dialogRef.current === e.target) onClose?.();
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!isValid) {
      setError("Completa al menos título y fuente.");
      return;
    }

    setSubmitting(true);
    setError(null);

    try {
      const payload = {
        title: formData.title.trim(),
        source: formData.source.trim(),
        level: formData.level,
        description: formData.description?.trim() || undefined,
        category: formData.category || undefined, // enum: performance/availability/network/database/auth/other
        score:
          formData.score !== "" && !Number.isNaN(Number(formData.score))
            ? Number(formData.score)
            : undefined,
      };

      await createThreat(payload);

      notify("success", "✅ Amenaza registrada correctamente");
      onSuccess?.();
      onClose?.();
    } catch (err) {
      let msg = err?.message || "Error al registrar la amenaza.";

      if (msg.includes(OFFLINE_MSG)) {
        msg =
          "Backend offline — no se pueden registrar amenazas ahora mismo.";
      } else if (
        msg.toLowerCase().includes("rol administrador") ||
        msg.includes("403")
      ) {
        msg =
          "No tienes permisos para registrar amenazas (se requiere rol administrador).";
      }

      setError(msg);
      notify("error", `❌ ${msg}`);
    } finally {
      setSubmitting(false);
    }
  };

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      {isOpen && (
        <Motion.div
          ref={dialogRef}
          onMouseDown={handleBackdropClick}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
        >
          <Motion.div
            onMouseDown={(e) => e.stopPropagation()}
            initial={{ scale: 0.96, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.96, opacity: 0 }}
            transition={{ duration: 0.22 }}
            className="bg-[#020617] border border-red-500/40 rounded-2xl shadow-2xl shadow-red-900/40 p-8 w-[480px] max-w-[95vw] relative text-white"
          >
            {/* Cerrar */}
            <button
              onClick={onClose}
              className="absolute top-3 right-3 text-gray-400 hover:text-red-400 transition"
              title="Cerrar"
              type="button"
            >
              <X size={20} />
            </button>

            {/* Header */}
            <header className="mb-6 text-center">
              <h2 className="text-2xl font-bold text-red-400 mb-1 flex justify-center items-center gap-2">
                <ShieldPlus size={22} /> Nueva alerta manual
              </h2>
              <p className="text-gray-400 text-sm">
                Registra una amenaza detectada manualmente o durante una
                revisión forense.
              </p>
            </header>

            {/* Error */}
            {error && (
              <p className="text-red-300 bg-red-500/10 border border-red-500/30 p-2 rounded-lg text-xs mb-4">
                ⚠️ {error}
              </p>
            )}

            {/* Formulario */}
            <form
              onSubmit={handleSubmit}
              className="flex flex-col gap-4 text-sm"
            >
              <input
                type="text"
                placeholder="Título de la amenaza"
                value={formData.title}
                onChange={(e) =>
                  setFormData({ ...formData, title: e.target.value })
                }
                required
                className="p-3 rounded-lg bg-neutral-900 border border-neutral-700 text-white focus:ring-2 focus:ring-red-500 outline-none"
              />

              <input
                type="text"
                placeholder="Fuente u origen (firewall, revisión manual, etc.)"
                value={formData.source}
                onChange={(e) =>
                  setFormData({ ...formData, source: e.target.value })
                }
                required
                className="p-3 rounded-lg bg-neutral-900 border border-neutral-700 text-white focus:ring-2 focus:ring-red-500 outline-none"
              />

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <select
                  value={formData.level}
                  onChange={(e) =>
                    setFormData({ ...formData, level: e.target.value })
                  }
                  className="p-3 rounded-lg bg-neutral-900 border border-neutral-700 text-white focus:ring-2 focus:ring-red-500 outline-none"
                >
                  <option value="critical">Crítico</option>
                  <option value="high">Alto</option>
                  <option value="medium">Medio</option>
                  <option value="low">Bajo</option>
                </select>

                <select
                  value={formData.category}
                  onChange={(e) =>
                    setFormData({ ...formData, category: e.target.value })
                  }
                  className="p-3 rounded-lg bg-neutral-900 border border-neutral-700 text-white focus:ring-2 focus:ring-red-500 outline-none"
                >
                  <option value="">Categoría (opcional)</option>
                  <option value="availability">Availability</option>
                  <option value="network">Network</option>
                  <option value="performance">Performance</option>
                  <option value="database">Database</option>
                  <option value="auth">Auth</option>
                  <option value="other">Other</option>
                </select>
              </div>

              <input
                type="number"
                min={0}
                max={100}
                step={1}
                placeholder="Score 0–100 (opcional)"
                value={formData.score}
                onChange={(e) =>
                  setFormData({ ...formData, score: e.target.value })
                }
                className="p-3 rounded-lg bg-neutral-900 border border-neutral-700 text-white focus:ring-2 focus:ring-red-500 outline-none"
              />

              <textarea
                placeholder="Descripción detallada del evento, contexto, evidencias…"
                value={formData.description}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    description: e.target.value,
                  })
                }
                rows={4}
                className="p-3 rounded-lg bg-neutral-900 border border-neutral-700 text-white focus:ring-2 focus:ring-red-500 outline-none resize-none"
              />

              <div className="flex gap-4 mt-2">
                <button
                  type="submit"
                  disabled={submitting || !isValid}
                  className="flex-1 bg-red-600 hover:bg-red-700 py-2 rounded-lg font-semibold transition-all disabled:opacity-50"
                >
                  {submitting ? "Guardando..." : "Registrar"}
                </button>
                <button
                  type="button"
                  onClick={onClose}
                  className="flex-1 bg-gray-600 hover:bg-gray-700 py-2 rounded-lg font-semibold transition-all"
                >
                  Cancelar
                </button>
              </div>
            </form>
          </Motion.div>
        </Motion.div>
      )}
    </AnimatePresence>
  );
}

