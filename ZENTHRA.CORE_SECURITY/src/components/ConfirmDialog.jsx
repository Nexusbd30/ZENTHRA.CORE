// =============================================================
// 💠 ZENTHRA ConfirmDialog — v2.4 Final
// =============================================================
// Modal de confirmación universal
// - Uso: eliminar usuarios, resetear contraseñas, acciones críticas
// - Animado con Framer Motion
// - Totalmente reutilizable en todo el sistema
// =============================================================

import React from "react";
import { motion as Motion, AnimatePresence } from "framer-motion";
import { X, AlertTriangle } from "lucide-react";

// =============================================================
// ⚙️ COMPONENTE PRINCIPAL
// =============================================================
export default function ConfirmDialog({
  isOpen,
  title = "Confirmar acción",
  message = "¿Estás seguro de continuar?",
  confirmLabel = "Confirmar",
  cancelLabel = "Cancelar",
  danger = false, // 🔴 estilo para acciones destructivas
  onConfirm,
  onCancel,
}) {
  if (!isOpen) return null;

  return (
    <AnimatePresence>
      {isOpen && (
        <Motion.div
          className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
        >
          {/* Cuerpo del modal */}
          <Motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.9, opacity: 0 }}
            className="bg-neutral-900 border border-neutral-700 rounded-2xl shadow-xl p-6 w-[420px] text-white relative"
          >
            {/* Botón cerrar */}
            <button
              onClick={onCancel}
              className="absolute top-3 right-3 text-neutral-400 hover:text-white transition"
            >
              <X size={20} />
            </button>

            {/* Encabezado */}
            <div className="flex items-center gap-3 mb-4">
              <AlertTriangle
                size={26}
                className={danger ? "text-red-400" : "text-yellow-400"}
              />
              <h2 className="text-lg font-semibold">{title}</h2>
            </div>

            {/* Mensaje */}
            <p className="text-neutral-300 mb-6 text-sm">{message}</p>

            {/* Botones */}
            <div className="flex justify-end gap-3">
              <button
                onClick={onCancel}
                className="px-4 py-2 bg-neutral-800 hover:bg-neutral-700 text-neutral-300 rounded-lg text-sm transition"
              >
                {cancelLabel}
              </button>

              <button
                onClick={onConfirm}
                className={`px-4 py-2 rounded-lg text-sm font-semibold transition-all ${
                  danger
                    ? "bg-red-600 hover:bg-red-700 text-white"
                    : "bg-blue-600 hover:bg-blue-700 text-white"
                }`}
              >
                {confirmLabel}
              </button>
            </div>
          </Motion.div>
        </Motion.div>
      )}
    </AnimatePresence>
  );
}

