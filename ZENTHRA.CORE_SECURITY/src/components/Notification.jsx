// =============================================================
// 💠 ZENTHRA Notification System
// =============================================================
// Inspirado en AWS Console y Cisco SecureX
// Estilo minimalista, animado y coherente con el diseño del dashboard
// =============================================================

import { motion as Motion, AnimatePresence } from "framer-motion";
import {
  CheckCircle,
  XCircle,
  AlertTriangle,
  Info,
  X,
} from "lucide-react";

export default function Notification({ type, message, onClose }) {
  // 🎨 Paleta según tipo
  const styles = {
    success: "bg-green-600/90 border-green-400 text-green-50",
    error: "bg-red-600/90 border-red-400 text-red-50",
    warning: "bg-yellow-600/90 border-yellow-400 text-yellow-50",
    info: "bg-blue-600/90 border-blue-400 text-blue-50",
  };

  const icons = {
    success: <CheckCircle className="w-5 h-5" />,
    error: <XCircle className="w-5 h-5" />,
    warning: <AlertTriangle className="w-5 h-5" />,
    info: <Info className="w-5 h-5" />,
  };

  return (
    <AnimatePresence>
      <Motion.div
        initial={{ opacity: 0, y: 50 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: 50 }}
        transition={{ duration: 0.3 }}
        className={`fixed bottom-6 right-6 z-50 flex items-center gap-3 px-5 py-4 border rounded-xl shadow-lg ${styles[type]}`}
      >
        <div className="flex items-center gap-3">
          {icons[type]}
          <p className="font-medium tracking-wide">{message}</p>
        </div>

        {/* Botón de cierre */}
        <button
          onClick={onClose}
          className="ml-4 text-white/80 hover:text-white transition-all"
        >
          <X size={18} />
        </button>
      </Motion.div>
    </AnimatePresence>
  );
}
