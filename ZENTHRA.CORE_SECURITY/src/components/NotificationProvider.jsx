// =============================================================
// 💠 ZENTHRA Notification Provider (v3.6 Enterprise)
// =============================================================
// - Contexto global de notificaciones
// - API uniforme: notify(type, message, duration?)
// - Compatible con Tailwind + Framer Motion
// =============================================================

import React, { createContext, useContext, useState, useCallback } from "react";
import { motion as Motion, AnimatePresence } from "framer-motion";
import { CheckCircle, XCircle, AlertTriangle, Info, X } from "lucide-react";

// =============================================================
// 🧠 Contexto global
// =============================================================
export const NotificationContext = createContext(null);

// Hook recomendado (si no usas el de /hooks)
export function useNotification() {
  const ctx = useContext(NotificationContext);
  if (!ctx) throw new Error("useNotification debe usarse dentro de <NotificationProvider>");
  return ctx; // { notify }
}

// (Alias legacy, por compatibilidad con código antiguo)
export const useNotify = () => {
  const ctx = useContext(NotificationContext);
  if (!ctx) throw new Error("useNotify debe usarse dentro de <NotificationProvider>");
  // Permite llamar useNotify()(type, message, duration)
  return (type, message, duration) => ctx.notify(type, message, duration);
};

// =============================================================
// 🎨 Estilos e íconos por tipo
// =============================================================
const styles = {
  success: "bg-emerald-600/90 border-emerald-400 text-emerald-50",
  error:   "bg-red-600/90 border-red-400 text-red-50",
  warning: "bg-yellow-600/90 border-yellow-400 text-yellow-50",
  info:    "bg-blue-600/90 border-blue-400 text-blue-50",
};

const icons = {
  success: <CheckCircle className="w-5 h-5" />,
  error:   <XCircle className="w-5 h-5" />,
  warning: <AlertTriangle className="w-5 h-5" />,
  info:    <Info className="w-5 h-5" />,
};

// =============================================================
// 🧩 Provider
// API: notify(type, message, duration = 5000)
// =============================================================
export function NotificationProvider({ children }) {
  const [notifications, setNotifications] = useState([]);

  const notify = useCallback((type = "info", message = "", duration = 5000) => {
    const id = crypto?.randomUUID?.() || `${Date.now()}-${Math.random()}`;
    const safeType = styles[type] ? type : "info";

    setNotifications((prev) => [...prev, { id, type: safeType, message }]);

    // Auto-cierre
    const timer = setTimeout(() => {
      setNotifications((prev) => prev.filter((n) => n.id !== id));
    }, duration);

    // Opcional: devuelve función para cerrar manualmente desde el caller
    return () => {
      clearTimeout(timer);
      setNotifications((prev) => prev.filter((n) => n.id !== id));
    };
  }, []);

  const closeNotification = (id) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id));
  };

  return (
    <NotificationContext.Provider value={{ notify }}>
      {children}

      {/* Contenedor de toasts */}
      <div className="fixed bottom-6 right-6 z-[9999] flex flex-col gap-3 w-full max-w-sm">
        <AnimatePresence>
          {notifications.map((n) => (
            <Motion.div
              key={n.id}
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 30 }}
              transition={{ duration: 0.25 }}
              className={`flex items-center justify-between px-4 py-3 border rounded-xl shadow-lg ${styles[n.type]}`}
            >
              <div className="flex items-center gap-3">
                {icons[n.type]}
                <p className="text-sm font-medium tracking-wide">{n.message}</p>
              </div>
              <button
                onClick={() => closeNotification(n.id)}
                className="text-white/80 hover:text-white transition"
                aria-label="Cerrar notificación"
              >
                <X size={16} />
              </button>
            </Motion.div>
          ))}
        </AnimatePresence>
      </div>
    </NotificationContext.Provider>
  );
}
