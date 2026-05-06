// =============================================================
// 🧠 useNotification — Hook global de notificaciones ZENTHRA
// =============================================================
// Permite mostrar mensajes globales desde cualquier componente.
// Se usa junto a <NotificationProvider>.
// =============================================================
//
// Ejemplo de uso:
// const { notify } = useNotification();
// notify("success", "Usuario creado correctamente ✅");
// =============================================================

import { useContext } from "react";
import { NotificationContext } from "@/components/NotificationProvider"; // ✅ Ruta absoluta limpia

export function useNotification() {
  const context = useContext(NotificationContext);

  if (!context) {
    throw new Error(
      "❌ useNotification debe usarse dentro de <NotificationProvider>"
    );
  }

  return context; // Devuelve { notify }
}