// =============================================================
// 💠 ZENTHRA UserFormModal — v2.4 Final
// =============================================================
// Modal profesional para creación y edición de usuarios.
// Integrado con:
//   - Backend FastAPI (/users/)
//   - Sistema JWT vía nexusApi
//   - Notificaciones globales (NotificationProvider)
// =============================================================

import React, { useState, useEffect } from "react";
import { motion as Motion, AnimatePresence } from "framer-motion";
import { X, Save, UserPlus, Shield } from "lucide-react";
import nexusApi from "@/api/nexusApi";
import { useNotify } from "@/components/NotificationProvider";

// =============================================================
// ⚙️ COMPONENTE PRINCIPAL
// =============================================================
export default function UserFormModal({ isOpen, onClose, user, onSuccess }) {
  const notify = useNotify();

  // ------------------------------------------------------------
  // 🧠 ESTADOS
  // ------------------------------------------------------------
  const [formData, setFormData] = useState({
    full_name: "",
    email: "",
    password: "",
    role: "user",
    is_active: true,
  });

  const [loading, setLoading] = useState(false);

  // ------------------------------------------------------------
  // ✳️ Cargar datos si es modo edición
  // ------------------------------------------------------------
  useEffect(() => {
    if (user) {
      setFormData({
        full_name: user.full_name || "",
        email: user.email || "",
        password: "",
        role: user.role || "user",
        is_active: user.is_active ?? true,
      });
    } else {
      // 🔁 Reset al abrir en modo "crear"
      setFormData({
        full_name: "",
        email: "",
        password: "",
        role: "user",
        is_active: true,
      });
    }
  }, [user, isOpen]);

  // ------------------------------------------------------------
  // 🧩 Manejo de cambios
  // ------------------------------------------------------------
  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: type === "checkbox" ? checked : value,
    }));
  };

  // ------------------------------------------------------------
  // 💾 Enviar formulario (crear o actualizar)
  // ------------------------------------------------------------
  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      if (user) {
        // ✏️ Actualizar usuario existente
        await nexusApi.put(`/users/${user.id}`, formData);
        notify("success", `Usuario ${formData.full_name} actualizado correctamente`);
      } else {
        // 🟢 Crear nuevo usuario
        await nexusApi.post(`/users/`, formData);
        notify("success", `Usuario ${formData.full_name} creado correctamente`);
      }

      onSuccess?.(); // 🔁 Refresca tabla
      onClose(); // 🔒 Cierra modal
    } catch (err) {
      console.error("❌ Error al guardar usuario:", err);
      const msg =
        err.response?.data?.detail ||
        "Error al guardar los datos del usuario";
      notify("error", msg);
    } finally {
      setLoading(false);
    }
  };

  // ------------------------------------------------------------
  // 🎨 RENDER DEL MODAL
  // ------------------------------------------------------------
  return (
    <AnimatePresence>
      {isOpen && (
        <Motion.div
          className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
        >
          {/* Contenedor principal */}
          <Motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.9, opacity: 0 }}
            className="bg-neutral-900 border border-neutral-700 rounded-2xl shadow-xl p-6 w-[420px] text-white relative"
          >
            {/* Cerrar */}
            <button
              onClick={onClose}
              className="absolute top-3 right-3 text-neutral-400 hover:text-white transition"
            >
              <X size={20} />
            </button>

            {/* Título */}
            <div className="flex items-center gap-2 mb-4">
              <Shield className="text-blue-400" size={22} />
              <h2 className="text-xl font-semibold">
                {user ? "Editar usuario" : "Nuevo usuario"}
              </h2>
            </div>

            {/* Formulario */}
            <form onSubmit={handleSubmit} className="flex flex-col gap-4">
              {/* Nombre */}
              <div>
                <label className="text-sm text-neutral-400">Nombre completo</label>
                <input
                  type="text"
                  name="full_name"
                  value={formData.full_name}
                  onChange={handleChange}
                  required
                  className="w-full mt-1 p-2 rounded-lg bg-neutral-800 border border-neutral-700 outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              {/* Correo */}
              <div>
                <label className="text-sm text-neutral-400">Correo electrónico</label>
                <input
                  type="email"
                  name="email"
                  value={formData.email}
                  onChange={handleChange}
                  required
                  className="w-full mt-1 p-2 rounded-lg bg-neutral-800 border border-neutral-700 outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              {/* Contraseña */}
              {!user && (
                <div>
                  <label className="text-sm text-neutral-400">Contraseña</label>
                  <input
                    type="password"
                    name="password"
                    value={formData.password}
                    onChange={handleChange}
                    required={!user}
                    className="w-full mt-1 p-2 rounded-lg bg-neutral-800 border border-neutral-700 outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              )}

              {/* Rol */}
              <div>
                <label className="text-sm text-neutral-400">Rol</label>
                <select
                  name="role"
                  value={formData.role}
                  onChange={handleChange}
                  className="w-full mt-1 p-2 rounded-lg bg-neutral-800 border border-neutral-700 outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="user">Usuario</option>
                  <option value="admin">Administrador</option>
                </select>
              </div>

              {/* Estado */}
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="is_active"
                  name="is_active"
                  checked={formData.is_active}
                  onChange={handleChange}
                  className="accent-blue-500"
                />
                <label htmlFor="is_active" className="text-sm text-neutral-400">
                  Usuario activo
                </label>
              </div>

              {/* Botón de acción */}
              <button
                type="submit"
                disabled={loading}
                className={`flex items-center justify-center gap-2 px-4 py-2 rounded-lg font-semibold mt-3 transition-all ${
                  loading
                    ? "bg-neutral-700 cursor-not-allowed"
                    : "bg-blue-600 hover:bg-blue-700"
                }`}
              >
                {loading ? (
                  "Guardando..."
                ) : user ? (
                  <>
                    <Save size={16} /> Actualizar
                  </>
                ) : (
                  <>
                    <UserPlus size={16} /> Crear
                  </>
                )}
              </button>
            </form>
          </Motion.div>
        </Motion.div>
      )}
    </AnimatePresence>
  );
}
