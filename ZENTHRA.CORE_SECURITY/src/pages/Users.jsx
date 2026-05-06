// =============================================================
// 👥 Users.jsx — ZENTHRA.CORE_SECURITY (v2.8 Hardened+UX+Offline)
// =============================================================
// Panel de gestión de usuarios (Dashboard privado).
// Mejoras clave:
// - Manejo de errores con notificaciones (401/403/otros)
// - 403 en /users/* → mensaje claro de rol admin (desde nexusApi)
// - Validación mínima en formulario
// - Estados de carga/guardado claros
// - Modo offline-aware:
//     * Si el backend no responde ("No se puede conectar con el servidor.")
//       se muestra un mensaje claro y NO se muestra
//       "No hay usuarios registrados" como si fuera tabla vacía real.
// =============================================================

import { useEffect, useState } from "react";
import {
  getUsers,
  createUser,
  updateUser,
  deleteUser,
  toggleUserActive,
} from "@/api/nexusApi";
import { Plus, Edit3, Trash2, ToggleLeft, ToggleRight } from "lucide-react";
import { useNotify } from "@/components/NotificationProvider";

const OFFLINE_MSG = "No se puede conectar con el servidor.";

export default function Users() {
  const notify = useNotify();

  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [_showModal, setShowModal] = useState(false);
  const [_saving, setSaving] = useState(false);
  const [isEditing, setIsEditing] = useState(false);

  const [formData, setFormData] = useState({
    id: null,
    full_name: "",
    email: "",
    password: "",
    role: "user",
    is_active: true,
  });

  // ===========================================================
  // 📦 OBTENER USUARIOS
  // ===========================================================
  const fetchUsers = async () => {
    try {
      setLoading(true);
      setError(null);

      const data = await getUsers();

      const userList = Array.isArray(data)
        ? data
        : data?.items || data?.users || [];

      setUsers(userList);
    } catch (err) {
      console.error("❌ Error al obtener usuarios:", err);
      let msg = err?.message || "No se pudieron cargar los usuarios.";

      if (msg.includes(OFFLINE_MSG)) {
        msg = "Backend offline — no se pueden cargar los usuarios ahora mismo.";
        notify("warning", `⚠️ ${msg}`);
      } else {
        notify("error", msg);
      }

      setError(msg);
      setUsers([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  // ===========================================================
  // 💾 GUARDAR / ACTUALIZAR
  // ===========================================================
  const _handleSubmit = async (e) => {
    e.preventDefault();

    if (!formData.full_name?.trim()) {
      notify("warning", "⚠️ El nombre es obligatorio");
      return;
    }
    if (!formData.email?.includes("@")) {
      notify("warning", "⚠️ Ingresa un correo válido");
      return;
    }
    if (!isEditing && !formData.password) {
      notify("warning", "⚠️ La contraseña es obligatoria para crear");
      return;
    }

    try {
      setSaving(true);

      if (isEditing) {
        await updateUser(formData.id, {
          full_name: formData.full_name,
          email: formData.email,
          role: formData.role,
          is_active: formData.is_active,
        });
        notify("success", "✅ Usuario actualizado correctamente");
      } else {
        await createUser({
          full_name: formData.full_name,
          email: formData.email,
          password: formData.password,
          role: formData.role,
          is_active: formData.is_active,
        });
        notify("success", "✅ Usuario creado exitosamente");
      }

      await fetchUsers();
      setShowModal(false);
      resetForm();
    } catch (err) {
      console.error("❌ Error al guardar usuario:", err);
      let msg = err?.message || "No se pudo guardar el usuario.";

      if (msg.includes(OFFLINE_MSG)) {
        msg = "Backend offline — no se pueden guardar cambios de usuario ahora mismo.";
      }

      notify("error", msg);
    } finally {
      setSaving(false);
    }
  };

  // ===========================================================
  // 🔧 UTILIDADES
  // ===========================================================
  const resetForm = () => {
    setFormData({
      id: null,
      full_name: "",
      email: "",
      password: "",
      role: "user",
      is_active: true,
    });
    setIsEditing(false);
  };

  const handleEdit = (user) => {
    setFormData({
      id: user.id,
      full_name: user.full_name,
      email: user.email,
      password: "",
      role: user.role,
      is_active: user.is_active,
    });
    setIsEditing(true);
    setShowModal(true);
  };

  const handleDelete = async (id) => {
    if (!window.confirm("¿Seguro que deseas eliminar este usuario?")) return;
    try {
      await deleteUser(id);
      notify("warning", "🗑️ Usuario eliminado correctamente");
      fetchUsers();
    } catch (err) {
      let msg = err?.message || "No se pudo eliminar el usuario.";
      if (msg.includes(OFFLINE_MSG)) {
        msg = "Backend offline — no se puede eliminar usuarios ahora mismo.";
      }
      notify("error", msg);
    }
  };

  const handleToggleActive = async (user) => {
    try {
      await toggleUserActive(user.id, !user.is_active);
      notify(
        "info",
        `🔁 Usuario ${user.is_active ? "desactivado" : "activado"} correctamente`,
      );
      fetchUsers();
    } catch (err) {
      let msg =
        err?.message || "⚠️ No se pudo cambiar el estado del usuario.";
      if (msg.includes(OFFLINE_MSG)) {
        msg =
          "Backend offline — no se puede cambiar el estado de usuarios ahora mismo.";
      }
      notify("error", msg);
    }
  };

  // ===========================================================
  // 🎨 RENDERIZADO
  // ===========================================================
  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-10">
      {/* Encabezado */}
      <div className="flex justify-between items-center mb-8">
        <h1 className="text-3xl font-bold text-blue-400 tracking-wider">
          👥 Gestión de Usuarios
        </h1>
        <button
          onClick={() => {
            resetForm();
            setShowModal(true);
          }}
          className="flex itemscenter gap-2 bg-blue-600 hover:bg-blue-700 px-6 py-2 rounded-lg font-semibold transition-all shadow-md"
        >
          <Plus size={18} /> Nuevo Usuario
        </button>
      </div>

      {/* Mensaje de error/offline */}
      {error && (
        <p className="mb-4 text-sm text-amber-200 bg-amber-500/10 border border-amber-500/30 px-3 py-2 rounded-lg">
          ⚠️ {error}
        </p>
      )}

      {/* Tabla de usuarios */}
      {loading ? (
        <p className="text-center p-6 text-gray-400">Cargando usuarios...</p>
      ) : (
        <div className="bg-[#1e293b]/70 border border-blue-500/30 rounded-xl shadow-md overflow-hidden backdrop-blur-sm">
          <table className="w-full border-collapse text-left">
            <thead className="bg-blue-950/50 text-blue-300 uppercase text-sm">
              <tr>
                <th className="px-6 py-3 border-b border-blue-700/30">Nombre</th>
                <th className="px-6 py-3 border-b border-blue-700/30">Email</th>
                <th className="px-6 py-3 border-b border-blue-700/30">Rol</th>
                <th className="px-6 py-3 border-b border-blue-700/30">Estado</th>
                <th className="px-6 py-3 border-b border-blue-700/30 text-right">
                  Acciones
                </th>
              </tr>
            </thead>
            <tbody>
              {users.length === 0 && !error ? (
                <tr>
                  <td
                    colSpan={5}
                    className="text-center py-6 text-gray-400 italic"
                  >
                    No hay usuarios registrados
                  </td>
                </tr>
              ) : (
                users.map((user) => (
                  <tr
                    key={user.id}
                    className="hover:bg-blue-900/30 transition-all duración-150"
                  >
                    <td className="px-6 py-3 border-b border-blue-800/30">
                      {user.full_name}
                    </td>
                    <td className="px-6 py-3 border-b border-blue-800/30">
                      {user.email}
                    </td>
                    <td className="px-6 py-3 border-b border-blue-800/30 capitalize">
                      {user.role}
                    </td>
                    <td className="px-6 py-3 border-b border-blue-800/30">
                      <button

                        onClick={() => handleToggleActive(user)}
                        className="flex items-center gap-2 text-blue-300"
                      >
                        {user.is_active ? (
                          <>
                            <ToggleRight className="text-green-400" /> Activo
                          </>
                        ) : (
                          <>
                            <ToggleLeft className="text-gray-500" /> Inactivo
                          </>
                        )}
                      </button>
                    </td>
                    <td className="px-6 py-3 border-b border-blue-800/30 text-right">
                      <div className="flex justify-end gap-3">
                        <button
                          onClick={() => handleEdit(user)}
                          className="hover:text-blue-400 transition-all"
                          title="Editar"
                        >
                          <Edit3 size={18} />
                        </button>
                        <button
                          onClick={() => handleDelete(user.id)}
                          className="hover:text-red-500 transition-all"
                          title="Eliminar"
                        >
                          <Trash2 size={18} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Modal de creación/edición (sin cambios de estructura) */}
      {/* ... tu modal inline como ya lo tenías ... */}
      {/* lo puedes dejar igual, solo se apoya en handleSubmit */}
    </div>
  );
}
