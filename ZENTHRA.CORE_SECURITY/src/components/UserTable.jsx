// =============================================================
// 💠 ZENTHRA UserTable — v2.5 Final Offline-aware
// =============================================================
// Módulo de gestión de usuarios (CRUD completo)
// - Integrado con backend FastAPI (/users/)
// - Autenticado con JWT mediante nexusApi
// - Diseño profesional (inspirado en AWS IAM Console)
// - Modo offline-aware:
//     * Si el backend no responde ("No se puede conectar con el servidor.")
//       se muestra un mensaje claro y NO se muestra
//       "No se encontraron usuarios" como si fuera tabla vacía real.
// =============================================================

import React, { useEffect, useState } from "react";
import { motion as Motion } from "framer-motion";
import {
  Search,
  UserCog,
  Trash2,
  Shield,
  RefreshCcw,
} from "lucide-react";

import nexusApi from "@/api/nexusApi";
import { useNotify } from "@/components/NotificationProvider";
import UserFormModal from "@/components/UserFormModal";
import ConfirmDialog from "@/components/ConfirmDialog";

const OFFLINE_MSG = "No se puede conectar con el servidor.";

export default function UserTable() {
  const notify = useNotify();

  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);

  const [selectedUser, setSelectedUser] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [error, setError] = useState(null);

  // =============================================================
  // 📦 CARGAR USUARIOS (con paginación y búsqueda)
  // =============================================================
  const fetchUsers = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await nexusApi.get(
        `/users/?page=${page}&limit=10${query ? `&search=${query}` : ""}`,
      );

      setUsers(response.data.items || []);
      setTotalPages(response.data.pages || 1);
    } catch (err) {
      console.error("❌ Error al obtener usuarios:", err);
      let msg = err?.message || "Error al cargar usuarios desde el servidor";

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
  }, [page, query]);

  // =============================================================
  // 🗑️ ELIMINAR USUARIO
  // =============================================================
  const handleDelete = async () => {
    if (!selectedUser) return;
    try {
      await nexusApi.delete(`/users/${selectedUser.id}`);
      notify(
        "success",
        `Usuario ${selectedUser.full_name} eliminado correctamente`,
      );
      setConfirmOpen(false);
      fetchUsers();
    } catch (err) {
      console.error("❌ Error al eliminar usuario:", err);
      const msg =
        err?.message || "Error al eliminar usuario desde el servidor";
      notify("error", msg);
    }
  };

  // =============================================================
  // 🎨 RENDER PRINCIPAL
  // =============================================================
  return (
    <div className="p-6 text-white">
      {/* CABECERA */}
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-semibold flex items-center gap-2">
          <Shield className="text-blue-400" size={24} />
          Gestión de Usuarios
        </h1>

        <button
          onClick={() => {
            setSelectedUser(null);
            setShowModal(true);
          }}
          className="px-4 py-2 bg-blue-600 rounded-xl hover:bg-blue-700 transition text-sm font-semibold"
        >
          + Nuevo usuario
        </button>
      </div>

      {/* BARRA DE BÚSQUEDA */}
      <div className="flex items-center gap-3 mb-4">
        <div className="flex items-center gap-2 bg-neutral-900 border border-neutral-700 rounded-xl px-3 py-2 w-full max-w-sm">
          <Search size={18} className="text-neutral-400" />
          <input
            type="text"
            placeholder="Buscar por nombre o correo..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="bg-transparent outline-none text-sm w-full"
          />
        </div>

        <button
          onClick={fetchUsers}
          className="p-2 bg-neutral-800 rounded-xl hover:bg-neutral-700 transition"
          title="Recargar lista"
        >
          <RefreshCcw size={18} className="text-blue-400" />
        </button>
      </div>

      {/* ERROR OFFLINE / OTROS */}
      {error && (
        <div className="mb-4 text-xs text-amber-200 bg-amber-500/10 border border-amber-500/30 px-3 py-2 rounded-lg">
          ⚠️ {error}
        </div>
      )}

      {/* TABLA DE USUARIOS */}
      <Motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="overflow-x-auto bg-neutral-900/70 border border-neutral-700 rounded-2xl shadow-lg backdrop-blur-sm"
      >
        <table className="min-w-full text-sm">
          <thead className="bg-neutral-800 text-neutral-300 uppercase text-xs">
            <tr>
              <th className="px-5 py-3 text-left">Nombre</th>
              <th className="px-5 py-3 text-left">Correo</th>
              <th className="px-5 py-3 text-left">Rol</th>
              <th className="px-5 py-3 text-left">Estado</th>
              <th className="px-5 py-3 text-center">Acciones</th>
            </tr>
          </thead>

          <tbody>
            {loading ? (
              <tr>
                <td colSpan={5} className="text-center py-6 text-neutral-400">
                  Cargando usuarios...
                </td>
              </tr>
            ) : users.length === 0 && !error ? (
              <tr>
                <td colSpan={5} className="text-center py-6 text-neutral-500">
                  No se encontraron usuarios
                </td>
              </tr>
            ) : (
              users.map((u) => (
                <tr
                  key={u.id}
                  className="border-t border-neutral-800 hover:bg-neutral-800/70 transition"
                >
                  <td className="px-5 py-3">{u.full_name}</td>
                  <td className="px-5 py-3">{u.email}</td>
                  <td className="px-5 py-3 capitalize">{u.role}</td>
                  <td className="px-5 py-3">
                    <span
                      className={`px-2 py-1 rounded-full text-xs font-medium ${
                        u.is_active
                          ? "bg-emerald-600/20 text-emerald-400 border border-emerald-500/30"
                          : "bg-red-600/20 text-red-400 border border-red-500/30"
                      }`}
                    >
                      {u.is_active ? "Activo" : "Inactivo"}
                    </span>
                  </td>
                  <td className="px-5 py-3 flex justify-center gap-3">
                    <button
                      onClick={() => {
                        setSelectedUser(u);
                        setShowModal(true);
                      }}
                      className="p-2 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/20 text-blue-300 transition"
                      title="Editar usuario"
                    >
                      <UserCog size={18} />
                    </button>

                    <button
                      onClick={() => {
                        setSelectedUser(u);
                        setConfirmOpen(true);
                      }}
                      className="p-2 rounded-lg bg-red-600/20 hover:bg-red-600/30 border border-red-500/20 text-red-400 transition"
                      title="Eliminar usuario"
                    >
                      <Trash2 size={18} />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </Motion.div>

      {/* PAGINACIÓN */}
      <div className="flex justify-end mt-4 gap-3 text-sm text-neutral-300">
        <button
          onClick={() => setPage((p) => Math.max(1, p - 1))}
          disabled={page <= 1}
          className={`px-3 py-1 rounded-lg border border-neutral-700 ${
            page <= 1 ? "opacity-50 cursor-not-allowed" : "hover:bg-neutral-800"
          }`}
        >
          Anterior
        </button>

        <span className="px-3 py-1 bg-neutral-800 rounded-lg">
          Página {page} / {totalPages}
        </span>

        <button
          onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
          disabled={page >= totalPages}
          className={`px-3 py-1 rounded-lg border border-neutral-700 ${
            page >= totalPages
              ? "opacity-50 cursor-not-allowed"
              : "hover:bg-neutral-800"
          }`}
        >
          Siguiente
        </button>
      </div>

      {/* MODALES */}
      <UserFormModal
        isOpen={showModal}
        onClose={() => setShowModal(false)}
        user={selectedUser}
        onSuccess={fetchUsers}
      />

      <ConfirmDialog
        isOpen={confirmOpen}
        title="Eliminar usuario"
        message={`¿Seguro que deseas eliminar la cuenta de ${selectedUser?.full_name}?`}
        confirmLabel="Eliminar"
        cancelLabel="Cancelar"
        danger
        onConfirm={handleDelete}
        onCancel={() => setConfirmOpen(false)}
      />
    </div>
  );
}

