import { useEffect, useState } from "react";
import { Edit3, Plus, Trash2, ToggleLeft, ToggleRight } from "lucide-react";

import { deleteUser, getUsers, toggleUserActive } from "@/api/nexusApi";
import UserFormModal from "@/components/UserFormModal";
import { useNotify } from "@/components/NotificationProvider";

const OFFLINE_MSG = "No se puede conectar con el servidor.";

export default function Users() {
  const notify = useNotify();

  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      setError(null);

      const data = await getUsers(1, 50);
      const userList = Array.isArray(data) ? data : data?.items || data?.users || [];
      setUsers(userList);
    } catch (err) {
      const rawMessage = err?.message || "No se pudieron cargar los usuarios.";
      const message = rawMessage.includes(OFFLINE_MSG)
        ? "Backend offline: no se pueden cargar usuarios ahora mismo."
        : rawMessage;

      setError(message);
      setUsers([]);
      notify(rawMessage.includes(OFFLINE_MSG) ? "warning" : "error", message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const openCreateModal = () => {
    setSelectedUser(null);
    setShowModal(true);
  };

  const openEditModal = (user) => {
    setSelectedUser(user);
    setShowModal(true);
  };

  const closeModal = () => {
    setShowModal(false);
    setSelectedUser(null);
  };

  const handleDelete = async (id) => {
    if (!window.confirm("Seguro que deseas eliminar este usuario?")) return;

    try {
      await deleteUser(id);
      notify("warning", "Usuario eliminado correctamente");
      fetchUsers();
    } catch (err) {
      const rawMessage = err?.message || "No se pudo eliminar el usuario.";
      const message = rawMessage.includes(OFFLINE_MSG)
        ? "Backend offline: no se pueden eliminar usuarios ahora mismo."
        : rawMessage;
      notify("error", message);
    }
  };

  const handleToggleActive = async (user) => {
    try {
      await toggleUserActive(user.id, !user.is_active);
      notify("info", `Usuario ${user.is_active ? "desactivado" : "activado"} correctamente`);
      fetchUsers();
    } catch (err) {
      const rawMessage = err?.message || "No se pudo cambiar el estado del usuario.";
      const message = rawMessage.includes(OFFLINE_MSG)
        ? "Backend offline: no se puede cambiar el estado de usuarios ahora mismo."
        : rawMessage;
      notify("error", message);
    }
  };

  return (
    <div className="min-h-screen bg-[#0f172a] p-10 text-white">
      <div className="mb-8 flex items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-wider text-blue-400">
            Gestion de Usuarios
          </h1>
          <p className="mt-2 text-sm text-slate-400">
            Control de identidades, roles y estado de cuentas.
          </p>
        </div>

        <button
          onClick={openCreateModal}
          className="flex items-center gap-2 rounded-lg bg-blue-600 px-6 py-2 font-semibold shadow-md transition hover:bg-blue-700"
        >
          <Plus size={18} /> Nuevo Usuario
        </button>
      </div>

      {error && (
        <p className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-200">
          {error}
        </p>
      )}

      {loading ? (
        <p className="p-6 text-center text-gray-400">Cargando usuarios...</p>
      ) : (
        <div className="overflow-hidden rounded-xl border border-blue-500/30 bg-[#1e293b]/70 shadow-md backdrop-blur-sm">
          <table className="w-full border-collapse text-left">
            <thead className="bg-blue-950/50 text-sm uppercase text-blue-300">
              <tr>
                <th className="border-b border-blue-700/30 px-6 py-3">Nombre</th>
                <th className="border-b border-blue-700/30 px-6 py-3">Email</th>
                <th className="border-b border-blue-700/30 px-6 py-3">Rol</th>
                <th className="border-b border-blue-700/30 px-6 py-3">Estado</th>
                <th className="border-b border-blue-700/30 px-6 py-3 text-right">
                  Acciones
                </th>
              </tr>
            </thead>
            <tbody>
              {users.length === 0 && !error ? (
                <tr>
                  <td colSpan={5} className="py-6 text-center italic text-gray-400">
                    No hay usuarios registrados
                  </td>
                </tr>
              ) : (
                users.map((user) => (
                  <tr key={user.id} className="transition hover:bg-blue-900/30">
                    <td className="border-b border-blue-800/30 px-6 py-3">
                      {user.full_name || "-"}
                    </td>
                    <td className="border-b border-blue-800/30 px-6 py-3">
                      {user.email}
                    </td>
                    <td className="border-b border-blue-800/30 px-6 py-3 capitalize">
                      {user.role || "user"}
                    </td>
                    <td className="border-b border-blue-800/30 px-6 py-3">
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
                    <td className="border-b border-blue-800/30 px-6 py-3 text-right">
                      <div className="flex justify-end gap-3">
                        <button
                          onClick={() => openEditModal(user)}
                          className="transition hover:text-blue-400"
                          title="Editar"
                        >
                          <Edit3 size={18} />
                        </button>
                        <button
                          onClick={() => handleDelete(user.id)}
                          className="transition hover:text-red-500"
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

      <UserFormModal
        isOpen={showModal}
        user={selectedUser}
        onClose={closeModal}
        onSuccess={fetchUsers}
      />
    </div>
  );
}
