import { useNotify } from "@/components/NotificationProvider";

export default function TestNotify() {
  const notify = useNotify();

  return (
    <div className="flex flex-col items-center justify-center h-screen bg-neutral-900 text-white gap-4">
      <button
        onClick={() => notify("Operación exitosa ✅", "success")}
        className="px-4 py-2 bg-emerald-600 rounded-lg hover:bg-emerald-700"
      >
        Mostrar Éxito
      </button>
      <button
        onClick={() => notify("Error al guardar ❌", "error")}
        className="px-4 py-2 bg-red-600 rounded-lg hover:bg-red-700"
      >
        Mostrar Error
      </button>
      <button
        onClick={() => notify("Advertencia ⚠️", "warning")}
        className="px-4 py-2 bg-amber-600 rounded-lg hover:bg-amber-700"
      >
        Mostrar Advertencia
      </button>
      <button
        onClick={() => notify("Información ℹ️", "info")}
        className="px-4 py-2 bg-blue-600 rounded-lg hover:bg-blue-700"
      >
        Mostrar Info
      </button>
    </div>
  );
}