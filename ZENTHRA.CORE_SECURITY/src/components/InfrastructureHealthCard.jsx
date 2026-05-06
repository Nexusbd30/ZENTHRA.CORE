import { useEffect, useState } from "react";
import { getFullInfraHealth } from "@/api/nexusApi";

export default function InfrastructureHealthCard() {
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;

    async function fetchHealth() {
      try {
        setLoading(true);
        setError(null);
        const data = await getFullInfraHealth();
        if (!cancelled) setHealth(data);
      } catch {
        if (!cancelled) setError("No se pudo obtener el estado de infraestructura.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    fetchHealth();
    const interval = setInterval(fetchHealth, 30000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const pillClass = (status) => {
    if (status === "up") return "bg-emerald-500/20 text-emerald-300 border-emerald-500/40";
    if (status === "degraded") return "bg-amber-500/20 text-amber-300 border-amber-500/40";
    if (status === "down") return "bg-red-500/20 text-red-300 border-red-500/40";
    return "bg-slate-600/40 text-slate-200 border-slate-500/40";
  };

  return (
    <div className="bg-black/25 border border-blue-500/40 rounded-2xl p-4">
      <p className="text-xs text-blue-200 uppercase tracking-wide mb-2">
        Estado de Infraestructura
      </p>

      {loading && <p className="text-sm text-blue-100">Cargando estado...</p>}
      {error && <p className="text-sm text-red-300">{error}</p>}

      {health && (
        <div className="space-y-2 text-sm">
          <div className="flex items-center justify-between">
            <span className="text-blue-100">Global</span>
            <span className={`px-2 py-0.5 rounded-full text-xs border ${pillClass(health.overall)}`}>
              {health.overall?.toUpperCase() || "N/A"}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs mt-2">
            {["backend", "database", "prometheus", "alertmanager"].map((key) => (
              <div
                key={key}
                className={`flex items-center justify-between px-2 py-1 rounded-lg border ${pillClass(health[key])}`}
              >
                <span className="capitalize text-blue-100">{key}</span>
                <span className="font-mono">{health[key] || "unknown"}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
