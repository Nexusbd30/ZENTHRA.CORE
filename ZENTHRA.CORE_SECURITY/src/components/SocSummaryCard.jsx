import { useEffect, useState } from "react";
import nexusApi, { getAlerts } from "@/api/nexusApi";

export default function SocSummaryCard() {
  const [threatCount, setThreatCount] = useState(null);
  const [alertCount, setAlertCount] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;

    async function fetchSummary() {
      try {
        setLoading(true);
        setError(null);

        const [threatsRes, alerts] = await Promise.all([
          nexusApi.get("/threats/"),
          getAlerts(),
        ]);
        const threats = Array.isArray(threatsRes.data)
          ? threatsRes.data
          : threatsRes.data.items || threatsRes.data.results || [];

        if (!cancelled) {
          setThreatCount(threats.length);
          setAlertCount(Array.isArray(alerts) ? alerts.length : 0);
        }
      } catch {
        if (!cancelled) setError("No se pudo cargar el resumen SOC.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    fetchSummary();
    const interval = setInterval(fetchSummary, 60000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  return (
    <div className="bg-slate-900/40 border border-slate-700/60 rounded-2xl p-5 shadow-lg backdrop-blur-md">
      <p className="text-xs text-slate-300 uppercase tracking-wide mb-2">
        Resumen SOC
      </p>

      {loading && <p className="text-sm text-slate-200">Cargando resumen...</p>}
      {error && <p className="text-sm text-red-400">{error}</p>}

      {!loading && !error && (
        <div className="grid grid-cols-2 gap-4 text-sm">
          <SummaryMetric
            label="Amenazas registradas"
            value={threatCount ?? "N/A"}
            detail="Incluye manuales y automaticas."
            tone="text-amber-300"
          />
          <SummaryMetric
            label="Alertas activas"
            value={alertCount ?? "N/A"}
            detail="Firing desde Alertmanager."
            tone="text-rose-300"
          />
        </div>
      )}

      <div className="mt-3 text-[11px] text-slate-400/80">
        ZENTHRA.CORE_SECURITY - Vista rapida del estado SOC.
      </div>
    </div>
  );
}

function SummaryMetric({ label, value, detail, tone }) {
  return (
    <div className="flex flex-col">
      <span className="text-slate-400 text-xs uppercase tracking-wide">{label}</span>
      <span className={`text-2xl font-bold mt-1 ${tone}`}>{value}</span>
      <span className="text-[11px] text-slate-400 mt-1">{detail}</span>
    </div>
  );
}
