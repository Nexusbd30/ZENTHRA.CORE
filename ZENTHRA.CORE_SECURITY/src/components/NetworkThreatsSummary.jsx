import { useEffect, useState } from "react";
import { getAlerts } from "@/api/nexusApi";

const NETWORK_ALERTS = [
  "NetworkDDoS",
  "NetworkRecon",
  "NetworkLateralMovement",
  "VPNUnstable",
  "DNSFailures",
];

export default function NetworkThreatsSummary() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const data = await getAlerts();
        if (!cancelled) {
          setAlerts(
            data.filter((alert) => NETWORK_ALERTS.includes(alert.labels?.alertname))
          );
        }
      } catch {
        if (!cancelled) setAlerts([]);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    const interval = setInterval(load, 10000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  return (
    <div className="bg-black/25 border border-cyan-500/40 rounded-2xl p-4 backdrop-blur shadow-lg">
      <p className="text-xs text-cyan-200 uppercase tracking-wide mb-2">
        Amenazas de Red (NOC / SOC)
      </p>

      {loading ? (
        <p className="text-sm text-cyan-100">Cargando amenazas...</p>
      ) : alerts.length === 0 ? (
        <p className="text-sm text-cyan-100">Sin amenazas de red activas.</p>
      ) : (
        <div className="space-y-2">
          {alerts.map((alert, index) => (
            <div
              key={`${alert.labels?.alertname || "alert"}-${index}`}
              className={`flex items-center justify-between px-2 py-1 rounded-lg border ${pill(alert.labels?.severity)}`}
            >
              <span className="text-xs font-semibold text-cyan-100">
                {alert.labels?.alertname || "unknown"}
              </span>
              <span className="text-[11px] opacity-80">
                {alert.labels?.severity || "unknown"}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function pill(severity) {
  if (severity === "critical") return "bg-red-500/20 text-red-300 border-red-500/40";
  if (severity === "high" || severity === "warning") return "bg-amber-500/20 text-amber-300 border-amber-500/40";
  if (severity === "medium") return "bg-blue-500/20 text-blue-300 border-blue-500/40";
  return "bg-slate-600/40 text-slate-200 border-slate-500/40";
}
