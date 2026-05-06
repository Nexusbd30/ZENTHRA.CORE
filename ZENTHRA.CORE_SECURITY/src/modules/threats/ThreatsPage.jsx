// =============================================================
// ThreatsPage — Mission-Critical skin (incidents view)
// =============================================================
// Mantiene flujo real:
//  - listThreats() para tabla (datos vivos)
//  - runCorrelationOnce() para correlación backend
//  - ThreatDetailsModal / ThreatFormModal para ver y crear
// =============================================================

import { useEffect, useState, useCallback } from "react";
import { listThreats, runCorrelationOnce } from "@/api/nexusApi";
import ThreatDetailsModal from "./ThreatDetailsModal";
import ThreatFormModal from "./ThreatFormModal";
import { useNotification } from "@/hooks/useNotification";

const OFFLINE_MSG = "No se puede conectar con el servidor.";

export default function ThreatsPage() {
  const { notify } = useNotification();

  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [stats, setStats] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  });

  const [selectedThreat, setSelectedThreat] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [correlationLoading, setCorrelationLoading] = useState(false);
  const [correlationMessage, setCorrelationMessage] = useState("");

  const loadThreats = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = await listThreats(0, 100);
      const items = Array.isArray(data) ? data : [];
      setThreats(items);

      const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
      items.forEach((t) => {
        const lvl = String(t.level || t.severity || "medium").toLowerCase();
        if (sevCounts[lvl] !== undefined) sevCounts[lvl] += 1;
      });
      setStats({
        total: items.length,
        ...sevCounts,
      });
    } catch (err) {
      const msg =
        err?.message || "Error al cargar las amenazas desde el servidor.";
      if (msg.includes(OFFLINE_MSG)) {
        notify("warning", "Backend offline — no se pueden cargar las amenazas.");
      } else {
        notify("error", msg);
      }
      setError(msg);
      setThreats([]);
      setStats({ total: 0, critical: 0, high: 0, medium: 0, low: 0 });
    } finally {
      setLoading(false);
    }
  }, [notify]);

  useEffect(() => {
    loadThreats();
  }, [loadThreats]);

  const handleRunCorrelation = async () => {
    try {
      setCorrelationLoading(true);
      setCorrelationMessage("");
      const res = await runCorrelationOnce();
      const created =
        typeof res?.created_count === "number"
          ? res.created_count
          : Array.isArray(res)
          ? res.length
          : 0;
      setCorrelationMessage(
        created > 0
          ? `Correlación ejecutada: ${created} nueva(s) amenaza(s).`
          : "Correlación ejecutada: sin nuevas amenazas."
      );
      await loadThreats();
    } catch (err) {
      const msg = err?.message || "Error al ejecutar correlación.";
      notify("error", msg);
      setCorrelationMessage(msg);
    } finally {
      setCorrelationLoading(false);
    }
  };

  const severityBadge = (level) => {
    const lvl = String(level || "medium").toLowerCase();
    const map = {
      critical: { bg: "rgba(255,180,171,0.12)", text: "#ffb4ab", border: "rgba(255,180,171,0.25)" },
      high: { bg: "rgba(255,84,81,0.12)", text: "#ff5451", border: "rgba(255,84,81,0.25)" },
      medium: { bg: "rgba(173,198,255,0.12)", text: "#adc6ff", border: "rgba(173,198,255,0.25)" },
      low: { bg: "rgba(74,225,118,0.12)", text: "#4ae176", border: "rgba(74,225,118,0.25)" },
    };
    const cls = map[lvl] || map.medium;
    return (
      <span
        className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-bold uppercase tracking-widest rounded-sm border"
        style={{
          backgroundColor: cls.bg,
          color: cls.text,
          borderColor: cls.border,
        }}
      >
        {lvl}
      </span>
    );
  };

  const formatDate = (ts) => {
    if (!ts) return "—";
    const d = new Date(ts);
    return Number.isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
  };

  return (
    <div className="min-h-screen bg-surface text-on-surface">
      {/* Header & stats */}
      <div className="flex flex-col items-center text-center gap-4 mb-8">
        <div>
          <h1 className="font-['Space_Grotesk'] text-4xl font-bold tracking-tighter text-[#adc6ff]">
            INCIDENT MONITOR
          </h1>
          <p className="text-outline font-label text-sm uppercase tracking-[0.2em]">
            Real-time Threat Intelligence Feed
          </p>
          {correlationMessage && (
            <p className="mt-2 text-xs text-outline">{correlationMessage}</p>
          )}
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
          <StatCard label="Active" value={stats.total} color="primary" />
          <StatCard label="Critical" value={stats.critical} color="error" />
          <StatCard label="Medium" value={stats.medium} color="on-surface" />
          <StatCard label="Resolved" value="—" color="secondary" />
        </div>
      </div>

      {/* Filters + actions */}
      <div className="bg-surface-container-low p-4 mb-6 flex flex-wrap gap-4 items-center justify-between">
        <div className="flex gap-3">
          <button
            onClick={handleRunCorrelation}
            disabled={correlationLoading}
            className="bg-gradient-to-br from-primary to-primary-container text-on-primary px-4 py-2 text-xs font-label uppercase font-bold tracking-widest rounded-sm flex items-center gap-2 disabled:opacity-60"
          >
            {correlationLoading ? "Running..." : "Run Correlation"}
          </button>
          <button
            onClick={() => setShowForm(true)}
            className="bg-surface-container-highest px-4 py-2 text-xs font-label uppercase tracking-widest text-on-surface hover:bg-surface-bright transition-colors rounded-sm flex items-center gap-2"
          >
            New Incident
          </button>
        </div>
        <div className="text-[10px] text-outline uppercase tracking-widest">
          Backend: {error ? "offline" : "online"}
        </div>
      </div>

      {/* Table */}
      <div className="bg-surface-container-low overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-surface-container-lowest">
              <TH>ID</TH>
              <TH>Timestamp</TH>
              <TH>Title</TH>
              <TH>Severity</TH>
              <TH>Source</TH>
              <TH>Assigned</TH>
              <TH align="right">Actions</TH>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#424754]/10">
            {loading && (
              <tr>
                <td colSpan={7} className="px-6 py-4 text-center text-outline">
                  Cargando amenazas...
                </td>
              </tr>
            )}
            {!loading && threats.length === 0 && (
              <tr>
                <td colSpan={7} className="px-6 py-4 text-center text-outline">
                  {error || "Sin datos"}
                </td>
              </tr>
            )}
            {!loading &&
              threats.map((t) => (
                <tr
                  key={t.id}
                  className="hover:bg-surface-container transition-colors group cursor-pointer border-l-2 border-transparent hover:border-primary"
                  onClick={() => setSelectedThreat(t)}
                >
                  <td className="px-6 py-4 text-xs font-mono text-primary">
                    {t.id}
                  </td>
                  <td className="px-6 py-4 text-xs text-on-surface-variant">
                    {formatDate(t.created_at || t.createdAt)}
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-sm font-medium text-on-surface">
                      {t.title || t.description || "Threat"}
                    </span>
                    <p className="text-[10px] text-outline">
                      Target: {t.target_service || t.database_host || "—"}
                    </p>
                  </td>
                  <td className="px-6 py-4">{severityBadge(t.level || t.severity)}</td>
                  <td className="px-6 py-4">
                    <span className="text-[10px] text-outline uppercase">
                      {t.source || "unknown"}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-xs text-on-surface-variant">
                      {t.created_by || "—"}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-right">
                    <button className="text-primary opacity-0 group-hover:opacity-100 transition-opacity">
                      <span className="material-symbols-outlined" aria-hidden="true">
                        visibility
                      </span>
                    </button>
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>

      {/* Modals */}
      {selectedThreat && (
        <ThreatDetailsModal
          threat={selectedThreat}
          onClose={() => setSelectedThreat(null)}
        />
      )}
      {showForm && (
        <ThreatFormModal
          isOpen={showForm}
          onClose={() => setShowForm(false)}
          onSuccess={() => {
            setShowForm(false);
            loadThreats();
          }}
        />
      )}
    </div>
  );
}

function StatCard({ label, value, color }) {
  const colorMap = {
    primary: "text-primary",
    secondary: "text-secondary",
    error: "text-error",
    "on-surface": "text-on-surface",
  };
  return (
    <div className="bg-surface-container p-4 rounded-sm min-w-[140px]">
      <p className="text-[10px] text-outline uppercase font-bold tracking-widest mb-1">
        {label}
      </p>
      <p className={`font-headline text-2xl ${colorMap[color] || "text-on-surface"}`}>
        {value}
      </p>
    </div>
  );
}

function TH({ children, align = "left" }) {
  return (
    <th
      className={`px-6 py-4 text-[10px] font-bold uppercase tracking-[0.2em] text-outline ${
        align === "right" ? "text-right" : "text-left"
      }`}
    >
      {children}
    </th>
  );
}
