import { useEffect, useMemo, useState } from "react";
import { getHostSummary, getRuntimeLogs, getSourceDiagnostics } from "@/api/nexusApi";

const REFRESH_MS = 15000;

export default function DiagnosticsPage() {
  const [diagnostics, setDiagnostics] = useState(null);
  const [host, setHost] = useState(null);
  const [logs, setLogs] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      const [diagResult, hostResult, logResult] = await Promise.allSettled([
        getSourceDiagnostics(),
        getHostSummary(),
        getRuntimeLogs({ limit: 20 }),
      ]);

      if (cancelled) return;

      setDiagnostics(diagResult.status === "fulfilled" ? diagResult.value : null);
      setHost(hostResult.status === "fulfilled" ? hostResult.value : null);
      setLogs(logResult.status === "fulfilled" ? logResult.value : null);

      const failed = [diagResult, hostResult, logResult].filter((item) => item.status === "rejected");
      setError(failed.length ? "Una o mas fuentes no respondieron. Mostrando solo datos reales disponibles." : "");
      setLoading(false);
    };

    load();
    const intervalId = setInterval(load, REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(intervalId);
    };
  }, []);

  const sourceRows = useMemo(() => {
    const sources = diagnostics?.sources || {};
    return [
      ["backend", sources.backend],
      ["database", sources.database],
      ["prometheus", sources.prometheus],
      ["alertmanager", sources.alertmanager],
      ["windows-exporter", sources.windows_exporter],
      ["gpu", sources.gpu],
      ["logs", sources.logs],
    ].map(([name, item]) => ({
      name,
      status: item?.status || "unknown",
      detail: item?.detail || "sin datos reales",
    }));
  }, [diagnostics]);

  return (
    <div className="min-h-full bg-[#0a0e14] text-[#f1f3fc]">
      <section className="mb-6 grid grid-cols-1 gap-4 lg:grid-cols-4">
        <SummaryCard label="Estado global" value={loading ? "..." : diagnostics?.overall || "N/A"} />
        <SummaryCard label="CPU" value={formatMetric(host?.cpu_percent, "%")} />
        <SummaryCard label="Memoria" value={formatMetric(host?.memory_percent, "%")} />
        <SummaryCard label="Red" value={formatMetric(host?.network_mbps, " Mb/s")} />
      </section>

      {error && (
        <div className="mb-6 border-l-2 border-amber-400 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">
          {error}
        </div>
      )}

      <section className="mb-6 bg-[#0f141a] p-5">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="font-label text-xs uppercase tracking-[0.2em] text-[#8ff5ff]">
            Diagnostico de fuentes
          </h3>
          <span className="font-label text-[10px] uppercase text-slate-500">
            Auto-refresh 15s
          </span>
        </div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
          {sourceRows.map((row) => (
            <div key={row.name} className="border border-white/5 bg-[#151a21] px-4 py-3">
              <div className="mb-1 flex items-center justify-between gap-3">
                <span className="font-label text-[10px] uppercase tracking-widest text-slate-500">
                  {row.name}
                </span>
                <span className={`font-label text-[10px] uppercase ${statusClass(row.status)}`}>
                  {row.status}
                </span>
              </div>
              <p className="truncate text-xs text-[#a8abb3]" title={row.detail}>
                {row.detail}
              </p>
            </div>
          ))}
        </div>
      </section>

      <section className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <div className="bg-[#0f141a] p-5">
          <h3 className="mb-4 font-label text-xs uppercase tracking-[0.2em] text-[#8ff5ff]">
            Host summary
          </h3>
          <pre className="max-h-[420px] overflow-auto bg-black/40 p-4 text-xs text-[#8ff5ff]/80">
            {JSON.stringify(host || { status: "sin datos reales" }, null, 2)}
          </pre>
        </div>

        <div className="bg-[#0f141a] p-5">
          <h3 className="mb-4 font-label text-xs uppercase tracking-[0.2em] text-[#8ff5ff]">
            Ultimos logs
          </h3>
          <div className="max-h-[420px] overflow-auto space-y-2">
            {(logs?.items || []).length ? (
              logs.items.map((item) => (
                <div key={item.event_id} className="border-l border-[#8ff5ff]/30 bg-[#151a21] px-3 py-2">
                  <p className="font-label text-[10px] uppercase text-slate-500">
                    {item.timestamp || "N/A"} / {item.logger || "backend"}
                  </p>
                  <p className="text-xs text-[#f1f3fc]">{item.message || item.raw || "sin mensaje"}</p>
                </div>
              ))
            ) : (
              <p className="text-sm text-[#a8abb3]">Sin datos reales de logs.</p>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}

function SummaryCard({ label, value }) {
  return (
    <div className="border-l-2 border-[#8ff5ff] bg-[#0f141a] p-5">
      <p className="mb-1 font-label text-[10px] uppercase tracking-widest text-[#a8abb3]">{label}</p>
      <p className="font-headline text-2xl font-bold text-[#f1f3fc]">{value}</p>
    </div>
  );
}

function formatMetric(metric, suffix) {
  if (!metric?.available || !Number.isFinite(Number(metric.value))) return "N/A";
  return `${Number(metric.value).toFixed(1)}${suffix}`;
}

function statusClass(status) {
  if (status === "up") return "text-[#8ff5ff]";
  if (status === "missing") return "text-amber-300";
  if (status === "down") return "text-[#ff716c]";
  return "text-slate-500";
}
