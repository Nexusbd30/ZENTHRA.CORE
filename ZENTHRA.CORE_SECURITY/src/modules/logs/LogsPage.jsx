import { useEffect, useMemo, useState } from "react";
import { getRuntimeLogs } from "@/api/nexusApi";

const AUTO_REFRESH_MS = 15000;
const FILTERS = ["all", "critical", "high", "medium", "low"];

export default function LogsPage() {
  const [logs, setLogs] = useState([]);
  const [selectedId, setSelectedId] = useState("");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [severity, setSeverity] = useState("all");
  const [query, setQuery] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [files, setFiles] = useState([]);

  const fetchLogs = async (options = {}) => {
    const isBackgroundRefresh = options.background === true;

    try {
      if (isBackgroundRefresh) {
        setRefreshing(true);
      } else {
        setLoading(logs.length === 0);
      }
      setError("");
      const response = await getRuntimeLogs({
        limit: 250,
        severity: normalizeSeverityFilter(options.severity ?? severity),
        search: options.search ?? query,
      });
      const items = Array.isArray(response?.items) ? response.items : [];
      setLogs(items);
      setFiles(Array.isArray(response?.files) ? response.files : []);
      setSelectedId((current) => current && items.some((item) => item.event_id === current) ? current : items[0]?.event_id || "");
    } catch (err) {
      setError(err?.message || "No se pudieron cargar los logs");
      if (!isBackgroundRefresh) {
        setLogs([]);
        setSelectedId("");
      }
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchLogs();
    const intervalId = setInterval(() => fetchLogs({ background: true }), AUTO_REFRESH_MS);
    return () => clearInterval(intervalId);
  }, []);

  useEffect(() => {
    fetchLogs({ severity, search: query });
  }, [severity, query]);

  const selectedLog = useMemo(
    () => logs.find((item) => item.event_id === selectedId) || logs[0] || null,
    [logs, selectedId]
  );

  const footerText = loading
    ? "Loading live backend logs..."
    : refreshing
      ? `Refreshing ${logs.length} live entries from ${files.join(", ") || "backend logs"}...`
    : `Showing ${logs.length} live entries from ${files.join(", ") || "backend logs"}`;

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(logs, null, 2)], {
      type: "application/json;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "zenthra-runtime-logs.json";
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleSearchSubmit = (event) => {
    event.preventDefault();
    setQuery(searchInput.trim());
  };

  return (
    <div className="relative min-h-full">
      <div className="pointer-events-none fixed inset-0 dot-grid opacity-100" />

      <div className="relative z-10 flex h-[calc(100vh-7.5rem)] gap-6">
        <section className="flex min-w-0 flex-1 flex-col overflow-hidden rounded-sm border border-[#44484f]/10 bg-[#0f141a]">
          <div className="flex items-center justify-between bg-[#1b2028] p-4">
            <div className="flex items-center gap-4">
              <span className="font-['JetBrains_Mono'] text-[10px] uppercase tracking-widest text-slate-500">
                Filters:
              </span>
              <div className="flex flex-wrap gap-2">
                {FILTERS.map((item) => (
                  <FilterButton
                    key={item}
                    active={severity === item}
                    severity={item}
                    onClick={() => setSeverity(item)}
                  />
                ))}
              </div>
            </div>

            <div className="flex gap-2">
              <button
                type="button"
                onClick={handleExport}
                className="flex items-center gap-2 border border-[#44484f]/10 bg-[#20262f] px-3 py-1 font-['JetBrains_Mono'] text-[10px] uppercase text-[#a8abb3] transition-colors hover:border-[#8ff5ff]/40"
              >
                <span className="material-symbols-outlined text-xs">file_download</span>
                Export
              </button>
              <button
                type="button"
                onClick={() => fetchLogs()}
                className="flex items-center gap-2 border border-[#44484f]/10 bg-[#20262f] px-3 py-1 font-['JetBrains_Mono'] text-[10px] uppercase text-[#a8abb3] transition-colors hover:border-[#8ff5ff]/40"
              >
                <span className="material-symbols-outlined text-xs">refresh</span>
                Refresh
              </button>
            </div>
          </div>

          <div className="border-b border-[#44484f]/10 bg-[#151a21] px-4 py-3">
            <form onSubmit={handleSearchSubmit} className="group flex items-center rounded-sm border border-[#44484f]/10 bg-[#0f141a] px-4 py-1.5 transition-all focus-within:border-[#8ff5ff]/30">
              <span className="material-symbols-outlined mr-2 text-sm text-slate-500 group-focus-within:text-[#8ff5ff]">
                search
              </span>
              <input
                type="text"
                value={searchInput}
                onChange={(event) => setSearchInput(event.target.value)}
                placeholder="SEARCH LOGS BY PATH, STATUS, LOGGER, OR KEYWORD..."
                className="w-full bg-transparent font-['JetBrains_Mono'] text-[10px] uppercase tracking-wider text-[#f1f3fc] outline-none placeholder:text-slate-600"
              />
            </form>
          </div>

          <div className="custom-scrollbar flex-1 overflow-auto">
            <table className="min-w-[1100px] w-full border-collapse text-left">
              <thead className="sticky top-0 z-20 bg-[#0f141a]">
                <tr className="border-b border-[#44484f]/10">
                  <th className="px-4 py-3 font-['JetBrains_Mono'] text-[10px] uppercase tracking-widest text-slate-500">Timestamp</th>
                  <th className="px-4 py-3 font-['JetBrains_Mono'] text-[10px] uppercase tracking-widest text-slate-500">Event ID</th>
                  <th className="px-4 py-3 font-['JetBrains_Mono'] text-[10px] uppercase tracking-widest text-slate-500">Source IP</th>
                  <th className="px-4 py-3 font-['JetBrains_Mono'] text-[10px] uppercase tracking-widest text-slate-500">Dest IP</th>
                  <th className="px-4 py-3 font-['JetBrains_Mono'] text-[10px] uppercase tracking-widest text-slate-500">Protocol</th>
                  <th className="px-4 py-3 font-['JetBrains_Mono'] text-[10px] uppercase tracking-widest text-slate-500">Action</th>
                  <th className="px-4 py-3 text-right font-['JetBrains_Mono'] text-[10px] uppercase tracking-widest text-slate-500">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#44484f]/5">
                {loading && (
                  <tr>
                    <td colSpan={7} className="px-4 py-6 font-['JetBrains_Mono'] text-[11px] text-[#a8abb3]">
                      Loading runtime logs from backend...
                    </td>
                  </tr>
                )}
                {!loading && logs.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-4 py-6 font-['JetBrains_Mono'] text-[11px] text-[#a8abb3]">
                      {error || "No matching logs found."}
                    </td>
                  </tr>
                )}
                {logs.map((log) => (
                  <tr
                    key={log.event_id}
                    onClick={() => setSelectedId(log.event_id)}
                    className={`cursor-pointer transition-colors hover:bg-[#8ff5ff]/5 ${
                      selectedLog?.event_id === log.event_id ? "border-l-2 border-[#8ff5ff] bg-[#8ff5ff]/10" : ""
                    }`}
                  >
                    <td className="px-4 py-3 font-['JetBrains_Mono'] text-[11px] text-[#a8abb3]">
                      {formatTimestamp(log.timestamp)}
                    </td>
                    <td className="px-4 py-3 font-['JetBrains_Mono'] text-[11px] text-[#8ff5ff]">
                      #{log.event_id}
                    </td>
                    <td className="px-4 py-3 font-['JetBrains_Mono'] text-[11px] text-[#f1f3fc]">
                      {log.source_ip || "n/a"}
                    </td>
                    <td className="px-4 py-3 font-['JetBrains_Mono'] text-[11px] text-[#f1f3fc]">
                      {log.dest_ip || "n/a"}
                    </td>
                    <td className="px-4 py-3 font-['JetBrains_Mono'] text-[11px]">
                      <span className="rounded-sm bg-[#151a21] px-1.5 py-0.5">{log.protocol}</span>
                    </td>
                    <td className="px-4 py-3 font-['JetBrains_Mono'] text-[11px]">
                      <span className={actionClassName(log.action)}>{log.action}</span>
                    </td>
                    <td className="px-4 py-3 text-right font-['JetBrains_Mono'] text-[11px]">
                      <span className={`${severityClassName(log.severity)} pl-2 uppercase`}>
                        {log.severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between border-t border-[#44484f]/10 bg-[#1b2028] px-4 py-2">
            <span className="font-['JetBrains_Mono'] text-[9px] uppercase text-slate-500">
              {footerText}
            </span>
            <span className="font-['JetBrains_Mono'] text-[10px] uppercase tracking-widest text-[#8ff5ff]">
              {refreshing ? "Refreshing..." : "Auto-refresh 15s"}
            </span>
          </div>
        </section>

        <aside className="relative flex w-96 flex-col overflow-hidden rounded-sm border border-[#44484f]/20 bg-[#0f141a] shadow-2xl">
          <div className="flex items-center justify-between border-b border-[#44484f]/10 bg-[#1b2028] p-4">
            <h3 className="font-headline text-xs font-bold uppercase tracking-widest text-[#8ff5ff]">
              Log Detail: #{selectedLog?.event_id || "N/A"}
            </h3>
            <span className="material-symbols-outlined text-slate-500">list_alt</span>
          </div>

          <div className="custom-scrollbar flex-1 overflow-y-auto p-6 space-y-6">
            {selectedLog ? (
              <>
                <div className={`border p-4 ${detailBadgeClassName(selectedLog.severity)}`}>
                  <div className="flex items-center justify-between">
                    <span className="font-['JetBrains_Mono'] text-[10px] font-bold uppercase tracking-widest">
                      {selectedLog.action} Event
                    </span>
                    <span className="material-symbols-outlined text-lg">
                      {selectedLog.severity === "critical" ? "warning" : "info"}
                    </span>
                  </div>
                  <p className="mt-2 font-['JetBrains_Mono'] text-[10px] uppercase leading-relaxed text-[#f1f3fc]/80">
                    {selectedLog.message}
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <DetailField label="Logger" value={selectedLog.logger} />
                  <DetailField label="Source File" value={selectedLog.source_file} />
                  <DetailField label="Request Method" value={selectedLog.request_method || "n/a"} />
                  <DetailField label="Status Code" value={selectedLog.status_code ?? "n/a"} />
                  <DetailField label="Protocol" value={selectedLog.protocol} />
                  <DetailField label="Duration" value={selectedLog.duration_ms ? `${selectedLog.duration_ms}ms` : "n/a"} />
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="font-['JetBrains_Mono'] text-[9px] uppercase tracking-widest text-slate-500">
                      Raw Metadata [JSON]
                    </label>
                    <button
                      type="button"
                      onClick={() => navigator.clipboard.writeText(JSON.stringify(selectedLog, null, 2))}
                      className="font-['JetBrains_Mono'] text-[9px] uppercase text-[#8ff5ff] hover:underline"
                    >
                      Copy JSON
                    </button>
                  </div>
                  <div className="custom-scrollbar overflow-x-auto rounded-sm bg-black p-3 font-['JetBrains_Mono'] text-[10px] leading-tight text-[#8ff5ff]/80">
                    <pre>{JSON.stringify(selectedLog, null, 2)}</pre>
                  </div>
                </div>
              </>
            ) : (
              <div className="font-['JetBrains_Mono'] text-[11px] text-[#a8abb3]">
                Select a log entry to inspect details.
              </div>
            )}
          </div>

          <div className="absolute bottom-0 left-0 h-1 w-full bg-[#8ff5ff]/20 shadow-[0_0_15px_rgba(143,245,255,0.4)]" />
        </aside>
      </div>
    </div>
  );
}

function FilterButton({ severity, active, onClick }) {
  const styles = {
    all: "bg-slate-800 text-slate-300 border-slate-700",
    critical: "bg-[#ff716c]/10 text-[#ff716c] border-[#ff716c]/20",
    high: "bg-[#ffa8a3]/10 text-[#ffa8a3] border-[#ffa8a3]/20",
    medium: "bg-[#af88ff]/10 text-[#af88ff] border-[#af88ff]/20",
    low: "bg-[#8ff5ff]/10 text-[#8ff5ff] border-[#8ff5ff]/20",
  };

  return (
    <button
      type="button"
      onClick={onClick}
      className={`border px-3 py-1 font-['JetBrains_Mono'] text-[9px] uppercase transition-all hover:brightness-110 ${styles[severity]} ${active ? "ring-1 ring-white/10" : ""}`}
    >
      {severity}
    </button>
  );
}

function DetailField({ label, value }) {
  return (
    <div className="space-y-1">
      <label className="font-['JetBrains_Mono'] text-[9px] uppercase tracking-tighter text-slate-500">
        {label}
      </label>
      <p className="font-['JetBrains_Mono'] text-[11px] text-[#f1f3fc] break-all">
        {String(value)}
      </p>
    </div>
  );
}

function formatTimestamp(value) {
  if (!value) return "n/a";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toISOString();
}

function severityClassName(severity) {
  if (severity === "critical") return "severity-critical";
  if (severity === "high") return "severity-high";
  if (severity === "medium") return "severity-medium";
  return "severity-low";
}

function detailBadgeClassName(severity) {
  if (severity === "critical") return "border-[#ff716c]/20 bg-[#9f0519]/10 text-[#ff716c]";
  if (severity === "high") return "border-[#ffa8a3]/20 bg-[#ffa8a3]/10 text-[#ffa8a3]";
  if (severity === "medium") return "border-[#af88ff]/20 bg-[#af88ff]/10 text-[#af88ff]";
  return "border-[#8ff5ff]/20 bg-[#8ff5ff]/10 text-[#8ff5ff]";
}

function actionClassName(action) {
  if (action === "BLOCKED" || action === "FAILED") return "font-bold text-[#ff716c]";
  if (action === "FLAGGED") return "font-bold text-[#af88ff]";
  return "font-bold text-[#8ff5ff]";
}

function normalizeSeverityFilter(value) {
  return value && value !== "all" ? value : undefined;
}
