import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Power,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  UploadCloud,
  XCircle,
} from "lucide-react";
import {
  activateAresKillSwitch,
  approveAresXVerdict,
  deactivateAresKillSwitch,
  getAresKillSwitch,
  getAresXIngestStats,
  getAresStatus,
  getRedQueenStats,
  getRedQueenStatus,
  ingestAresXEvent,
  listAresXIngestSources,
  listAresExecutions,
  listAresXAuditRecords,
  listRedQueenVerdicts,
  rejectAresXVerdict,
  rollbackAresExecution,
  verifyAresXAudit,
} from "@/api/vaelqorixApi";

const REFRESH_MS = 15000;

export default function AIPage() {
  const [loading, setLoading] = useState(true);
  const [actionBusy, setActionBusy] = useState("");
  const [error, setError] = useState("");
  const [redQueenStatus, setRedQueenStatus] = useState(null);
  const [aresStatus, setAresStatus] = useState(null);
  const [killSwitch, setKillSwitch] = useState(null);
  const [stats, setStats] = useState(null);
  const [ingestStats, setIngestStats] = useState(null);
  const [ingestSources, setIngestSources] = useState([]);
  const [verdicts, setVerdicts] = useState([]);
  const [executions, setExecutions] = useState([]);
  const [audit, setAudit] = useState([]);
  const [auditVerify, setAuditVerify] = useState(null);
  const [selectedVerdictId, setSelectedVerdictId] = useState("");

  const load = useCallback(async () => {
    setError("");
    try {
      const [
        redQueenResult,
        aresResult,
        killSwitchResult,
        statsResult,
        ingestStatsResult,
        ingestSourcesResult,
        verdictsResult,
        executionsResult,
        auditResult,
        verifyResult,
      ] = await Promise.allSettled([
        getRedQueenStatus(),
        getAresStatus(),
        getAresKillSwitch(),
        getRedQueenStats(),
        getAresXIngestStats(),
        listAresXIngestSources(),
        listRedQueenVerdicts({ limit: 20 }),
        listAresExecutions({ limit: 20 }),
        listAresXAuditRecords({ limit: 20 }),
        verifyAresXAudit(),
      ]);

      setRedQueenStatus(valueOrNull(redQueenResult));
      setAresStatus(valueOrNull(aresResult));
      setKillSwitch(valueOrNull(killSwitchResult)?.kill_switch || null);
      setStats(valueOrNull(statsResult));
      setIngestStats(valueOrNull(ingestStatsResult));
      setIngestSources(valueOrNull(ingestSourcesResult)?.sources || []);
      setVerdicts(valueOrNull(verdictsResult)?.items || []);
      setExecutions(valueOrNull(executionsResult)?.items || []);
      setAudit(valueOrNull(auditResult)?.items || []);
      setAuditVerify(valueOrNull(verifyResult));

      const rejected = [
        redQueenResult,
        aresResult,
        killSwitchResult,
        statsResult,
        ingestStatsResult,
        ingestSourcesResult,
        verdictsResult,
        executionsResult,
        auditResult,
        verifyResult,
      ].find((result) => result.status === "rejected");
      if (rejected) {
        setError(rejected.reason?.message || "No se pudo cargar una parte del panel.");
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const intervalId = setInterval(load, REFRESH_MS);
    return () => clearInterval(intervalId);
  }, [load]);

  const selectedVerdict = useMemo(
    () => verdicts.find((item) => item.verdict_id === selectedVerdictId) || verdicts[0],
    [selectedVerdictId, verdicts]
  );
  const selectedExecutions = useMemo(
    () =>
      selectedVerdict
        ? executions.filter((item) => item.verdict_id === selectedVerdict.verdict_id)
        : [],
    [executions, selectedVerdict]
  );

  const handleKillSwitch = async () => {
    setActionBusy("kill-switch");
    setError("");
    try {
      if (killSwitch?.active) {
        await deactivateAresKillSwitch({
          reason: "Operator resumed autonomous response from command center",
          actor: "command-center",
        });
      } else {
        await activateAresKillSwitch({
          reason: "Operator paused autonomous response from command center",
          actor: "command-center",
        });
      }
      await load();
    } catch (err) {
      setError(err?.message || "No se pudo actualizar el kill switch.");
    } finally {
      setActionBusy("");
    }
  };

  const mutateVerdict = async (verdictId, action) => {
    setActionBusy(`${action}-${verdictId}`);
    setError("");
    try {
      if (action === "approve") {
        await approveAresXVerdict(verdictId);
      } else {
        await rejectAresXVerdict(verdictId);
      }
      await load();
    } catch (err) {
      setError(err?.message || "No se pudo actualizar el verdict.");
    } finally {
      setActionBusy("");
    }
  };

  const rollbackExecution = async (executionId) => {
    setActionBusy(`rollback-${executionId}`);
    setError("");
    try {
      await rollbackAresExecution(executionId, {
        reason: "Operator rollback from command center",
        actor: "command-center",
      });
      await load();
    } catch (err) {
      setError(err?.message || "No se pudo ejecutar rollback.");
    } finally {
      setActionBusy("");
    }
  };

  const ingestControlEvent = async () => {
    setActionBusy("ingest-event");
    setError("");
    try {
      await ingestAresXEvent({
        source: "qradar",
        payload: {
          id: `frontend-${Date.now()}`,
          description: "Credential access T1110 from command center",
          magnitude: 8,
          username: "operator.demo@corp.local",
          source_ip: "10.10.4.22",
        },
      });
      await load();
    } catch (err) {
      setError(err?.message || "No se pudo ingerir el evento.");
    } finally {
      setActionBusy("");
    }
  };

  return (
    <div className="min-h-full bg-[#0a0e14] text-[#f1f3fc]">
      <section className="mb-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="font-label text-[10px] uppercase tracking-[0.22em] text-[#8ff5ff]">
            AresX Command Center
          </p>
          <h1 className="mt-2 font-headline text-3xl font-bold tracking-normal text-white">
            RedQueen / ARES
          </h1>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={load}
            className="inline-flex h-10 items-center gap-2 border border-white/10 bg-[#151a21] px-4 font-label text-[10px] uppercase tracking-widest text-slate-200 hover:border-[#8ff5ff]/60"
            title="Refresh"
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
          <button
            type="button"
            onClick={handleKillSwitch}
            disabled={actionBusy === "kill-switch"}
            className={`inline-flex h-10 items-center gap-2 border px-4 font-label text-[10px] uppercase tracking-widest disabled:opacity-50 ${
              killSwitch?.active
                ? "border-[#8ff5ff]/50 bg-[#8ff5ff]/10 text-[#8ff5ff]"
                : "border-[#ff716c]/50 bg-[#ff716c]/10 text-[#ff716c]"
            }`}
            title={killSwitch?.active ? "Deactivate kill switch" : "Activate kill switch"}
          >
            <Power className="h-4 w-4" />
            {killSwitch?.active ? "Resume ARES" : "Pause ARES"}
          </button>
        </div>
      </section>

      {error && (
        <div className="mb-6 border-l-2 border-amber-400 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">
          {error}
        </div>
      )}

      <section className="mb-6 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricPanel
          label="RedQueen"
          value={loading ? "..." : redQueenStatus?.phase || "N/A"}
          detail={redQueenStatus?.role || "brain"}
          tone="primary"
          icon={<ShieldCheck className="h-5 w-5" />}
        />
        <MetricPanel
          label="ARES"
          value={loading ? "..." : aresStatus?.phase || "N/A"}
          detail={killSwitch?.active ? "kill switch active" : "execution enabled"}
          tone={killSwitch?.active ? "error" : "primary"}
          icon={<ShieldAlert className="h-5 w-5" />}
        />
        <MetricPanel
          label="Verdicts"
          value={loading ? "..." : String(stats?.total_verdicts ?? verdicts.length)}
          detail={`${stats?.human_required ?? 0} human review`}
          tone="neutral"
          icon={<CheckCircle2 className="h-5 w-5" />}
        />
        <MetricPanel
          label="Ingestion"
          value={loading ? "..." : String(ingestStats?.total ?? 0)}
          detail={`${ingestSources.length} sources`}
          tone="neutral"
          icon={<UploadCloud className="h-5 w-5" />}
        />
        <MetricPanel
          label="Audit Chain"
          value={loading ? "..." : auditVerify?.valid ? "VALID" : "CHECK"}
          detail={`${auditVerify?.records_checked ?? audit.length} records`}
          tone={auditVerify?.valid ? "primary" : "error"}
          icon={<AlertTriangle className="h-5 w-5" />}
        />
      </section>

      <section className="grid grid-cols-12 gap-6">
        <div className="col-span-12 bg-[#0f141a]">
          <PanelHeader title="Ingestion Pipeline" right={ingestStats?.window || "all"} />
          <div className="grid grid-cols-1 gap-4 p-5 lg:grid-cols-3">
            <div className="border border-white/5 bg-[#151a21] p-4">
              <p className="font-label text-[10px] uppercase tracking-widest text-slate-500">
                Total Events
              </p>
              <p className="mt-2 font-headline text-2xl font-bold text-white">
                {loading ? "..." : ingestStats?.total ?? 0}
              </p>
            </div>
            <div className="border border-white/5 bg-[#151a21] p-4">
              <p className="font-label text-[10px] uppercase tracking-widest text-slate-500">
                Sources
              </p>
              <div className="mt-3 flex flex-wrap gap-2">
                {(ingestSources.length ? ingestSources : ["qradar", "wazuh", "edr"]).slice(0, 8).map((source) => (
                  <span key={source} className="bg-[#0f141a] px-2 py-1 font-label text-[10px] uppercase text-[#8ff5ff]">
                    {source}
                  </span>
                ))}
              </div>
            </div>
            <div className="flex items-center justify-between gap-4 border border-white/5 bg-[#151a21] p-4">
              <div>
                <p className="font-label text-[10px] uppercase tracking-widest text-slate-500">
                  QRadar Control Event
                </p>
                <p className="mt-2 text-xs text-slate-400">
                  T1110 / magnitude 8
                </p>
              </div>
              <button
                type="button"
                onClick={ingestControlEvent}
                disabled={actionBusy === "ingest-event"}
                title="Ingest QRadar control event"
                className="inline-flex h-10 items-center gap-2 border border-[#8ff5ff]/40 bg-[#8ff5ff]/10 px-4 font-label text-[10px] uppercase tracking-widest text-[#8ff5ff] hover:border-[#8ff5ff] disabled:opacity-40"
              >
                <UploadCloud className="h-4 w-4" />
                Ingest
              </button>
            </div>
          </div>
        </div>

        <div className="col-span-12 bg-[#0f141a] xl:col-span-7">
          <PanelHeader title="RedQueen Verdicts" right={`${verdicts.length} loaded`} />
          <div className="overflow-x-auto">
            <table className="w-full min-w-[860px] text-left">
              <thead>
                <tr className="border-b border-white/5 font-label text-[10px] uppercase tracking-widest text-slate-500">
                  <th className="px-5 py-4 font-normal">Target</th>
                  <th className="px-5 py-4 font-normal">Risk</th>
                  <th className="px-5 py-4 font-normal">Confidence</th>
                  <th className="px-5 py-4 font-normal">Status</th>
                  <th className="px-5 py-4 font-normal">Action</th>
                  <th className="px-5 py-4 font-normal">Controls</th>
                </tr>
              </thead>
              <tbody className="font-label text-[11px]">
                {verdicts.length === 0 ? (
                  <tr>
                    <td className="px-5 py-8 text-slate-500" colSpan={6}>
                      {loading ? "Loading verdicts..." : "No verdicts available"}
                    </td>
                  </tr>
                ) : (
                  verdicts.map((verdict) => (
                    <tr
                      key={verdict.verdict_id}
                      className={`cursor-pointer border-b border-white/5 hover:bg-[#151a21] ${
                        selectedVerdict?.verdict_id === verdict.verdict_id ? "bg-[#151a21]" : ""
                      }`}
                      onClick={() => setSelectedVerdictId(verdict.verdict_id)}
                    >
                      <td className="px-5 py-4">
                        <div className="max-w-[220px] truncate font-medium text-white">
                          {verdict.target || "unknown"}
                        </div>
                        <div className="mt-1 max-w-[220px] truncate text-[9px] text-slate-500">
                          {verdict.verdict_id}
                        </div>
                      </td>
                      <td className="px-5 py-4">
                        <RiskBar value={verdict.risk_score} />
                      </td>
                      <td className="px-5 py-4 text-slate-300">
                        {formatPercent(verdict.confidence_score || verdict.confidence)}
                      </td>
                      <td className="px-5 py-4">
                        <StatusBadge value={verdict.status} />
                      </td>
                      <td className="px-5 py-4 text-slate-300">
                        {verdict.primary_action || verdict.action_type || "observe"}
                      </td>
                      <td className="px-5 py-4">
                        <div className="flex items-center gap-2">
                          <IconButton
                            title="Approve"
                            disabled={actionBusy === `approve-${verdict.verdict_id}`}
                            onClick={(event) => {
                              event.stopPropagation();
                              mutateVerdict(verdict.verdict_id, "approve");
                            }}
                          >
                            <CheckCircle2 className="h-4 w-4" />
                          </IconButton>
                          <IconButton
                            title="Reject"
                            disabled={actionBusy === `reject-${verdict.verdict_id}`}
                            onClick={(event) => {
                              event.stopPropagation();
                              mutateVerdict(verdict.verdict_id, "reject");
                            }}
                          >
                            <XCircle className="h-4 w-4" />
                          </IconButton>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="col-span-12 space-y-6 xl:col-span-5">
          <div className="bg-[#0f141a]">
            <PanelHeader
              title="Selected Verdict"
              right={selectedVerdict?.status || "none"}
            />
            <div className="space-y-4 p-5">
              {selectedVerdict ? (
                <>
                  <KeyValue label="Target" value={selectedVerdict.target} />
                  <KeyValue label="Severity" value={selectedVerdict.severity} />
                  <KeyValue label="Primary Action" value={selectedVerdict.primary_action} />
                  <KeyValue label="Human Approval" value={selectedVerdict.requires_human_approval ? "required" : "not required"} />
                  <div>
                    <p className="mb-2 font-label text-[10px] uppercase tracking-widest text-slate-500">
                      XAI Factors
                    </p>
                    <div className="space-y-2">
                      {(selectedVerdict.xai_explanation?.top_factors || []).slice(0, 4).map((factor) => (
                        <div key={`${factor.feature}-${factor.label}`} className="flex items-center justify-between gap-3 border border-white/5 bg-[#151a21] px-3 py-2">
                          <span className="truncate text-xs text-slate-300">
                            {factor.label || factor.feature}
                          </span>
                          <span className="font-label text-[10px] text-[#8ff5ff]">
                            {formatScore(factor.value)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              ) : (
                <p className="text-sm text-slate-500">No verdict selected</p>
              )}
            </div>
          </div>

          <div className="bg-[#0f141a]">
            <PanelHeader title="ARES Executions" right={`${selectedExecutions.length} linked`} />
            <div className="max-h-[310px] overflow-y-auto p-5">
              {selectedExecutions.length === 0 ? (
                <p className="text-sm text-slate-500">No linked executions</p>
              ) : (
                <div className="space-y-3">
                  {selectedExecutions.map((execution) => (
                    <div key={execution.id} className="border border-white/5 bg-[#151a21] p-4">
                      <div className="mb-3 flex items-start justify-between gap-3">
                        <div>
                          <p className="font-label text-[11px] uppercase text-white">
                            {execution.action_type || "action"}
                          </p>
                          <p className="mt-1 text-xs text-slate-500">{execution.target_entity}</p>
                        </div>
                        <StatusBadge value={execution.status} />
                      </div>
                      <div className="flex items-center justify-between gap-3">
                        <span className="font-label text-[10px] uppercase text-slate-500">
                          reward {execution.rl_reward}
                        </span>
                        <IconButton
                          title="Rollback"
                          disabled={
                            execution.status === "rolled_back" ||
                            actionBusy === `rollback-${execution.id}`
                          }
                          onClick={() => rollbackExecution(execution.id)}
                        >
                          <RotateCcw className="h-4 w-4" />
                        </IconButton>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="col-span-12 bg-[#0f141a]">
          <PanelHeader title="Audit Trail" right={auditVerify?.valid ? "chain valid" : "verify pending"} />
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left">
              <thead>
                <tr className="border-b border-white/5 font-label text-[10px] uppercase tracking-widest text-slate-500">
                  <th className="px-5 py-4 font-normal">Sequence</th>
                  <th className="px-5 py-4 font-normal">Event</th>
                  <th className="px-5 py-4 font-normal">Actor</th>
                  <th className="px-5 py-4 font-normal">Verdict</th>
                  <th className="px-5 py-4 font-normal">Hash</th>
                </tr>
              </thead>
              <tbody className="font-label text-[11px]">
                {audit.length === 0 ? (
                  <tr>
                    <td className="px-5 py-8 text-slate-500" colSpan={5}>
                      {loading ? "Loading audit..." : "No audit records available"}
                    </td>
                  </tr>
                ) : (
                  audit.map((record) => (
                    <tr key={record.record_id} className="border-b border-white/5">
                      <td className="px-5 py-4 text-slate-300">{record.sequence_number}</td>
                      <td className="px-5 py-4 text-white">{record.event_type}</td>
                      <td className="px-5 py-4 text-slate-300">{record.actor}</td>
                      <td className="px-5 py-4 text-slate-500">{record.verdict_id}</td>
                      <td className="px-5 py-4">
                        <span className="block max-w-[220px] truncate text-slate-500">
                          {record.chain_hash}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  );
}

function valueOrNull(result) {
  return result.status === "fulfilled" ? result.value : null;
}

function MetricPanel({ label, value, detail, tone, icon }) {
  const toneClass = tone === "error" ? "text-[#ff716c] border-[#ff716c]" : tone === "primary" ? "text-[#8ff5ff] border-[#8ff5ff]" : "text-[#f1f3fc] border-slate-600";
  return (
    <div className={`border-l-2 bg-[#0f141a] p-5 ${toneClass}`}>
      <div className="mb-4 flex items-center justify-between gap-3">
        <span className="font-label text-[10px] uppercase tracking-widest text-slate-500">
          {label}
        </span>
        {icon}
      </div>
      <p className="font-headline text-2xl font-bold text-white">{value}</p>
      <p className="mt-2 font-label text-[10px] uppercase tracking-widest text-slate-500">
        {detail}
      </p>
    </div>
  );
}

function PanelHeader({ title, right }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-white/5 px-5 py-4">
      <h2 className="font-label text-xs uppercase tracking-[0.2em] text-[#8ff5ff]">
        {title}
      </h2>
      <span className="font-label text-[10px] uppercase tracking-widest text-slate-500">
        {right}
      </span>
    </div>
  );
}

function StatusBadge({ value }) {
  const normalized = String(value || "unknown").toLowerCase();
  const className =
    normalized === "approved" || normalized === "success" || normalized === "executed"
      ? "bg-[#8ff5ff]/10 text-[#8ff5ff]"
      : normalized === "rejected" || normalized === "failed" || normalized === "blocked"
        ? "bg-[#ff716c]/10 text-[#ff716c]"
        : normalized === "rolled_back"
          ? "bg-amber-400/10 text-amber-300"
          : "bg-slate-500/10 text-slate-300";
  return (
    <span className={`inline-flex px-2 py-1 font-label text-[10px] uppercase ${className}`}>
      {normalized}
    </span>
  );
}

function RiskBar({ value }) {
  const parsed = Math.max(0, Math.min(Number(value) || 0, 100));
  const tone = parsed >= 80 ? "bg-[#ff716c]" : parsed >= 60 ? "bg-amber-300" : "bg-[#8ff5ff]";
  return (
    <div className="w-28">
      <div className="mb-1 flex justify-between text-[10px] text-slate-500">
        <span>{Math.round(parsed)}</span>
        <span>/100</span>
      </div>
      <div className="h-1.5 bg-[#1b2028]">
        <div className={`h-full ${tone}`} style={{ width: `${parsed}%` }} />
      </div>
    </div>
  );
}

function IconButton({ title, disabled, onClick, children }) {
  return (
    <button
      type="button"
      title={title}
      aria-label={title}
      disabled={disabled}
      onClick={onClick}
      className="inline-flex h-8 w-8 items-center justify-center border border-white/10 bg-[#0f141a] text-slate-300 hover:border-[#8ff5ff]/60 hover:text-[#8ff5ff] disabled:cursor-not-allowed disabled:opacity-40"
    >
      {children}
    </button>
  );
}

function KeyValue({ label, value }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-white/5 pb-3">
      <span className="font-label text-[10px] uppercase tracking-widest text-slate-500">
        {label}
      </span>
      <span className="max-w-[260px] truncate text-sm text-slate-200">{value || "N/A"}</span>
    </div>
  );
}

function formatPercent(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return "N/A";
  return `${Math.round(parsed * 100)}%`;
}

function formatScore(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return "N/A";
  return parsed <= 1 ? parsed.toFixed(2) : Math.round(parsed);
}
