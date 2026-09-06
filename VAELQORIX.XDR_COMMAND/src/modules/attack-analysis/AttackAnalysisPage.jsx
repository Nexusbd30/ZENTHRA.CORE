import { useCallback, useEffect, useMemo, useState } from "react";
import {
  BrainCircuit,
  CheckCircle2,
  FileCheck2,
  GitBranch,
  Radar,
  RefreshCw,
  ShieldAlert,
  XCircle,
} from "lucide-react";

import {
  executeAresVerdict,
  getAttackAnalysisEntity,
  getAttackAnalysisStatus,
  issueAttackAnalysisVerdict,
  listAttackAnalyses,
  listCtfLabScenarios,
  replayCtfLabScenario,
  runAresHunterTrace,
} from "@/api/vaelqorixApi";

const REFRESH_MS = 20000;

export default function AttackAnalysisPage() {
  const [loading, setLoading] = useState(true);
  const [actionBusy, setActionBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [status, setStatus] = useState(null);
  const [summary, setSummary] = useState(null);
  const [ctfScenarios, setCtfScenarios] = useState([]);
  const [selectedScenarioId, setSelectedScenarioId] = useState("identity_credential_foothold");
  const [ctfRun, setCtfRun] = useState(null);
  const [selectedEntityId, setSelectedEntityId] = useState("");
  const [analysis, setAnalysis] = useState(null);
  const [verdictResult, setVerdictResult] = useState(null);
  const [aresDryRun, setAresDryRun] = useState(null);
  const [hunterTrace, setHunterTrace] = useState(null);

  const load = useCallback(async () => {
    setError("");
    try {
      const [statusResult, summaryResult, scenariosResult] = await Promise.allSettled([
        getAttackAnalysisStatus(),
        listAttackAnalyses({ limit: 100 }),
        listCtfLabScenarios(),
      ]);
      setStatus(valueOrNull(statusResult));
      const nextSummary = valueOrNull(summaryResult);
      setSummary(nextSummary);
      const nextScenarios = valueOrNull(scenariosResult)?.items || [];
      setCtfScenarios(nextScenarios);
      if (!selectedScenarioId && nextScenarios[0]?.id) setSelectedScenarioId(nextScenarios[0].id);

      const firstEntity = nextSummary?.items?.[0]?.entity_id || "";
      const entityToLoad = selectedEntityId || firstEntity;
      if (!selectedEntityId && firstEntity) setSelectedEntityId(firstEntity);
      if (entityToLoad) setAnalysis(await getAttackAnalysisEntity(entityToLoad));

      const failed = [statusResult, summaryResult, scenariosResult].find((result) => result.status === "rejected");
      if (failed) setError(failed.reason.message || "No se pudo cargar analisis de ataque.");
    } catch (err) {
      setError(err.message || "No se pudo cargar analisis de ataque.");
    } finally {
      setLoading(false);
    }
  }, [selectedEntityId]);

  useEffect(() => {
    load();
    const intervalId = setInterval(load, REFRESH_MS);
    return () => clearInterval(intervalId);
  }, [load]);

  const selectedSummary = useMemo(
    () => (summary?.items || []).find((item) => item.entity_id === selectedEntityId) || null,
    [selectedEntityId, summary]
  );

  const handleSelect = async (entityId) => {
    setSelectedEntityId(entityId);
    setActionBusy(`select-${entityId}`);
    setError("");
    try {
      setAnalysis(await getAttackAnalysisEntity(entityId));
      setVerdictResult(null);
      setAresDryRun(null);
      setHunterTrace(null);
    } catch (err) {
      setError(err.message || "No se pudo abrir la entidad.");
    } finally {
      setActionBusy("");
    }
  };

  const handleVerdict = async () => {
    if (!selectedEntityId) return;
    setActionBusy("verdict");
    setError("");
    try {
      const result = await issueAttackAnalysisVerdict(selectedEntityId, {
        executionControls: {
          dry_run: true,
          source: "attack-analysis-ui",
          change_ticket: "ATTACK-ANALYSIS-DRY-RUN",
        },
      });
      setVerdictResult(result);
      setAresDryRun(null);
      setNotice(`Verdict generado: ${result.verdict?.action_type || "observe"}.`);
    } catch (err) {
      setError(err.message || "No se pudo generar el verdict.");
    } finally {
      setActionBusy("");
    }
  };

  const handleAresDryRun = async () => {
    const verdict = verdictResult?.verdict;
    if (!verdict) return;
    setActionBusy("ares-dry-run");
    setError("");
    try {
      const result = await executeAresVerdict(verdict, {
        humanApproved: true,
        approvalEvidence: null,
      });
      setAresDryRun(result);
      setNotice(`ARES dry-run: ${result.status || "completed"}.`);
    } catch (err) {
      setError(err.message || "No se pudo ejecutar ARES dry-run.");
    } finally {
      setActionBusy("");
    }
  };

  const handleHunterTrace = async () => {
    if (!selectedEntityId) return;
    setActionBusy("hunter-trace");
    setError("");
    try {
      const result = await runAresHunterTrace({
        target: selectedEntityId,
        executionControls: {
          ctf_mode: true,
          source: "attack-analysis-ui",
          change_ticket: "HUNTER-TRACE-DRY-RUN",
        },
      });
      setHunterTrace(result);
      setNotice(`Hunter trace: ${result.presence_state || "unknown"}.`);
    } catch (err) {
      setError(err.message || "No se pudo ejecutar hunter trace.");
    } finally {
      setActionBusy("");
    }
  };

  const handleCtfReplay = async () => {
    if (!selectedScenarioId) return;
    setActionBusy("ctf-replay");
    setError("");
    try {
      const result = await replayCtfLabScenario(selectedScenarioId, {
        runLabel: `ui-${Date.now()}`,
      });
      setCtfRun(result);
      setSelectedEntityId(result.target);
      setAnalysis(result.analysis);
      setHunterTrace(result.hunter_trace);
      setNotice(`CTF ${result.scenario_id}: ${result.status}.`);
      setSummary(await listAttackAnalyses({ limit: 100 }));
    } catch (err) {
      setError(err.message || "No se pudo lanzar el escenario CTF.");
    } finally {
      setActionBusy("");
    }
  };

  const items = summary?.items || [];
  const timeline = analysis?.timeline || [];
  const score = Number(analysis?.attack_reality_score || selectedSummary?.attack_reality_score || 0);
  const classification = analysis?.classification || selectedSummary?.classification || "unknown";

  return (
    <div className="min-h-full text-[#eef3ff]">
      <section className="mb-6 flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
        <div>
          <p className="font-label text-[10px] uppercase text-[#8c909f]">
            RedQueen / Attack reality
          </p>
          <h2 className="mt-1 font-headline text-3xl font-bold text-white">
            Analisis del desarrollo del ataque
          </h2>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-[#aeb7ca]">
            Reconstruccion temporal, evidencia causal y clasificacion de si el suceso parece
            ataque real, actividad sospechosa o falso positivo probable.
          </p>
        </div>
        <button
          type="button"
          onClick={load}
          className="inline-flex h-10 items-center justify-center gap-2 border border-white/10 bg-[#121a2f] px-4 text-sm text-[#dbe7ff] hover:border-[#adc6ff]/50"
          title="Actualizar analisis"
        >
          <RefreshCw size={16} />
          Actualizar
        </button>
      </section>

      {error && (
        <div className="mb-5 border border-[#ffb4ab]/30 bg-[#3a1619] px-4 py-3 text-sm text-[#ffd6d2]">
          {error}
        </div>
      )}
      {notice && (
        <div className="mb-5 border border-[#4ae176]/25 bg-[#10281b] px-4 py-3 text-sm text-[#9ef0b6]">
          {notice}
        </div>
      )}

      <section className="mb-5 grid grid-cols-1 border border-white/10 bg-[#0d1422] md:grid-cols-2 xl:grid-cols-4">
        <MetricTile
          icon={<Radar size={18} />}
          label="Clasificacion"
          value={loading ? "..." : classification}
          detail={`${analysis?.event_count || selectedSummary?.event_count || 0} eventos correlados`}
          tone={classificationTone(classification)}
        />
        <MetricTile
          icon={<BrainCircuit size={18} />}
          label="Reality score"
          value={loading ? "..." : String(Math.round(score))}
          detail={`confianza ${Math.round(Number(analysis?.confidence || 0) * 100)}%`}
          tone={score >= 70 ? "danger" : score >= 45 ? "warning" : "neutral"}
        />
        <MetricTile
          icon={<GitBranch size={18} />}
          label="Fases"
          value={loading ? "..." : String(analysis?.kill_chain_stages?.length || 0)}
          detail={(analysis?.kill_chain_stages || []).slice(0, 2).join(", ") || "sin fases"}
        />
        <MetricTile
          icon={<ShieldAlert size={18} />}
          label="Motor"
          value={status?.status || "enabled"}
          detail={(status?.capabilities || []).slice(0, 1).join(", ") || "attack analysis"}
          tone="success"
        />
      </section>

      <section className="mb-5 border border-white/10 bg-[#10182b]">
        <div className="flex min-h-14 items-center justify-between gap-3 border-b border-white/10 px-5">
          <h3 className="font-label text-xs uppercase text-[#adc6ff]">CTF defensivo / lab</h3>
          <span className="font-label text-[10px] uppercase text-[#8c909f]">
            synthetic dry-run
          </span>
        </div>
        <div className="grid gap-4 p-5 lg:grid-cols-[minmax(0,1fr)_220px]">
          <div className="grid gap-3 md:grid-cols-[260px_minmax(0,1fr)]">
            <select
              value={selectedScenarioId}
              onChange={(event) => setSelectedScenarioId(event.target.value)}
              className="h-10 border border-white/10 bg-[#0b1020] px-3 text-sm text-[#dbe7ff] outline-none"
            >
              {ctfScenarios.map((scenario) => (
                <option key={scenario.id} value={scenario.id}>
                  {scenario.name}
                </option>
              ))}
            </select>
            <div className="border border-white/10 bg-[#0b1020] px-4 py-3 text-sm leading-6 text-[#aeb7ca]">
              {ctfScenarios.find((scenario) => scenario.id === selectedScenarioId)?.objective ||
                "Lanza telemetria sintetica para entrenar deteccion, respuesta y evidencia."}
            </div>
          </div>
          <button
            type="button"
            onClick={handleCtfReplay}
            disabled={!selectedScenarioId || actionBusy === "ctf-replay"}
            className="inline-flex h-10 items-center justify-center gap-2 bg-[#78ffbd] px-4 text-sm font-bold text-[#07130c] disabled:opacity-50"
          >
            <Radar size={16} />
            Lanzar replay
          </button>
        </div>
        {ctfRun && (
          <div className="grid gap-3 border-t border-white/10 p-5 md:grid-cols-4">
            <ResultBox title="Resultado" body={ctfRun.status} ok={ctfRun.status === "passed"} />
            <ResultBox title="Clasificacion" body={ctfRun.actual_classification} ok={ctfRun.scorecard?.detection_passed} />
            <ResultBox title="Eventos" body={String(ctfRun.synthetic_events_inserted)} ok />
            <ResultBox title="Hunter trace" body={ctfRun.hunter_presence_state} ok={ctfRun.hunter_trace?.expulsion_readiness === "operator_gated"} />
          </div>
        )}
      </section>

      <section className="grid grid-cols-12 gap-5">
        <Panel className="col-span-12 xl:col-span-4" title="Entidades" right={`${items.length} grupos`}>
          <div className="space-y-3">
            {items.length === 0 ? (
              <EmptyState text={loading ? "Cargando entidades..." : "No hay eventos para analizar."} />
            ) : (
              items.map((item) => (
                <button
                  key={item.entity_id}
                  type="button"
                  onClick={() => handleSelect(item.entity_id)}
                  className={`block w-full border p-4 text-left transition-colors ${
                    item.entity_id === selectedEntityId
                      ? "border-[#adc6ff]/60 bg-[#151f32]"
                      : "border-white/10 bg-[#0b1020] hover:border-[#adc6ff]/40"
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="truncate text-sm font-semibold text-white">{item.entity_id}</div>
                      <div className="mt-1 font-label text-[10px] uppercase text-[#8c909f]">
                        {item.event_count} eventos / sev {item.severity}
                      </div>
                    </div>
                    <StatusBadge value={item.classification} />
                  </div>
                  <div className="mt-3 h-1.5 bg-[#070b12]">
                    <div
                      className={scoreBarClass(item.attack_reality_score)}
                      style={{ width: `${Math.max(2, Math.min(100, item.attack_reality_score))}%` }}
                    />
                  </div>
                </button>
              ))
            )}
          </div>
        </Panel>

        <Panel className="col-span-12 xl:col-span-8" title="Decision" right={selectedEntityId || "sin seleccion"}>
          <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_260px]">
            <div className="space-y-4">
              <div className="border border-white/10 bg-[#0b1020] p-4">
                <div className="mb-2 font-label text-[10px] uppercase text-[#8c909f]">
                  Evidencia principal
                </div>
                <div className="flex flex-wrap gap-2">
                  {(analysis?.evidence || []).length === 0 ? (
                    <span className="text-sm text-[#8c909f]">Sin evidencia calculada.</span>
                  ) : (
                    analysis.evidence.map((item) => (
                      <SmallTag key={item}>{item}</SmallTag>
                    ))
                  )}
                </div>
              </div>
              <div className="border border-white/10 bg-[#0b1020] p-4">
                <div className="mb-2 font-label text-[10px] uppercase text-[#8c909f]">
                  Senales de falso positivo
                </div>
                {(analysis?.false_positive_signals || []).length === 0 ? (
                  <div className="flex items-center gap-2 text-sm text-[#78ffbd]">
                    <CheckCircle2 size={16} />
                    No hay senales fuertes de falso positivo.
                  </div>
                ) : (
                  <div className="grid gap-2">
                    {analysis.false_positive_signals.map((item) => (
                      <div key={item} className="flex items-center gap-2 text-sm text-[#ffbd7a]">
                        <XCircle size={16} />
                        {item}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
            <div className="space-y-3">
              <ResultBox
                title={classification}
                body={`Accion sugerida: ${analysis?.recommended_action || "observe"}`}
                ok={score < 45}
              />
              <ResultBox
                title={analysis?.requires_human_review ? "Human review" : "High confidence"}
                body={
                  analysis?.requires_human_review
                    ? "Requiere revision antes de ejecucion real."
                    : "Evidencia suficiente para escalar."
                }
                ok={!analysis?.requires_human_review}
              />
              <button
                type="button"
                onClick={handleVerdict}
                disabled={!selectedEntityId || actionBusy === "verdict"}
                className="inline-flex h-10 w-full items-center justify-center gap-2 bg-[#78ffbd] px-4 text-sm font-bold text-[#07130c] disabled:opacity-50"
              >
                <FileCheck2 size={16} />
                Generar verdict
              </button>
              <button
                type="button"
                onClick={handleAresDryRun}
                disabled={!verdictResult?.verdict || actionBusy === "ares-dry-run"}
                className="inline-flex h-10 w-full items-center justify-center gap-2 border border-[#78ffbd]/30 bg-[#10281b] px-4 text-sm text-[#9ef0b6] hover:border-[#78ffbd] disabled:opacity-50"
              >
                <ShieldAlert size={16} />
                ARES dry-run
              </button>
              <button
                type="button"
                onClick={handleHunterTrace}
                disabled={!selectedEntityId || actionBusy === "hunter-trace"}
                className="inline-flex h-10 w-full items-center justify-center gap-2 border border-[#adc6ff]/30 bg-[#0b1020] px-4 text-sm text-[#dbe7ff] hover:border-[#adc6ff] disabled:opacity-50"
              >
                <Radar size={16} />
                ARES hunter trace
              </button>
            </div>
          </div>
        </Panel>

        <Panel className="col-span-12 xl:col-span-7" title="Timeline" right={`${timeline.length} eventos`}>
          <div className="space-y-3">
            {timeline.length === 0 ? (
              <EmptyState text="Selecciona una entidad con eventos." />
            ) : (
              timeline.map((event) => (
                <div
                  key={event.id}
                  className="grid gap-3 border border-white/10 bg-[#0b1020] p-4 md:grid-cols-[160px_minmax(0,1fr)_120px]"
                >
                  <div className="text-xs text-[#8c909f]">{formatTime(event.occurred_at)}</div>
                  <div className="min-w-0">
                    <div className="truncate text-sm font-semibold text-white">{event.event_type}</div>
                    <div className="mt-1 truncate text-xs text-[#aeb7ca]">{event.summary}</div>
                    <div className="mt-2 flex flex-wrap gap-2">
                      <SmallTag>{event.source}</SmallTag>
                      <SmallTag>{event.stage}</SmallTag>
                      {event.mitre_tags.slice(0, 4).map((tag) => (
                        <SmallTag key={tag}>{tag}</SmallTag>
                      ))}
                    </div>
                  </div>
                  <div className="text-right text-sm text-[#dbe7ff]">sev {event.severity}</div>
                </div>
              ))
            )}
          </div>
        </Panel>

        <Panel className="col-span-12 xl:col-span-5" title="Causal chain" right="RedQueen">
          {analysis?.causal_chain ? (
            <pre className="max-h-96 overflow-auto bg-[#070b12] p-3 text-xs text-[#dbe7ff]">
              {JSON.stringify(
                {
                  causal_chain: analysis.causal_chain,
                  attack_anticipation: analysis.attack_anticipation,
                  strategic_anticipation: analysis.strategic_anticipation,
                },
                null,
                2
              )}
            </pre>
          ) : (
            <EmptyState text="Sin cadena causal disponible." />
          )}
        </Panel>
      </section>

      {verdictResult && (
        <div className="mt-5 border border-white/10 bg-[#0d1422] p-4">
          <div className="mb-2 font-label text-[10px] uppercase text-[#8c909f]">
            Verdict generado
          </div>
          <pre className="max-h-80 overflow-auto bg-[#070b12] p-3 text-xs text-[#dbe7ff]">
            {JSON.stringify(verdictResult, null, 2)}
          </pre>
        </div>
      )}

      {aresDryRun && (
        <div className="mt-5 border border-[#78ffbd]/20 bg-[#0d1422] p-4">
          <div className="mb-2 font-label text-[10px] uppercase text-[#8c909f]">
            ARES dry-run / evidencia
          </div>
          <pre className="max-h-80 overflow-auto bg-[#070b12] p-3 text-xs text-[#dbe7ff]">
            {JSON.stringify(aresDryRun, null, 2)}
          </pre>
        </div>
      )}

      {hunterTrace && (
        <div className="mt-5 border border-white/10 bg-[#0d1422] p-4">
          <div className="mb-2 font-label text-[10px] uppercase text-[#8c909f]">
            ARES hunter trace
          </div>
          <pre className="max-h-80 overflow-auto bg-[#070b12] p-3 text-xs text-[#dbe7ff]">
            {JSON.stringify(hunterTrace, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

function valueOrNull(result) {
  return result.status === "fulfilled" ? result.value : null;
}

function classificationTone(value) {
  if (["confirmed_attack", "probable_attack"].includes(String(value))) return "danger";
  if (["suspicious_activity", "needs_human_review"].includes(String(value))) return "warning";
  return "neutral";
}

function scoreBarClass(score) {
  const tone =
    Number(score) >= 70 ? "bg-[#ff8d96]" : Number(score) >= 45 ? "bg-[#ffbd7a]" : "bg-[#78ffbd]";
  return `h-full ${tone}`;
}

function formatTime(value) {
  if (!value) return "N/A";
  return new Intl.DateTimeFormat("es", {
    dateStyle: "short",
    timeStyle: "medium",
  }).format(new Date(value));
}

function MetricTile({ icon, label, value, detail, tone = "neutral" }) {
  const color =
    tone === "success"
      ? "text-[#78ffbd]"
      : tone === "danger"
        ? "text-[#ff8d96]"
        : tone === "warning"
          ? "text-[#ffbd7a]"
          : "text-white";
  return (
    <article className="border-b border-r border-white/10 p-5 last:border-r-0 xl:border-b-0">
      <div className="flex items-center justify-between font-label text-[10px] uppercase text-[#8c909f]">
        <span>{label}</span>
        <span className={color}>{icon}</span>
      </div>
      <strong className={`mt-3 block truncate text-2xl font-bold ${color}`}>{value}</strong>
      <small className="mt-2 block truncate text-xs text-[#8c909f]">{detail}</small>
    </article>
  );
}

function Panel({ className = "", title, right, children }) {
  return (
    <section className={`border border-white/10 bg-[#10182b] ${className}`}>
      <div className="flex min-h-14 items-center justify-between gap-3 border-b border-white/10 px-5">
        <h3 className="font-label text-xs uppercase text-[#adc6ff]">{title}</h3>
        <span className="font-label text-[10px] uppercase text-[#8c909f]">{right}</span>
      </div>
      <div className="p-5">{children}</div>
    </section>
  );
}

function ResultBox({ title, body, ok }) {
  return (
    <div
      className={`border px-3 py-3 ${
        ok ? "border-[#78ffbd]/25 bg-[#10281b]" : "border-[#ffb4ab]/30 bg-[#3a1619]"
      }`}
    >
      <div className="font-label text-[10px] uppercase text-[#8c909f]">{title}</div>
      <div className="mt-1 text-sm text-white">{body}</div>
    </div>
  );
}

function StatusBadge({ value }) {
  const normalized = String(value || "unknown").toLowerCase();
  const ok = ["false_positive_likely"].includes(normalized);
  return (
    <span
      className={`px-2 py-1 font-label text-[10px] uppercase ${
        ok ? "bg-[#78ffbd]/10 text-[#78ffbd]" : "bg-[#ff8d96]/10 text-[#ff8d96]"
      }`}
    >
      {normalized}
    </span>
  );
}

function SmallTag({ children }) {
  return (
    <span className="bg-[#10182b] px-2 py-1 font-label text-[10px] text-[#adc6ff]">
      {children}
    </span>
  );
}

function EmptyState({ text }) {
  return <div className="border border-white/10 bg-[#0b1020] p-4 text-sm text-[#8c909f]">{text}</div>;
}
