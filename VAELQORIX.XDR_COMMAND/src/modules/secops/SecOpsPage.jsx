import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  ClipboardCheck,
  CheckCircle2,
  Database,
  Eye,
  FileCheck2,
  RefreshCw,
  Send,
  ShieldCheck,
  ShieldEllipsis,
  SlidersHorizontal,
  UploadCloud,
  XCircle,
} from "lucide-react";

import {
  createAresApprovalToken,
  exportSecOpsSecurityEvents,
  getAresApprovals,
  getAresEvidenceBundle,
  getSecOpsEnterpriseReadiness,
  getSecOpsIntegrationsReadiness,
  getSecOpsPosture,
  getSecOpsProviderReadiness,
  getSecOpsSecurityEvents,
  getSecOpsStatus,
  listSecOpsProviders,
  listRedQueenVerdicts,
  listTenantPolicies,
  materializeSecOpsSecurityEvents,
  runSecOpsExecutionPreflight,
  runSecOpsSecurityEventLifecycle,
  upsertTenantPolicy,
} from "@/api/vaelqorixApi";

const REFRESH_MS = 20000;

const EMPTY_POLICY = {
  tenant_id: "default",
  name: "default-secops-policy",
  condition_dsl: "domain in ['identity','devsecops','soc']",
  action_allowed: "observe,soar_delegate,require_human_approval",
  provider_assignments: "identity=entra,devsecops=github_actions,soc=generic_webhook",
  max_autonomy_score: 50,
  requires_human: true,
  enabled: true,
};

export default function SecOpsPage() {
  const [loading, setLoading] = useState(true);
  const [actionBusy, setActionBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [status, setStatus] = useState(null);
  const [posture, setPosture] = useState(null);
  const [enterpriseReadiness, setEnterpriseReadiness] = useState(null);
  const [integrationsReadiness, setIntegrationsReadiness] = useState(null);
  const [providers, setProviders] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [securityEvents, setSecurityEvents] = useState(null);
  const [preflight, setPreflight] = useState(null);
  const [providerReadiness, setProviderReadiness] = useState(null);
  const [exportPreview, setExportPreview] = useState(null);
  const [exportDelivery, setExportDelivery] = useState(null);
  const [materializeResult, setMaterializeResult] = useState(null);
  const [lifecycleResult, setLifecycleResult] = useState(null);
  const [verdicts, setVerdicts] = useState([]);
  const [selectedVerdictId, setSelectedVerdictId] = useState("");
  const [approvals, setApprovals] = useState(null);
  const [approvalToken, setApprovalToken] = useState(null);
  const [evidenceBundle, setEvidenceBundle] = useState(null);
  const [approvalDraft, setApprovalDraft] = useState({
    approver: "secops-lead",
    reason: "Reviewed from SecOps command center",
  });
  const [policyDraft, setPolicyDraft] = useState(EMPTY_POLICY);
  const [selectedProvider, setSelectedProvider] = useState("github_actions");
  const [selectedAction, setSelectedAction] = useState("devsecops.block_deployment");

  const load = useCallback(async () => {
    setError("");
    try {
      const results = await Promise.allSettled([
        getSecOpsStatus(),
        getSecOpsPosture(),
        getSecOpsEnterpriseReadiness(),
        getSecOpsIntegrationsReadiness(),
        listSecOpsProviders(),
        listTenantPolicies(),
        getSecOpsSecurityEvents({ limit: 25 }),
        listRedQueenVerdicts({ limit: 20 }),
      ]);

      setStatus(valueOrNull(results[0]));
      setPosture(valueOrNull(results[1]));
      setEnterpriseReadiness(valueOrNull(results[2]));
      setIntegrationsReadiness(valueOrNull(results[3]));
      setProviders(valueOrNull(results[4]) || []);
      setPolicies(valueOrNull(results[5]) || []);
      setSecurityEvents(valueOrNull(results[6]));
      setVerdicts(valueOrNull(results[7]).items || []);

      const failed = results.find((result) => result.status === "rejected");
      if (failed) {
        setError(failed.reason.message || "Parte del command center no respondio.");
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

  useEffect(() => {
    const provider = providers.find((item) => item.provider === selectedProvider) || providers[0];
    if (!provider) return;
    setSelectedProvider(provider.provider);
    if (!provider.actions.includes(selectedAction)) {
      setSelectedAction(provider.actions[0] || "observe");
    }
  }, [providers, selectedAction, selectedProvider]);

  const readinessItems = useMemo(
    () => flattenReadiness(integrationsReadiness, enterpriseReadiness),
    [integrationsReadiness, enterpriseReadiness]
  );

  const providerOptions = providers.length
    ? providers
    : [{ provider: "github_actions", actions: ["devsecops.block_deployment"], commands: [] }];
  const activeProvider =
    providerOptions.find((provider) => provider.provider === selectedProvider) || providerOptions[0];
  const activeActions = activeProvider.actions.length
    ? activeProvider.actions
    : ["devsecops.block_deployment"];
  const selectedVerdict = useMemo(
    () => verdicts.find((item) => item.verdict_id === selectedVerdictId) || verdicts[0] || null,
    [selectedVerdictId, verdicts]
  );
  const lifecycleAllowed = Boolean(preflight.allowed);
  const exportReady = Boolean(exportPreview.ready_to_send || isReadinessKeyReady(readinessItems, "soc"));

  const handlePreflight = async () => {
    setActionBusy("preflight");
    setError("");
    try {
      const result = await runSecOpsExecutionPreflight({
        provider: selectedProvider,
        actionType: selectedAction,
        executionControls: { dry_run: true, source: "secops-command-center" },
      });
      setPreflight(result);
      const readiness = await getSecOpsProviderReadiness(selectedProvider).catch(() => null);
      setProviderReadiness(readiness);
      setNotice(result.allowed ? "Preflight permitido en dry-run." : "Preflight bloqueado.");
    } catch (err) {
      setError(err.message || "No se pudo ejecutar preflight.");
    } finally {
      setActionBusy("");
    }
  };

  const handleMaterialize = async () => {
    setActionBusy("materialize");
    setError("");
    try {
      const result = await materializeSecOpsSecurityEvents({ minCount: 2, limit: 100 });
      setMaterializeResult(result);
      setNotice(`${result.materialized || 0} eventos materializados.`);
      await load();
    } catch (err) {
      setError(err.message || "No se pudieron materializar eventos.");
    } finally {
      setActionBusy("");
    }
  };

  const handleExport = async () => {
    setActionBusy("export");
    setError("");
    try {
      const result = await exportSecOpsSecurityEvents({
        destination: "generic_webhook",
        format: "soc_case.v1",
        includeItems: true,
        send: false,
        limit: 100,
      });
      setExportPreview(result);
      setNotice(result.ready_to_send ? "Export listo para envio." : "Export generado en preview.");
    } catch (err) {
      setError(err.message || "No se pudo generar export SOC/SIEM.");
    } finally {
      setActionBusy("");
    }
  };

  const handleSendExport = async () => {
    if (!exportReady) {
      setError("SOC/SIEM send bloqueado: readiness del destino no esta listo.");
      return;
    }
    setActionBusy("export-send");
    setError("");
    try {
      const result = await exportSecOpsSecurityEvents({
        destination: "generic_webhook",
        format: "soc_case.v1",
        includeItems: true,
        send: true,
        limit: 100,
      });
      setExportDelivery(result);
      setNotice(result.delivery.status || "Export enviado al destino configurado.");
    } catch (err) {
      setError(err.message || "No se pudo enviar export SOC/SIEM.");
    } finally {
      setActionBusy("");
    }
  };

  const handleLifecycle = async (sourceEventId) => {
    if (!lifecycleAllowed) {
      setError("Lifecycle bloqueado: ejecuta un preflight permitido antes de continuar.");
      return;
    }
    setActionBusy(`lifecycle-${sourceEventId}`);
    setError("");
    try {
      const result = await runSecOpsSecurityEventLifecycle(sourceEventId, {
        executionControls: { dry_run: true, source: "secops-command-center" },
        humanApproved: false,
      });
      setLifecycleResult(result);
      setNotice(`Lifecycle ${result.status || "procesado"} en dry-run.`);
      await load();
    } catch (err) {
      setError(err.message || "No se pudo lanzar lifecycle.");
    } finally {
      setActionBusy("");
    }
  };

  const loadApprovalEvidence = async (verdictId = selectedVerdict.verdict_id) => {
    if (!verdictId) return;
    setActionBusy("approval-evidence");
    setError("");
    try {
      const [approvalResult, evidenceResult] = await Promise.allSettled([
        getAresApprovals(verdictId),
        getAresEvidenceBundle(verdictId),
      ]);
      setApprovals(valueOrNull(approvalResult));
      setEvidenceBundle(valueOrNull(evidenceResult));
      const failed = [approvalResult, evidenceResult].find((result) => result.status === "rejected");
      if (failed) setError(failed.reason.message || "No se pudo cargar evidencia de approval.");
    } finally {
      setActionBusy("");
    }
  };

  const createApprovalEvidence = async () => {
    if (!selectedVerdict) return;
    setActionBusy("approval-token");
    setError("");
    try {
      const token = await createAresApprovalToken({
        verdict: selectedVerdict,
        approver: approvalDraft.approver,
        reason: approvalDraft.reason,
      });
      setApprovalToken(token);
      setNotice("Approval evidence generado para el verdict seleccionado.");
      await loadApprovalEvidence();
    } catch (err) {
      setError(err.message || "No se pudo generar approval evidence.");
    } finally {
      setActionBusy("");
    }
  };

  const handlePolicySave = async (event) => {
    event.preventDefault();
    setActionBusy("policy");
    setError("");
    try {
      const result = await upsertTenantPolicy({
        tenant_id: policyDraft.tenant_id.trim(),
        name: policyDraft.name.trim(),
        condition_dsl: policyDraft.condition_dsl.trim(),
        action_allowed: splitList(policyDraft.action_allowed),
        provider_assignments: parseAssignments(policyDraft.provider_assignments),
        max_autonomy_score: Number(policyDraft.max_autonomy_score),
        requires_human: policyDraft.requires_human,
        enabled: policyDraft.enabled,
      });
      setNotice(`Policy guardada: ${result.name || result.rule_id || "tenant policy"}.`);
      await load();
    } catch (err) {
      setError(err.message || "No se pudo guardar la tenant policy.");
    } finally {
      setActionBusy("");
    }
  };

  return (
    <div className="min-h-full text-[#eef3ff]">
      <section className="mb-6 flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
        <div>
          <p className="font-label text-[10px] uppercase text-[#8c909f]">
            SecOps / DevSecOps
          </p>
          <h2 className="mt-1 font-headline text-3xl font-bold text-white">
            Command center operativo
          </h2>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-[#aeb7ca]">
            Contratos reales de postura, readiness, eventos, providers, policies y acciones
            gobernadas.
          </p>
        </div>
        <button
          type="button"
          onClick={load}
          className="inline-flex h-10 items-center justify-center gap-2 border border-white/10 bg-[#121a2f] px-4 text-sm text-[#dbe7ff] hover:border-[#adc6ff]/50"
          title="Actualizar SecOps"
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
          icon={<ShieldCheck size={18} />}
          label="Postura SecOps"
          value={loading ? "..." : posture.overall || "N/A"}
          detail={`${posture.security_events || 0} security events`}
          tone={posture.overall === "ready" ? "success" : "neutral"}
        />
        <MetricTile
          icon={<Activity size={18} />}
          label="Control plane"
          value={loading ? "..." : status.phase || "N/A"}
          detail={`${status.integrates.length || 0} dominios integrados`}
        />
        <MetricTile
          icon={<Database size={18} />}
          label="Tenant policies"
          value={loading ? "..." : String(policies.length)}
          detail={enterpriseReadiness.tenant_policy.status || "readiness pendiente"}
        />
        <MetricTile
          icon={<ShieldEllipsis size={18} />}
          label="Providers"
          value={loading ? "..." : String(providers.length)}
          detail={`${activeActions.length} acciones activas`}
        />
      </section>

      <section className="grid grid-cols-12 gap-5">
        <Panel className="col-span-12 xl:col-span-4" title="Readiness" right="external gates">
          <div className="space-y-3">
            {readinessItems.length === 0 ? (
              <EmptyState text={loading ? "Cargando readiness..." : "Sin readiness disponible"} />
            ) : (
              readinessItems.slice(0, 12).map((item) => (
                <ReadinessRow key={item.key} item={item} />
              ))
            )}
          </div>
        </Panel>

        <Panel className="col-span-12 xl:col-span-4" title="Provider preflight" right="dry-run">
          <div className="space-y-4">
            <label className="block">
              <span className="mb-2 block font-label text-[10px] uppercase text-[#8c909f]">
                Provider
              </span>
              <select
                value={selectedProvider}
                onChange={(event) => setSelectedProvider(event.target.value)}
                className="h-10 w-full border border-white/10 bg-[#0b1020] px-3 text-sm text-white outline-none"
              >
                {providerOptions.map((provider) => (
                  <option key={provider.provider} value={provider.provider}>
                    {provider.provider}
                  </option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="mb-2 block font-label text-[10px] uppercase text-[#8c909f]">
                Accion
              </span>
              <select
                value={selectedAction}
                onChange={(event) => setSelectedAction(event.target.value)}
                className="h-10 w-full border border-white/10 bg-[#0b1020] px-3 text-sm text-white outline-none"
              >
                {activeActions.map((action) => (
                  <option key={action} value={action}>
                    {action}
                  </option>
                ))}
              </select>
            </label>
            <button
              type="button"
              onClick={handlePreflight}
              disabled={actionBusy === "preflight"}
              className="inline-flex h-10 w-full items-center justify-center gap-2 bg-[#78ffbd] px-4 text-sm font-bold text-[#07130c] disabled:opacity-50"
            >
              <SlidersHorizontal size={16} />
              Ejecutar preflight
            </button>
            {preflight && (
              <ResultBox
                title={preflight.allowed ? "Allowed" : "Blocked"}
                body={preflight.reason || preflight.mode}
                ok={preflight.allowed}
              />
            )}
            {providerReadiness && (
              <pre className="max-h-44 overflow-auto bg-[#070b12] p-3 text-xs text-[#dbe7ff]">
                {JSON.stringify(providerReadiness, null, 2)}
              </pre>
            )}
          </div>
        </Panel>

        <Panel className="col-span-12 xl:col-span-4" title="SOC/SIEM export" right="preview">
          <div className="grid gap-3">
            <ActionButton
              icon={<UploadCloud size={16} />}
              label="Materializar eventos"
              busy={actionBusy === "materialize"}
              onClick={handleMaterialize}
            />
            <ActionButton
              icon={<Send size={16} />}
              label="Generar export"
              busy={actionBusy === "export"}
              onClick={handleExport}
            />
            <ActionButton
              icon={<ShieldCheck size={16} />}
              label="Enviar si readiness pasa"
              busy={actionBusy === "export-send"}
              onClick={handleSendExport}
              disabled={!exportReady}
            />
            {materializeResult && (
              <ResultBox
                title="Materialize"
                body={`${materializeResult.materialized || 0} nuevos, ${materializeResult.duplicates || 0} duplicados`}
                ok
              />
            )}
            {exportPreview && (
              <ResultBox
                title={exportPreview.ready_to_send ? "Ready to send" : "Preview only"}
                body={`${exportPreview.count || 0} items hacia ${exportPreview.destination}`}
                ok={exportPreview.ready_to_send}
              />
            )}
            {exportDelivery && (
              <ResultBox
                title="Delivery"
                body={exportDelivery.delivery.status || exportDelivery.status || "procesado"}
                ok
              />
            )}
          </div>
        </Panel>

        <Panel className="col-span-12 xl:col-span-8" title="Security events" right={`${securityEvents.count || 0} eventos`}>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[920px] text-left">
              <thead>
                <tr className="border-b border-white/10 font-label text-[10px] uppercase text-[#8c909f]">
                  <th className="px-4 py-3 font-normal">Evento</th>
                  <th className="px-4 py-3 font-normal">Reason</th>
                  <th className="px-4 py-3 font-normal">Tenant</th>
                  <th className="px-4 py-3 font-normal">Provider</th>
                  <th className="px-4 py-3 font-normal">Capability</th>
                  <th className="px-4 py-3 font-normal">Accion</th>
                </tr>
              </thead>
              <tbody className="text-sm">
                {(securityEvents.items || []).length === 0 ? (
                  <tr>
                    <td className="px-4 py-8 text-[#8c909f]" colSpan={6}>
                      {loading ? "Cargando eventos..." : "No hay eventos de seguridad."}
                    </td>
                  </tr>
                ) : (
                  securityEvents.items.map((item) => (
                    <tr key={item.record_id} className="border-b border-white/5">
                      <td className="px-4 py-3">
                        <div className="truncate font-medium text-white">{item.event_type}</div>
                        <div className="mt-1 truncate font-label text-[10px] text-[#5f687a]">
                          {item.source_event_id}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-[#dbe7ff]">{item.reason}</td>
                      <td className="px-4 py-3 text-[#aeb7ca]">{item.tenant_id}</td>
                      <td className="px-4 py-3 text-[#aeb7ca]">{item.provider}</td>
                      <td className="px-4 py-3 text-[#aeb7ca]">{item.capability}</td>
                      <td className="px-4 py-3">
                        <button
                          type="button"
                          onClick={() => handleLifecycle(item.source_event_id)}
                          disabled={
                            !lifecycleAllowed || actionBusy === `lifecycle-${item.source_event_id}`
                          }
                          className="inline-flex h-9 items-center gap-2 border border-[#adc6ff]/30 px-3 text-xs text-[#dbe7ff] hover:border-[#adc6ff] disabled:opacity-40"
                        >
                          <FileCheck2 size={14} />
                          Lifecycle
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel className="col-span-12 xl:col-span-4" title="Tenant policy" right="upsert">
          <form className="space-y-3" onSubmit={handlePolicySave}>
            <TextInput label="Tenant" value={policyDraft.tenant_id} onChange={(value) => setPolicyDraft({ ...policyDraft, tenant_id: value })} />
            <TextInput label="Nombre" value={policyDraft.name} onChange={(value) => setPolicyDraft({ ...policyDraft, name: value })} />
            <TextInput label="Condition DSL" value={policyDraft.condition_dsl} onChange={(value) => setPolicyDraft({ ...policyDraft, condition_dsl: value })} />
            <TextInput label="Acciones permitidas" value={policyDraft.action_allowed} onChange={(value) => setPolicyDraft({ ...policyDraft, action_allowed: value })} />
            <TextInput label="Provider assignments" value={policyDraft.provider_assignments} onChange={(value) => setPolicyDraft({ ...policyDraft, provider_assignments: value })} />
            <div className="grid grid-cols-2 gap-3">
              <label className="block">
                <span className="mb-2 block font-label text-[10px] uppercase text-[#8c909f]">
                  Max autonomy
                </span>
                <input
                  type="number"
                  min="0"
                  max="100"
                  value={policyDraft.max_autonomy_score}
                  onChange={(event) =>
                    setPolicyDraft({ ...policyDraft, max_autonomy_score: event.target.value })
                  }
                  className="h-10 w-full border border-white/10 bg-[#0b1020] px-3 text-sm text-white outline-none"
                />
              </label>
              <div className="flex items-end gap-3">
                <Toggle
                  label="Human"
                  checked={policyDraft.requires_human}
                  onChange={(checked) => setPolicyDraft({ ...policyDraft, requires_human: checked })}
                />
                <Toggle
                  label="Enabled"
                  checked={policyDraft.enabled}
                  onChange={(checked) => setPolicyDraft({ ...policyDraft, enabled: checked })}
                />
              </div>
            </div>
            <button
              type="submit"
              disabled={actionBusy === "policy"}
              className="inline-flex h-10 w-full items-center justify-center gap-2 bg-[#adc6ff] px-4 text-sm font-bold text-[#08111f] disabled:opacity-50"
            >
              <CheckCircle2 size={16} />
              Guardar policy
            </button>
          </form>
        </Panel>

        <Panel className="col-span-12 xl:col-span-8" title="Approvals y evidencia" right={`${verdicts.length} verdicts`}>
          <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px] text-left">
                <thead>
                  <tr className="border-b border-white/10 font-label text-[10px] uppercase text-[#8c909f]">
                    <th className="px-4 py-3 font-normal">Verdict</th>
                    <th className="px-4 py-3 font-normal">Risk</th>
                    <th className="px-4 py-3 font-normal">Status</th>
                    <th className="px-4 py-3 font-normal">Human</th>
                    <th className="px-4 py-3 font-normal">Evidencia</th>
                  </tr>
                </thead>
                <tbody className="text-sm">
                  {verdicts.length === 0 ? (
                    <tr>
                      <td className="px-4 py-8 text-[#8c909f]" colSpan={5}>
                        {loading ? "Cargando verdicts..." : "No hay verdicts disponibles."}
                      </td>
                    </tr>
                  ) : (
                    verdicts.map((verdict) => (
                      <tr
                        key={verdict.verdict_id}
                        className="cursor-pointer border-b border-white/5 hover:bg-[#151f32]"
                        onClick={() => setSelectedVerdictId(verdict.verdict_id)}
                      >
                        <td className="px-4 py-3">
                          <div className="truncate font-medium text-white">
                            {verdict.target || verdict.verdict_id}
                          </div>
                          <div className="mt-1 truncate font-label text-[10px] text-[#5f687a]">
                            {verdict.verdict_id}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-[#dbe7ff]">{Math.round(Number(verdict.risk_score) || 0)}</td>
                        <td className="px-4 py-3"><StatusBadge value={verdict.status} /></td>
                        <td className="px-4 py-3 text-[#aeb7ca]">
                          {verdict.requires_human_approval ? "required" : "not required"}
                        </td>
                        <td className="px-4 py-3">
                          <button
                            type="button"
                            onClick={(event) => {
                              event.stopPropagation();
                              setSelectedVerdictId(verdict.verdict_id);
                              loadApprovalEvidence(verdict.verdict_id);
                            }}
                            className="inline-flex h-8 items-center gap-2 border border-white/10 px-3 text-xs text-[#dbe7ff] hover:border-[#adc6ff]"
                          >
                            <Eye size={14} />
                            Ver
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
            <div className="space-y-3">
              <div className="border border-white/10 bg-[#0b1020] p-4">
                <div className="font-label text-[10px] uppercase text-[#8c909f]">
                  Verdict seleccionado
                </div>
                <div className="mt-2 truncate text-sm font-semibold text-white">
                  {selectedVerdict.verdict_id || "N/A"}
                </div>
              </div>
              <TextInput
                label="Approver"
                value={approvalDraft.approver}
                onChange={(value) => setApprovalDraft({ ...approvalDraft, approver: value })}
              />
              <TextInput
                label="Reason"
                value={approvalDraft.reason}
                onChange={(value) => setApprovalDraft({ ...approvalDraft, reason: value })}
              />
              <ActionButton
                icon={<ClipboardCheck size={16} />}
                label="Generar approval evidence"
                busy={actionBusy === "approval-token"}
                onClick={createApprovalEvidence}
                disabled={!selectedVerdict}
              />
              <ActionButton
                icon={<FileCheck2 size={16} />}
                label="Cargar audit evidence"
                busy={actionBusy === "approval-evidence"}
                onClick={loadApprovalEvidence}
                disabled={!selectedVerdict}
              />
              {approvals && (
                <ResultBox
                  title="Approvals"
                  body={`${approvals.count || 0} approvals registrados`}
                  ok
                />
              )}
            </div>
          </div>
        </Panel>

        <Panel className="col-span-12 xl:col-span-4" title="Evidence bundle" right={approvalToken ? "token generado" : "audit"}>
          <div className="space-y-3">
            {approvalToken && (
              <pre className="max-h-48 overflow-auto bg-[#070b12] p-3 text-xs text-[#dbe7ff]">
                {JSON.stringify(approvalToken, null, 2)}
              </pre>
            )}
            {evidenceBundle ? (
              <pre className="max-h-64 overflow-auto bg-[#070b12] p-3 text-xs text-[#dbe7ff]">
                {JSON.stringify(evidenceBundle, null, 2)}
              </pre>
            ) : (
              <EmptyState text="Selecciona un verdict y carga evidencia." />
            )}
          </div>
        </Panel>

        <Panel className="col-span-12" title="Policies registradas" right={`${policies.length} reglas`}>
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
            {policies.length === 0 ? (
              <EmptyState text={loading ? "Cargando policies..." : "No hay policies registradas"} />
            ) : (
              policies.map((policy) => (
                <div key={policy.rule_id || policy.name} className="border border-white/10 bg-[#0b1020] p-4">
                  <div className="mb-3 flex items-start justify-between gap-3">
                    <div>
                      <h3 className="font-semibold text-white">{policy.name}</h3>
                      <p className="mt-1 font-label text-[10px] uppercase text-[#8c909f]">
                        {policy.tenant_id || "default"}
                      </p>
                    </div>
                    <StatusBadge value={policy.enabled ? "enabled" : "disabled"} />
                  </div>
                  <p className="mb-3 line-clamp-2 text-xs text-[#aeb7ca]">
                    {policy.condition_dsl || "Sin condition DSL"}
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {(policy.action_allowed || []).slice(0, 5).map((action) => (
                      <span key={action} className="bg-[#10182b] px-2 py-1 font-label text-[10px] text-[#adc6ff]">
                        {action}
                      </span>
                    ))}
                  </div>
                </div>
              ))
            )}
          </div>
        </Panel>
      </section>

      {lifecycleResult && (
        <div className="mt-5 border border-white/10 bg-[#0d1422] p-4">
          <div className="mb-2 font-label text-[10px] uppercase text-[#8c909f]">
            Ultimo lifecycle
          </div>
          <pre className="max-h-72 overflow-auto bg-[#070b12] p-3 text-xs text-[#dbe7ff]">
            {JSON.stringify(lifecycleResult, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

function valueOrNull(result) {
  return result.status === "fulfilled" ? result.value : null;
}

function flattenReadiness(integrationsReadiness, enterpriseReadiness) {
  const items = [];
  if (integrationsReadiness && typeof integrationsReadiness === "object") {
    Object.entries(integrationsReadiness).forEach(([key, value]) => {
      if (value && typeof value === "object") {
        items.push({
          key,
          label: value.integration || value.module || key,
          status: value.status || value.overall || (value.configured ? "configured" : "pending"),
          detail: value.reason || value.mode || value.next_gate || "",
        });
      }
    });
  }
  if (enterpriseReadiness.tenant_policy) {
    items.unshift({
      key: "tenant_policy",
      label: "tenant_policy",
      status: enterpriseReadiness.tenant_policy.status || "unknown",
      detail: enterpriseReadiness.tenant_policy.reason || "",
    });
  }
  return items;
}

function splitList(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseAssignments(value) {
  return splitList(value).reduce((acc, item) => {
    const [key, provider] = item.split("=").map((part) => part.trim());
    if (key && provider) acc[key] = provider;
    return acc;
  }, {});
}

function isReadyStatus(value) {
  return ["ready", "ok", "configured", "pass", "passing"].includes(
    String(value || "").toLowerCase()
  );
}

function isReadinessKeyReady(items, keyPart) {
  return items.some(
    (item) =>
      String(item.key || item.label || "").toLowerCase().includes(keyPart) &&
      isReadyStatus(item.status)
  );
}

function MetricTile({ icon, label, value, detail, tone = "neutral" }) {
  const color = tone === "success" ? "text-[#78ffbd]" : "text-white";
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

function ReadinessRow({ item }) {
  const ok = ["ready", "ok", "configured", "pass", "passing"].includes(
    String(item.status || "").toLowerCase()
  );
  return (
    <div className="flex items-start gap-3 border border-white/10 bg-[#0b1020] p-3">
      {ok ? (
        <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-[#78ffbd]" />
      ) : (
        <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-[#ff8d96]" />
      )}
      <div className="min-w-0">
        <div className="truncate text-sm font-medium text-white">{item.label}</div>
        <div className="mt-1 truncate font-label text-[10px] uppercase text-[#8c909f]">
          {item.status}
        </div>
        {item.detail && <p className="mt-2 text-xs text-[#aeb7ca]">{item.detail}</p>}
      </div>
    </div>
  );
}

function ActionButton({ icon, label, busy, onClick, disabled = false }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={busy || disabled}
      className="inline-flex h-10 items-center justify-center gap-2 border border-[#adc6ff]/30 bg-[#0b1020] px-4 text-sm text-[#dbe7ff] hover:border-[#adc6ff] disabled:opacity-40"
    >
      {icon}
      {label}
    </button>
  );
}

function ResultBox({ title, body, ok }) {
  return (
    <div className={`border px-3 py-3 ${ok ? "border-[#78ffbd]/25 bg-[#10281b]" : "border-[#ffb4ab]/30 bg-[#3a1619]"}`}>
      <div className="font-label text-[10px] uppercase text-[#8c909f]">{title}</div>
      <div className="mt-1 text-sm text-white">{body}</div>
    </div>
  );
}

function TextInput({ label, value, onChange }) {
  return (
    <label className="block">
      <span className="mb-2 block font-label text-[10px] uppercase text-[#8c909f]">
        {label}
      </span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-10 w-full border border-white/10 bg-[#0b1020] px-3 text-sm text-white outline-none focus:border-[#adc6ff]/50"
      />
    </label>
  );
}

function Toggle({ label, checked, onChange }) {
  return (
    <label className="flex h-10 flex-1 items-center justify-between gap-2 border border-white/10 bg-[#0b1020] px-3 text-xs text-[#dbe7ff]">
      <span>{label}</span>
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        className="h-4 w-4 accent-[#78ffbd]"
      />
    </label>
  );
}

function StatusBadge({ value }) {
  const normalized = String(value || "unknown").toLowerCase();
  const ok = ["enabled", "ready", "ok", "active"].includes(normalized);
  return (
    <span className={`px-2 py-1 font-label text-[10px] uppercase ${ok ? "bg-[#78ffbd]/10 text-[#78ffbd]" : "bg-slate-500/10 text-slate-300"}`}>
      {normalized}
    </span>
  );
}

function EmptyState({ text }) {
  return <div className="border border-white/10 bg-[#0b1020] p-4 text-sm text-[#8c909f]">{text}</div>;
}
