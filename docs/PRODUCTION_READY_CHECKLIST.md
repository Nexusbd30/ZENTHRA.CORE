# Production Readiness Checklist

Fase 1 queda cerrada formalmente en `docs/DOC-10_PHASE1_CLOSURE.md`.
Fase 2 queda cerrada formalmente en `docs/PHASE2_CLOSURE.md`.
Fase 3 Enterprise AI queda cerrada formalmente en `docs/PHASE3_CLOSURE.md` y documentada operativamente en `docs/PHASE3_ENTERPRISE_AI_RUNBOOK.md`.
Fase 4 queda como cierre de endurecimiento backend y code intelligence en `docs/PHASE4_BACKEND_HARDENING.md`.
El cierre de codigo backend de Fase 5 queda documentado en `docs/PHASE5_BACKEND_CODE_CLOSURE.md`.
El trabajo restante depende de activacion productiva externa y Fase 6 Product and Operations Closure.

## Backend Core Status

- Backend suite: `282 passed`.
- Coverage total: `93.53%`.
- RedQueen/ARES core: ready for controlled pilot with real-integration gates.
- Identity Defense, SecOps/DevSecOps, audit chain, MCP context, LLM contract/governance, enterprise AI memory, provider readiness, execution preflight and controlled SOC export are implemented.
- ARES kill-switch supports Redis-backed distributed state and fails closed when the configured distributed backend is unavailable.
- Tenant/provider policies are persisted in `policy_rules` and exposed through SecOps tenant-policy endpoints.
- Runtime secret consumption now supports file-backed secrets for core auth, JWT/HMAC signing, Entra, GitHub, ARES webhook dispatch and SOC export.

## Ready For Controlled Pilot

- RedQueen issues signed, domain-aware verdicts.
- ARES validates signatures, policy, kill switch, approvals, MCP policy and provider capabilities.
- Enterprise audit context persists `tenant_id`, `actor_role`, `capability` and `request_id`.
- Microsoft Entra webhook contract supports HMAC signature, timestamp skew validation, provider evidence, rate limit and replay guard.
- SOC/SIEM security event read path is available through `GET /api/v1/secops/security/events`.
- Security events can be materialized as `ThreatEvent` with source `secops:integration_security_abuse`.
- Materialized integration abuse can run through RedQueen/ARES lifecycle.
- Prometheus exposes security counters for webhook rejections, rate limits, replay, SOC materialization and SOC lifecycle.
- Export contract `soc_case.v1` is available for SIEM/case management payload generation.
- SOC capabilities are separated as `soc:read`, `soc:materialize` and `soc:execute`.
- Integration readiness contracts are available for GitHub Actions, Redis, SOC webhook, secret backend and Sentinel/Wazuh ingestion.
- Execution preflight is available at `POST /api/v1/secops/execution/preflight`.
- Real provider execution is guarded by provider readiness, action capability, explicit mode, `change_ticket`, ARES validation and signed human approval when required.
- Enterprise AI readiness is available at `GET /api/v1/secops/intelligence/enterprise/readiness`.
- Enterprise AI contract registry is available at `GET /api/v1/secops/intelligence/enterprise/contracts`.
- ARES AI evidence bundle is available at `GET /api/v1/ares/evidence/{verdict_id}`.
- Static backend architecture analysis is available at `POST /api/v1/code-intelligence/analyze`.
- Restricted RedQueen, ARES, and ingestion ASGI entrypoints are available without scheduler ownership.
- Tenant policy management is available through `GET /api/v1/secops/tenant-policies` and `POST /api/v1/secops/tenant-policies`.
- Strict tenant mode rejects missing tenant headers on enterprise capability routes and rejects tenant-policy read/write mismatches.

## Pilot Only Until External Backend Exists

- Baseline RAG can still use in-memory documents, but Enterprise AI memory now supports persistent SQL-backed versioned knowledge documents.
- Provider connectors require real secrets and provider-side permissions before live execution.
- Redis must be selected through `RATE_LIMIT_BACKEND=redis`, `REPLAY_GUARD_BACKEND=redis` and `ARES_KILL_SWITCH_BACKEND=redis` for multi-instance production.
- SOC export can send a real generic webhook when `SOC_WEBHOOK_URL`, `SOC_WEBHOOK_TOKEN` and `SOC_WEBHOOK_HMAC_SECRET` are configured.
- Entra Graph active response requires `ACTION_EXECUTION_MODE=provider`, `ENTRA_GRAPH_ENABLED=true` and least-privilege Graph credentials.
- GitHub/GHAS execution requires `ACTION_EXECUTION_MODE=provider` or `real` and configured GitHub token permissions.
- K8s backend deployments mount `aresx-secrets` at `/run/secrets/aresx` and select `SECRET_BACKEND=file`.

## Required For Production

### Phase 5 - Production Activation

- Select Redis, API Gateway or WAF distributed enforcement for rate limit and replay stores.
- Validate shared Redis-backed ARES kill-switch state across multiple ARES processes or replicas.
- Decide whether SQL-backed knowledge documents are enough for pilot or replace retrieval with pgvector, Qdrant or Azure AI Search.
- Connect real MCP servers and keep allow/block policy enforced per action.
- Activate Microsoft Entra Graph with least-privilege permissions and managed secrets.
- Activate at least one DevSecOps provider: GitHub Actions/GHAS, Azure DevOps or GitLab CI.
- Activate at least one SIEM/SOC export destination: Microsoft Sentinel or generic webhook.
- Move secrets to Key Vault or equivalent secret manager.
- Enforce persisted tenant policies across all critical repository read/write paths for strict multi-tenant mode.

### Phase 6 - Product And Operations Closure

- Add frontend SOC/SecOps command center.
- Add Terraform/IaC only after the deployment target is fixed.
- Add service dashboards, alerts, SLOs, backup/restore, rollback, incident, load,
  resilience and security validation.

## CI/CD

- `CI` workflow in `.github/workflows/ci.yml`
  - Backend: `ruff`, `mypy`, `pytest` with 90% coverage gate.
  - Frontend: `pnpm run lint`, `pnpm run build`.
- `CD` workflow in `.github/workflows/cd.yml`
  - Builds and pushes image to GHCR.
  - Deploys hardened manifests in `infra/k8s`.

## Required GitHub Secrets

- `KUBE_CONFIG_DATA` (base64 kubeconfig).
- Production deployments also require external secret management for identity, DevSecOps and SIEM connectors.

## Security

- No real credentials in committed templates:
  - `.env.example`
  - `infra/k8s/secrets.yaml`
- Bootstrap admin disabled by default in production config:
  - `BOOTSTRAP_ADMIN_ENABLED=false`
- Production must configure:
  - `SECRET_KEY`
  - `ZENTHRA_MONITOR_TOKEN`
  - Provider secrets through a secret manager, not plain env files.
- K8s secret templates include placeholders for `ACTION_SHARED_TOKEN`, `ENTRA_CLIENT_SECRET`, `ENTRA_WEBHOOK_SECRET`, `GITHUB_TOKEN`, `SOC_WEBHOOK_TOKEN` and `SOC_WEBHOOK_HMAC_SECRET`.

## Infrastructure Hardening

- K8s deployments include:
  - `readinessProbe` and `livenessProbe`
  - non-root execution and dropped Linux capabilities
  - resource requests/limits
  - fixed image tag, no `latest`
- Added:
  - `infra/k8s/hpa.yaml`
  - `infra/k8s/networkpolicy.yaml`
  - `infra/k8s/pdb.yaml`

## Current Known Risk

- In-memory stores are not safe for multi-instance production.
- External connectors are not live yet.
- Frontend product workflow is pending.
- Terraform should wait until provider and deployment decisions are stable.
- Strict tenant policy persistence exists; additional domain-specific row-level isolation should still be reviewed before broad multi-tenant onboarding.
- A real LLM gateway and vector retrieval backend are not selected.
- Restricted service routing and NetworkPolicies are required before enabling split deployments.
- ARES may only scale horizontally after the shared Redis kill-switch backend is validated in the target environment.
