# Production Readiness Checklist

Fase 1 queda cerrada formalmente en `docs/DOC-10_PHASE1_CLOSURE.md`.
Fase 2 queda cerrada formalmente en `docs/PHASE2_CLOSURE.md`.
Fase 3 Enterprise AI queda cerrada formalmente en `docs/PHASE3_CLOSURE.md` y documentada operativamente en `docs/PHASE3_ENTERPRISE_AI_RUNBOOK.md`.
Fase 4 queda como cierre de endurecimiento backend y code intelligence en `docs/PHASE4_BACKEND_HARDENING.md`.
El cierre de codigo backend de Fase 5 queda documentado en `docs/PHASE5_BACKEND_CODE_CLOSURE.md`.
El release de produccion queda definido por `.github/workflows/cd.yml` y
`docs/PRODUCTION_RELEASE_RUNBOOK.md`. El trabajo restante ya no es codigo base:
depende de configurar los recursos gestionados, secretos reales y aprobaciones
del entorno `production`.

## Backend Core Status

- Backend suite: `286 passed`.
- Coverage total: `93.48%`.
- RedQueen/ARES core: listo para produccion con gates de integracion real.
- Identity Defense, SecOps/DevSecOps, audit chain, MCP context, LLM contract/governance, enterprise AI memory, provider readiness, execution preflight and controlled SOC export are implemented.
- ARES kill-switch supports Redis-backed distributed state and fails closed when the configured distributed backend is unavailable.
- Tenant/provider policies are persisted in `policy_rules` and exposed through SecOps tenant-policy endpoints.
- Runtime secret consumption now supports file-backed secrets for core auth, JWT/HMAC signing, Entra, GitHub, ARES webhook dispatch and SOC export.

## Ready For Production Release

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
- Restricted RedQueen, ARES, and ingestion ASGI entrypoints are deployed by the production workflow.
- Tenant policy management is available through `GET /api/v1/secops/tenant-policies` and `POST /api/v1/secops/tenant-policies`.
- Strict tenant mode rejects missing tenant headers on enterprise capability routes and rejects tenant-policy read/write mismatches.

## External Production Contracts

- Production refuses `local_stub`, `dry_run`, public registration and in-memory distributed stores at settings validation time.
- Provider connectors require real secrets and provider-side permissions before live execution.
- Redis must be selected through `RATE_LIMIT_BACKEND=redis`, `REPLAY_GUARD_BACKEND=redis` and `ARES_KILL_SWITCH_BACKEND=redis` for production.
- SOC export can send a real generic webhook when `SOC_WEBHOOK_URL`, `SOC_WEBHOOK_TOKEN` and `SOC_WEBHOOK_HMAC_SECRET` are configured.
- Entra Graph active response requires `ACTION_EXECUTION_MODE=provider`, `ENTRA_GRAPH_ENABLED=true` and least-privilege Graph credentials.
- GitHub/GHAS execution requires `ACTION_EXECUTION_MODE=provider` or `real` and configured GitHub token permissions.
- K8s backend deployments mount `aresx-secrets` at `/run/secrets/aresx` and select `SECRET_BACKEND=file`.

## Required For Production Environment

- Managed Postgres reachable by the cluster.
- Managed Redis reachable by the cluster.
- Kubernetes secret `aresx-secrets` populated from the chosen secret manager.
- Kubernetes TLS secret `vaelqorix-tls`.
- GitHub environment `production` with required variables and deployment approval.
- Real Identity, DevSecOps, SOC/SIEM, LLM and vector/RAG provider configuration.
- Backup/restore, rollback and incident drills executed against the target cluster.

## CI/CD

- `CI` workflow in `.github/workflows/ci.yml`
  - Backend: `ruff`, `mypy`, `pytest` with 90% coverage gate.
  - Frontend: `pnpm run lint`, `pnpm run build`.
- `Production` workflow in `.github/workflows/cd.yml`
  - Runs backend/frontend quality gates, encoding guard and production preflight.
  - Audits Python and frontend dependencies.
  - Builds and pushes backend/frontend images to GHCR.
  - Generates production runtime config from the GitHub `production` environment.
  - Deploys API, frontend, RedQueen, ARES, ingestion, migrations, ingress, HPA, PDB and NetworkPolicy.
  - Runs rollout status and public `/health` + `/ready` smoke tests.

## Required GitHub Secrets

- `KUBE_CONFIG_DATA` (base64 kubeconfig).
- `REDIS_URL`.
- Cluster secret `aresx-secrets` for `SECRET_KEY`, `VAELQORIX_MONITOR_TOKEN`, `POSTGRES_PASSWORD` and provider credentials.

## Security

- No real credentials in committed templates:
  - `.env.example`
  - `infra/k8s/secrets.yaml`
- Bootstrap admin disabled by default in production config:
  - `BOOTSTRAP_ADMIN_ENABLED=false`
- Production must configure:
  - `SECRET_KEY`
  - `VAELQORIX_MONITOR_TOKEN`
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

- Deployment cannot complete until the real GitHub `production` environment, cluster secrets, DNS/TLS, managed Postgres and managed Redis exist.
- Real provider permissions still need target-environment validation.
- Backup/restore, rollback, tenant isolation, multi-replica and incident drills must be executed in the production cluster.
