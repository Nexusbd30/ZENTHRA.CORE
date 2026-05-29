# Production Readiness Checklist

Fase 1 queda cerrada formalmente en `docs/DOC-10_PHASE1_CLOSURE.md`.

## Backend Core Status

- Backend suite: `193 passed`.
- Coverage total: `84%`.
- RedQueen/ARES core: ready for controlled pilot.
- Identity Defense, SecOps/DevSecOps, audit chain, MCP context, LLM contract and local RAG are implemented.

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

## Pilot Only Until External Backend Exists

- RAG uses in-memory knowledge repository.
- Rate limit store is `in_memory`.
- Replay guard store is `in_memory`.
- SOC export returns `ready_to_send=false`; no external SIEM/case destination is connected.
- Entra Graph active response is not connected yet.
- DevSecOps providers are capability contracts and dry-run bridges until real provider credentials are configured.

## Required For Production

- Replace rate limit and replay stores with Redis, API Gateway or WAF distributed enforcement.
- Replace local RAG with pgvector, Qdrant or Azure AI Search.
- Connect real MCP servers and keep allow/block policy enforced per action.
- Connect Microsoft Entra Graph with least-privilege permissions and managed secrets.
- Connect at least one DevSecOps provider: GitHub Actions/GHAS, Azure DevOps or GitLab CI.
- Connect at least one SIEM/SOC export destination: Microsoft Sentinel or generic webhook.
- Move secrets to Key Vault or equivalent secret manager.
- Add tenant policy persistence for strict multi-tenant mode.
- Add frontend SOC/SecOps command center.
- Add Terraform/IaC only after the deployment target is fixed.

## CI/CD

- `CI` workflow in `.github/workflows/ci.yml`
  - Backend: `ruff`, `mypy`, `pytest` with coverage gate.
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
