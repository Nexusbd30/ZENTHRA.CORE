# Phase 7 - Production Closure Plan

## Current Gate

The repository is now in technical pre-production shape:

- Backend tests pass with coverage above the production gate.
- Backend lint and type checks pass.
- Frontend lint and production build pass.
- Python and frontend dependency audits report no known vulnerabilities.
- Text encoding guard reports zero mojibake findings.

This phase focuses on turning the clean codebase into an operated production platform.

## Production Objectives

1. Establish managed runtime infrastructure.
2. Move all production secrets out of plain environment variables.
3. Complete full-stack deployment automation.
4. Validate external enterprise integrations.
5. Prove operational safety with rollback, backups, tenant isolation, and incident workflows.

## Workstreams

### 1. Infrastructure

- Provision managed Postgres for application state.
- Provision managed Redis for rate limits, replay guard, and kill switch state.
- Select the final runtime target: Kubernetes, Azure Container Apps, App Service, or equivalent.
- Define production domain, TLS certificates, ingress or reverse proxy.
- Configure persistent storage and backup policies.

### 2. Secrets And Configuration

- Choose a secrets backend: Azure Key Vault, External Secrets, SOPS, SealedSecrets, or equivalent.
- Move JWT, monitor, action, SOC, Entra, GitHub, database, and webhook secrets to the selected backend.
- Validate `SECRET_BACKEND=file` or managed secret provider in staging.
- Add secret rotation runbooks.
- Block production startup when placeholder secrets are detected.

### 3. Deployment

- Complete CD for backend, frontend, RedQueen, ARES, and ingestion entrypoints.
- Automate Alembic migrations as a controlled deployment step.
- Add production-ready manifests for every runtime component.
- Add rollback workflow and release tagging.
- Validate probes, resource limits, HPA/PDB, and network policies in staging.

### 4. Security Hardening

- Decide final user onboarding model.
- Restrict public `POST /users/` in enterprise production or move it behind invite/admin flow.
- Replace password reset with a signed, expiring recovery-token workflow.
- Add frontend security headers: CSP, HSTS, frame options, referrer policy, and permissions policy.
- Verify Redis-backed rate limit, replay guard, and kill switch across multiple replicas.

### 5. Enterprise Integrations

- Connect one real identity provider path, starting with Entra.
- Connect one real DevSecOps provider path, starting with GitHub/GHAS or the chosen pipeline provider.
- Connect one real SOC/SIEM export path, starting with Sentinel, Wazuh, QRadar, or a signed SOC webhook.
- Select production LLM gateway/model provider.
- Select final RAG/vector backend: SQL/local, pgvector, Qdrant, Azure AI Search, or equivalent.

### 6. Production Validation

- Run staging end-to-end deployment from clean checkout.
- Run tenant isolation tests.
- Run backup and restore drill.
- Run rollback drill.
- Run multi-replica smoke tests.
- Run basic load test against auth, monitoring, ingestion, and SecOps endpoints.
- Run incident-response drill with kill switch and human approval path.

## Exit Criteria

- CI and CD are green from a clean branch.
- Production secrets are not stored in repo or plain runtime env placeholders.
- Full stack deploys from automation, including frontend and all backend services.
- Migrations run safely against staging and production.
- Managed Postgres and Redis are validated.
- At least one real integration is live for Identity, DevSecOps, and SOC/SIEM.
- Backup, restore, rollback, and incident workflow have been tested and documented.

## Suggested Order

1. Secrets backend and production config gate.
2. Managed Postgres and Redis staging deployment.
3. Full CD for backend, frontend, and service entrypoints.
4. User onboarding and password recovery hardening.
5. Entra, DevSecOps, and SOC/SIEM real integrations.
6. Multi-replica, backup/restore, rollback, and incident drills.

