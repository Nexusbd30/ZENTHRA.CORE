# Preproduction To Production Plan

## Current Target

All production-facing work now lands on the `preproduc` branch. `main` remains untouched until the final release merge.

## What This Branch Must Prove

- Backend and frontend quality gates pass from a clean checkout.
- Python and frontend dependency audits report no known vulnerabilities.
- The text encoding guard reports zero mojibake findings.
- Public user registration is disabled by configuration in production.
- Runtime secrets are read from a secret backend, not committed values.
- Backend API, frontend, RedQueen, ARES, ingestion, migrations, ingress, HPA, PDB, and network policies are deployable as one preproduction unit.

## Required External Resources

- Managed Postgres.
- Managed Redis.
- Cluster secret `aresx-secrets`, populated from the selected secret manager.
- TLS secret `vaelqorix-tls`.
- DNS record for the preproduction hostname.
- Real credentials for the first Identity, DevSecOps, SOC/SIEM, LLM, and vector/RAG integrations selected for pilot.

## Preproduction Configuration Gate

Preproduction uses production-grade settings before the final `main` release. Use
`.env.preproduc.example` as the contract for GitHub environment variables and secret-manager
entries.

Before deploying, run:

```bash
python scripts/preproduction_readiness.py
```

For checking the committed template only:

```bash
python scripts/preproduction_readiness.py --env-file .env.preproduc.example --allow-placeholders
```

The real preproduction run must fail when it finds localhost endpoints, SQLite, placeholder
secrets, public registration, in-memory rate limit/replay/kill-switch storage, local AI, local
vector storage, or non-HTTPS CORS origins.

## Deployment Flow

1. Push to `preproduc` or run the Preproduction workflow manually.
2. CI validates backend, frontend, dependency audits, tests, type checks, and encoding.
3. Backend and frontend images are pushed to GHCR.
4. Kubernetes manifests are applied.
5. Alembic migrations run as a Kubernetes Job.
6. Deployments roll out for API, RedQueen, ARES, ingestion, and frontend.
7. Public smoke tests verify `/health`, `/ready`, RedQueen status, ARES status, and connector readiness.

## Production Exit Criteria

- `preproduc` workflow is green.
- Staging/preproduction smoke test passes through the public ingress.
- Tenant isolation test passes.
- Redis-backed rate limit, replay guard, and kill switch are validated with multiple replicas.
- Backup and restore drill is documented.
- Rollback drill is documented.
- Incident drill validates human approval and kill-switch behavior.
- At least one real integration is live for Identity, DevSecOps, and SOC/SIEM.

## Final Release Path

1. Freeze `preproduc`.
2. Merge required phase branches into `preproduc`, if any remain.
3. Re-run the full validation workflow.
4. Merge `preproduc` into `main`.
5. Tag the release.
6. Deploy production from `main`.
