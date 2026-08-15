# Production Release Runbook

This repo is production-ready only when the `main` workflow can deploy with real
environment values. The workflow intentionally fails before deployment if any
mandatory production contract is missing.

## Required GitHub Environment

Create the `production` environment and require approval before deployment.

Required environment variables:

- `PRODUCTION_HOSTNAME`
- `POSTGRES_HOST`
- `POSTGRES_PORT`
- `POSTGRES_DB`
- `POSTGRES_USER`
- `CORS_ORIGINS`
- `ACTION_EXECUTION_MODE` set to `webhook`, `provider`, or `real`
- `AI_PROVIDER` set to a real provider, not `local_stub`
- `AI_BASE_URL`
- `AI_MODEL`
- `VECTOR_STORE_PROVIDER` set to the selected production backend
- `PROMETHEUS_BASE`
- `ALERTMANAGER_BASE`

Required environment secrets:

- `KUBE_CONFIG_DATA`
- `REDIS_URL`

Required Kubernetes secrets already present in the target namespace:

- `aresx-secrets`
- `vaelqorix-tls`

The `aresx-secrets` secret must contain at least:

- `SECRET_KEY`
- `VAELQORIX_MONITOR_TOKEN`
- `POSTGRES_PASSWORD`
- Provider secrets for the selected Identity, DevSecOps, SOC/SIEM, LLM, and
  action execution integrations.

## Release Flow

1. Freeze `preproduc`.
2. Run local gates:
   - `python scripts/check_text_encoding.py`
   - `python scripts/production_preflight.py`
   - `python -m ruff check app tests scripts`
   - `python -m mypy app`
   - `python -m pip_audit -r requirements.txt`
   - `python -m pytest --cov=app --cov-report=term-missing --cov-fail-under=90`
   - `pnpm audit --prod`
   - `pnpm lint`
   - `pnpm build`
3. Merge `preproduc` to `main`.
4. Tag the release.
5. Let the `Production` workflow build, push, migrate, deploy, and smoke test.

## Production Guardrails

- Public registration is disabled.
- Runtime secrets come from mounted secret files and Kubernetes secrets.
- Redis backs rate limit, replay guard, and ARES kill switch.
- The workflow deploys API, frontend, RedQueen, ARES, ingestion, migrations,
  HPA, PDB, NetworkPolicy, and Ingress as one release.
- The frontend never receives `VAELQORIX_MONITOR_TOKEN`.
- Placeholder hosts and lab providers are rejected before deployment.

## Rollback

Use the previous successful image SHA from GHCR:

```bash
kubectl set image deployment/vaelqorix-api api=ghcr.io/<owner>/vaelqorix-api:<sha>
kubectl set image deployment/redqueen redqueen=ghcr.io/<owner>/vaelqorix-api:<sha>
kubectl set image deployment/ares ares=ghcr.io/<owner>/vaelqorix-api:<sha>
kubectl set image deployment/ingestion ingestion=ghcr.io/<owner>/vaelqorix-api:<sha>
kubectl set image deployment/vaelqorix-frontend frontend=ghcr.io/<owner>/vaelqorix-frontend:<sha>
kubectl rollout status deployment/vaelqorix-api deployment/redqueen deployment/ares deployment/ingestion deployment/vaelqorix-frontend
```
