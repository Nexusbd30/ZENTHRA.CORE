# Production Readiness Checklist

## CI/CD
- `CI` workflow in `.github/workflows/ci.yml`
  - Backend: `ruff`, `mypy`, `pytest` with coverage gate (`--cov-fail-under=65`)
  - Frontend: `npm run lint`, `npm run build`
- `CD` workflow in `.github/workflows/cd.yml`
  - Builds and pushes image to GHCR
  - Deploys hardened manifests in `infra/k8s`

## Required GitHub Secrets
- `KUBE_CONFIG_DATA` (base64 kubeconfig)

## Security
- No real credentials in committed templates:
  - `.env.example`
  - `infra/k8s/secrets.yaml`
- Bootstrap admin disabled by default in production config:
  - `BOOTSTRAP_ADMIN_ENABLED=false`

## Infrastructure Hardening
- K8s deployments include:
  - `readinessProbe` and `livenessProbe`
  - non-root execution and dropped Linux capabilities
  - resource requests/limits
  - fixed image tag (no `latest`)
- Added:
  - `infra/k8s/hpa.yaml`
  - `infra/k8s/networkpolicy.yaml`
  - `infra/k8s/pdb.yaml`

## Runtime
- Docker image runs as non-root user and has healthcheck.

## Current Known Risk
- Test coverage is currently `65%` and critical modules still need deeper tests:
  - `app/services/correlation_engine.py`
  - `app/routers/monitoring.py`
