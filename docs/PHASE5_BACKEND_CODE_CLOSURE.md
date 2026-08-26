# Phase 5 Backend Code Closure

This document closes the backend-code portion of Phase 5 that can be completed
inside this repository without live external provider credentials.

It does not claim full production activation. Production activation still requires
real secrets, live provider permissions, SIEM/SOC destinations, and environment
validation outside the local workspace.

## Validation Baseline

- Backend suite: `276 passed`.
- Coverage total: `93.51%`.
- Ruff: passing.
- Mypy: passing.
- Text encoding guard: passing.
- Alembic has one head: `c2d3e4f5a6b7`.
- Alembic `upgrade head` validates against a temporary SQLite database.

Validation commands:

```powershell
.\venv\Scripts\python.exe -m pytest -q --cov=app --cov-report=term --cov-fail-under=90
.\venv\Scripts\python.exe -m ruff check app tests
.\venv\Scripts\python.exe -m mypy app
.\venv\Scripts\python.exe scripts\check_text_encoding.py
.\venv\Scripts\alembic.exe heads
```

## Completed Backend Code Gates

- ARES kill-switch supports Redis-backed distributed state.
- Redis kill-switch failures fail closed and prevent unsafe ARES execution.
- Docker Compose enables Redis-backed ARES kill-switch state by default.
- Tenant/provider policies are persisted in `policy_rules`.
- Tenant policy readiness is exposed in enterprise readiness.
- SecOps exposes tenant policy management endpoints:
  - `GET /api/v1/secops/tenant-policies`
  - `POST /api/v1/secops/tenant-policies`
- Password validation requires at least 10 characters for create, update, and reset.
- Backend test isolation no longer depends on cross-test database leftovers.
- Restricted RedQueen, ARES, and ingestion entrypoints expose explicit route surfaces
  under the current FastAPI version.
- GitHub provider rejects empty repository targets even when a default owner exists.
- `NetworkMonitor` no longer performs duplicate initial counter reads that can hang
  the backend test suite.

## Current Runtime Posture

The compatible full FastAPI API remains the external control plane. Restricted
RedQueen, ARES, and ingestion entrypoints remain available for gradual separation,
but split-service production rollout still requires service routing and rollback
validation.

ARES can be horizontally validated only in an environment where
`ARES_KILL_SWITCH_BACKEND=redis` points to a reachable Redis instance shared by all
ARES replicas. If Redis is configured but unavailable, ARES fails closed.

## Remaining External Production Gates

- Apply Alembic migrations in the target database.
- Configure managed production secrets outside Git.
- Validate shared Redis from multiple ARES processes or replicas.
- Activate one live Identity provider, such as Microsoft Entra, with least-privilege
  credentials.
- Activate one live DevSecOps provider, such as GitHub Actions/GHAS, Azure DevOps,
  or GitLab CI.
- Activate one SIEM/SOC export destination, such as Microsoft Sentinel or a generic
  webhook.
- Select and validate the real LLM gateway.
- Decide whether SQL-backed enterprise memory is enough for pilot, or replace
  retrieval with pgvector, Qdrant, or Azure AI Search.
- Enforce strict tenant isolation across all critical repositories and API read/write
  paths.
- Add production SLOs, dashboards, alerts, backup/restore, incident and rollback
  runbooks.
