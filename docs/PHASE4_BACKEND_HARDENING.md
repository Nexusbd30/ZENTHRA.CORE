# Phase 4 Backend Hardening and Code Intelligence

Phase 4 remains backend-only. It closes the current hardening increment and
introduces static code intelligence before any frontend implementation.

## Objectives

1. Align CI quality gates with the documented 90% backend coverage baseline.
2. Make deployment configuration reproducible and portable.
3. Require externally managed Kubernetes secrets instead of applying placeholders.
4. Preserve safe defaults until real providers pass readiness and preflight.
5. Introduce a non-executing architecture analysis contract for the backend.
6. Prepare strict tenant policy persistence and live-provider validation as later gates.

## Phase Status

Phase 4 is ready for closure once the validation gates pass. Frontend work remains
explicitly out of scope.

Completed increments:

- Static code intelligence contract and restricted analysis scope.
- CI coverage gate aligned to 90%.
- Reproducible observability container versions and portable Prometheus secret mount.
- External ownership requirement for Kubernetes secrets.
- Restricted RedQueen, ARES, and ingestion process entrypoints.
- Safe deployment migration order documented.

Current validation baseline:

- Test suite: `252 passed`.
- Coverage: `90.24%`.
- Ruff: passing.
- Mypy: passing.

Validation command:

```powershell
.\venv\Scripts\python.exe -m pytest -q --cov=app --cov-report=term --cov-fail-under=90
```

## Closed Phase 4 Scope

Phase 4 closes the backend-only platform hardening baseline:

- NexusOps platform map and readiness contracts.
- BlackNode security gateway as the ARES validation boundary.
- Static code intelligence contract for backend architecture analysis.
- Restricted RedQueen, ARES, and ingestion ASGI entrypoints.
- Kubernetes manifests prepared for restricted ARES and ingestion services.
- CD keeps the compatible full API as the external control plane.
- Documentation for safe deployment migration and provider activation.

## Remaining Work Split

The remaining project work is split into two phases after Phase 4.

### Phase 5 - Production Activation

Purpose: turn the controlled pilot backend into a production-capable backend with
real providers, distributed safety state, and strict tenant persistence.

Scope:

- Keep the compatible full API as the external control plane.
- Validate restricted entrypoints and route ownership in CI.
- Add internal service routing and least-privilege NetworkPolicies.
- Keep split deployments disabled in CD until rollback validation passes.
- Move kill-switch state from process memory to Redis-backed storage.
- Preserve fail-closed behavior when Redis is unavailable.
- Persist actor, reason, timestamp, and state transition evidence.
- Enable horizontal ARES scaling only after distributed-state validation.
- Persist tenant policies and provider assignments.
- Bind tenant context to repository reads and writes.
- Reject missing or mismatched tenant context in strict mode.
- Add tenant-scoped audit and readiness evidence.
- Extract correlation into a single-owner worker entrypoint.
- Replace direct cross-domain Python calls where separation requires network boundaries.
- Version internal request, event, and evidence contracts.
- Define retry, idempotency, timeout, and dead-letter behavior.
- Validate one Identity provider, one DevSecOps provider, and one SOC export target.
- Select and validate the LLM gateway and vector retrieval backend.
- Keep readiness, preflight, approval, change-ticket, and audit gates mandatory.

Exit criteria:

- All ARES replicas observe the same kill-switch state.
- Redis outage prevents unsafe execution.
- Cross-tenant access tests fail closed in strict mode.
- Background jobs have one declared owner.
- Controlled end-to-end provider runs produce complete evidence.
- Provider failures fail closed or degrade safely.
- No committed or plaintext production secrets.

### Phase 6 - Product And Operations Closure

Purpose: finish the operator-facing product, IaC, observability, and production
operations story after backend activation gates are proven.

Scope:

- Add frontend SOC/SecOps command center workflows.
- Add Terraform or selected IaC once deployment targets are fixed.
- Replace placeholder Kubernetes secret workflow with the selected secret manager.
- Add service-level dashboards, alerts, SLOs, and runbooks.
- Validate backup, restore, migration, rollback, and incident procedures.
- Run load, resilience, dependency-failure, and security validation.
- Decide final monolith-versus-services deployment posture from measured evidence.

Exit criteria:

- Production readiness checklist has no unowned critical gaps.
- CI/CD, observability, recovery, and security gates pass.
- Operator workflows cover posture, cases, RedQueen decisions, ARES executions,
  tenant/provider setup, policies, and approvals.
- Final deployment topology is documented and reproducible.

## Code Intelligence Contract

Contract: `zenthra.code_architecture.v1`

Endpoints:

- `GET /api/v1/code-intelligence/status`
- `POST /api/v1/code-intelligence/analyze`

The analyzer:

- Is restricted to Python files under `app/`.
- Uses Python AST parsing and never imports or executes target modules.
- Inventories domains, components, routes, imports, and execution points.
- Produces an internal dependency graph and basic execution-risk findings.
- Does not read `.env`, databases, secrets, frontend files, or arbitrary paths.

Example request:

```json
{
  "scope": "app",
  "include_private": false
}
```

## Current Runtime Architecture

The production image can still run one compatible FastAPI monolith containing
ingestion, RedQueen, ARES, SecOps, Identity, Intelligence, monitoring, and code
intelligence. Restricted process entrypoints are now available for gradual
separation:

- `app.entrypoints.redqueen:app`
- `app.entrypoints.ares:app`
- `app.entrypoints.ingestion:app`

Each restricted entrypoint exposes only system health, metrics, process status, and
its owned domain routes. Restricted profiles do not register CORS and do not own the
correlation scheduler. `/process/status` requires internal monitor-token or admin
authentication. Swagger, ReDoc, and OpenAPI endpoints are disabled on restricted
processes. They use `app.process_factory` and do not import or construct the full
`app.main` application.

`deployment-ares.yaml` and `deployment-ingestion.yaml` now use their restricted
entrypoints. They remain outside CD until service routing, persistent ownership, and
end-to-end validation are complete.

ARES remains limited to one replica because kill-switch state is currently local to
the process. Horizontal ARES scaling requires a distributed kill-switch store.

Initial static inventory:

- 161 Python components under `app/`.
- 20 backend domains.
- 137 API route declarations.
- 351 direct internal dependency edges.
- 6 explicit application lifecycle or execution entrypoints.

Largest domains by component count:

- `core`: 20
- `redqueen`: 15
- `models`: 14
- `ingestion`: 13
- `ares`: 12
- `intelligence`: 10

The main architectural concentration is `app.main`, which owns route composition,
startup and shutdown events, and the correlation worker. A future service split
must extract process entrypoints and ensure only one owner runs each background
worker.

## Separation Safety Boundaries

Current guarantees:

- Restricted HTTP route surfaces per RedQueen, ARES, and ingestion process.
- Restricted processes do not construct or import the full monolith application.
- No correlation worker ownership in restricted processes.
- Internal process status requires authentication.
- Internal profiles do not expose browser CORS.
- ARES is single-replica while kill-switch state is process-local.

Not yet guaranteed:

- Independent databases or schemas per domain.
- NetworkPolicy routing between the restricted services.
- Distributed ARES kill-switch state.
- Event-driven contracts replacing direct Python service calls.
- Independent migrations and release cadence.

## Safe Deployment Migration

The currently deployed `deployment-redqueen.yaml` remains the compatible full API
surface. Replacing it directly with the restricted RedQueen entrypoint would remove
existing auth, SecOps, Identity, ARES, and ingestion routes and is therefore unsafe.

Migration order:

1. Keep the compatible full API as the external control-plane entrypoint.
2. Deploy restricted ARES and ingestion services only after internal service routing
   and NetworkPolicies are defined.
3. Move direct domain calls behind versioned internal contracts or events.
4. Move ARES kill-switch state to Redis or another distributed store.
5. Deploy restricted RedQueen and route its API prefix explicitly.
6. Extract correlation into a single-owner worker process.
7. Retire the full API only after route-by-route traffic migration and rollback tests.

## Safe Provider Activation

Repository defaults remain `local_stub` and `dry_run`. Production activation is an
environment concern and requires:

1. Externally managed secrets.
2. Provider readiness passing.
3. Action preflight passing.
4. Signed human approval and change ticket where required.
5. Controlled end-to-end validation with audit evidence.

## Remaining Gates

- Persist tenant policies and enforce strict tenant isolation in repositories.
- Select and validate the real LLM gateway and vector retrieval backend.
- Validate one identity, one DevSecOps, and one SOC provider end to end.
- Replace placeholder Kubernetes secret workflow with the selected secret manager.
- Decide whether to keep the monolith or create independent RedQueen, ARES, and
  ingestion process entrypoints.
