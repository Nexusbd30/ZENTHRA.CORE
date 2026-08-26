# Phase 2 Closure

Phase 2 closes the real-integration hardening work for the backend. The system is ready to move into Enterprise AI work, with external providers governed through readiness checks, execution preflight, ARES validation, audit evidence, and contract tests.

## Closure Scope

1. Real integration paths are connected through authenticated provider adapters.
2. Readiness endpoints are stable contracts for provider setup checks.
3. Execution preflight is required before real provider execution.
4. `dry_run` and real mode are separated by explicit execution controls.
5. Real disruptive execution requires `change_ticket` and signed human approval when required by RedQueen/ARES policy.
6. Sentinel/Wazuh, GitHub/GHAS, Redis, SOC webhook, and secret backend paths are covered by readiness and tests.
7. ARES execution persists execution result evidence and audit-chain records.
8. Backend coverage is maintained at 90% with contract tests around Phase 2 behavior.
9. The backend is ready for Phase 3 Enterprise AI and later frontend operations.

## Stable Provider Contracts

Identity:

- Entra readiness: `GET /api/v1/identity/providers/entra/readiness`
- Entra webhook ingestion: `POST /api/v1/identity/providers/entra/events`
- Identity provider preflight: `POST /api/v1/identity/providers/{provider}/preflight`

SecOps and DevSecOps:

- All integration readiness: `GET /api/v1/secops/integrations/readiness`
- GitHub Actions readiness: `GET /api/v1/secops/providers/github_actions/readiness`
- Generic provider readiness: `GET /api/v1/secops/providers/{provider}/readiness`
- Redis readiness: `GET /api/v1/secops/readiness/redis`
- SOC webhook readiness: `GET /api/v1/secops/readiness/soc-webhook`
- Secret backend readiness: `GET /api/v1/secops/readiness/secrets`
- Sentinel/Wazuh readiness: `GET /api/v1/secops/readiness/ingestion`
- Execution preflight: `POST /api/v1/secops/execution/preflight`

Execution and evidence:

- ARES lifecycle from threat: `POST /api/v1/ares/lifecycle/from-threat/{threat_id}`
- ARES lifecycle from event: `POST /api/v1/ares/lifecycle/from-event/{event_id}`
- ARES audit verification: `GET /api/v1/ares/audit/verify`
- SOC case export: `POST /api/v1/secops/security/events/export`

## Real Mode Rules

Real execution is allowed only when all of the following hold:

- Provider readiness reports the required configuration.
- Provider action preflight reports the action as supported.
- Execution controls explicitly include `dry_run=false`.
- Disruptive actions include `change_ticket` or threat traceability.
- Human approval evidence is signed and matches the verdict when the verdict requires human approval.
- ARES validation passes signature, policy matrix, kill switch, provider capability, MCP action policy, MCP tool policy, and audit evidence requirements.

`dry_run=true` remains the default safe operator preview path.

## Verified Integration Paths

Redis:

- Rate limit and replay guard have Redis-backed stores.
- Readiness reports selected backend, URL validity, distributed status, and ping result when Redis is selected.

GitHub/GHAS:

- GitHub Actions provider supports repository resolution, environment approval gates, artifact quarantine, deployment block, and configured token-secret revocation.
- Readiness verifies API URL, token presence, configured owner, token secret names, and supported capability payload.

Sentinel/Wazuh:

- Sentinel and Wazuh adapters normalize payloads into `ThreatModel`.
- Controlled E2E verifies Sentinel ingestion into threat lifecycle.

SOC webhook:

- `soc_case.v1` export can send signed generic webhook payloads.
- Readiness verifies HTTPS URL, bearer token presence, HMAC secret presence, timeout, and contract.

Secret backend:

- Secret readiness reports backend, configured secret names, missing secret names, and production readiness without exposing secret values.

Entra:

- Entra Graph and webhook contracts remain the identity-provider entrypoint.
- Real Graph activation requires least-privilege tenant/client credentials and enabled provider mode.

## Validation Gates

The phase is closed only when these commands pass:

```powershell
.\venv\Scripts\python.exe -m pytest -q
.\venv\Scripts\python.exe -m ruff check app tests
.\venv\Scripts\python.exe -m mypy app
```

Current closed baseline:

- Test suite: `231 passed`
- Coverage: `90%`
- Lint: passing
- Type check: passing

## Phase 3 Entry Criteria

Phase 3 can start because the backend now exposes stable operational contracts for:

- Provider readiness.
- Provider preflight.
- Controlled execution.
- Audit and evidence.
- SIEM/SOC export.
- Identity and DevSecOps signals.

Phase 3 should focus on Enterprise AI: persistent memory, versioned knowledge, stricter MCP context, LLM gateway controls, evaluation, and AI decision traceability.
