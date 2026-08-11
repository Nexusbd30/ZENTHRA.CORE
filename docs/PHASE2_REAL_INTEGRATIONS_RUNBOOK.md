# Phase 2 Real Integrations Runbook

This runbook defines the minimum production setup for the Phase 2 backend integration gates.

## Entra Graph

- Set `ENTRA_GRAPH_ENABLED=true`.
- Set `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`, `ENTRA_GRAPH_SCOPE`.
- Keep `ENTRA_GRAPH_BASE_URL=https://graph.microsoft.com/v1.0`.
- Configure only the Graph permissions required by enabled actions:
  - revoke sessions: user/session invalidation permission.
  - MFA challenge: Conditional Access or authentication method policy capability.
  - degrade privileges: group membership write for configured group IDs.
- Verify readiness with `GET /api/v1/identity/providers/entra/readiness`.

## Redis

- Set `RATE_LIMIT_BACKEND=redis`.
- Set `REPLAY_GUARD_BACKEND=redis`.
- Set `REDIS_URL` and `REDIS_KEY_PREFIX`.
- Verify readiness with `GET /api/v1/secops/readiness/redis`.

## GitHub Actions / GHAS

- Set `GITHUB_API_BASE_URL=https://api.github.com`.
- Set `GITHUB_TOKEN` through the configured secret backend.
- Optionally set `GITHUB_DEFAULT_OWNER`.
- Set `GITHUB_TOKEN_SECRET_NAMES` before enabling `revoke_pipeline_token`.
- Verify readiness with `GET /api/v1/secops/providers/github_actions/readiness`.

## SOC Webhook

- Set `SOC_WEBHOOK_URL` to an HTTPS endpoint.
- Set `SOC_WEBHOOK_TOKEN` and `SOC_WEBHOOK_HMAC_SECRET` through the configured secret backend.
- Verify readiness with `GET /api/v1/secops/readiness/soc-webhook`.
- Send controlled exports with `POST /api/v1/secops/security/events/export` using `send=true`.

## Sentinel and Wazuh Ingestion

- Sentinel endpoint: `POST /api/v1/ingestion/events/sentinel`.
- Wazuh endpoint: `POST /api/v1/ingestion/events/wazuh`.
- Verify readiness with `GET /api/v1/secops/readiness/ingestion`.

## Secret Backend

- Production must not use `SECRET_BACKEND=env`.
- Use `SECRET_BACKEND=file` or a managed equivalent wired through the same secret access contract.
- Set `SECRET_FILE_DIR` to the mounted secret directory.
- The bundled K8s manifests set `SECRET_BACKEND=file`, mount `aresx-secrets` at `/run/secrets/aresx`, and use that path as `SECRET_FILE_DIR`.
- Verify readiness with `GET /api/v1/secops/readiness/secrets`.

## Execution Preflight

Before any real provider execution, call `POST /api/v1/secops/execution/preflight` with:

- `provider`
- `action_type`
- `execution_controls.dry_run`
- `execution_controls.change_ticket` when `dry_run=false`

Real mode is not valid unless provider readiness, action capability, explicit mode, and change-ticket checks pass.
