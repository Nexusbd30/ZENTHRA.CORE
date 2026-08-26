# Phase 6 Frontend Backend Map

This document tracks the first Product and Operations Closure increment.

The current increment connects the React/Vite frontend to existing backend
contracts. It does not activate external providers, change deployment topology,
or replace the monolith control plane.

## Connected Frontend Surface

- Route: `/dashboard/secops`
- Component: `VAELQORIX.XDR_COMMAND/src/modules/secops/SecOpsPage.jsx`
- API client: `VAELQORIX.XDR_COMMAND/src/api/vaelqorixApi.js`
- Navigation:
  - `VAELQORIX.XDR_COMMAND/src/layouts/DashboardLayout.jsx`
  - `VAELQORIX.XDR_COMMAND/src/components/Sidebar.jsx`

## Endpoint Coverage

| Backend endpoint | Frontend helper | Frontend surface | Operator workflow |
| --- | --- | --- | --- |
| `GET /api/v1/secops/status` | `getSecOpsStatus` | SecOps metrics | Control-plane status |
| `GET /api/v1/secops/posture` | `getSecOpsPosture` | SecOps metrics | Security posture summary |
| `GET /api/v1/secops/enterprise/readiness` | `getSecOpsEnterpriseReadiness` | Readiness panel | Enterprise gates and tenant-policy readiness |
| `GET /api/v1/secops/integrations/readiness` | `getSecOpsIntegrationsReadiness` | Readiness panel | External integration gates |
| `GET /api/v1/secops/providers` | `listSecOpsProviders` | Provider preflight | Provider/action selection |
| `GET /api/v1/secops/providers/{provider}/readiness` | `getSecOpsProviderReadiness` | API-ready helper | Provider-specific readiness |
| `POST /api/v1/secops/execution/preflight` | `runSecOpsExecutionPreflight` | Provider preflight | Dry-run execution gate |
| `GET /api/v1/secops/security/events` | `getSecOpsSecurityEvents` | Security events table | SOC event review |
| `POST /api/v1/secops/security/events/materialize` | `materializeSecOpsSecurityEvents` | SOC/SIEM export panel | Materialize integration abuse events |
| `POST /api/v1/secops/security/events/export` | `exportSecOpsSecurityEvents` | SOC/SIEM export panel | Generate export payload in preview mode |
| `POST /api/v1/secops/security/events/{id}/lifecycle` | `runSecOpsSecurityEventLifecycle` | Security events table | Dry-run lifecycle from SOC event |
| `GET /api/v1/secops/tenant-policies` | `listTenantPolicies` | Policies panel | Review tenant/provider policy rules |
| `POST /api/v1/secops/tenant-policies` | `upsertTenantPolicy` | Tenant policy form | Create/update tenant policy |

## Existing ARES/RedQueen Surface

The existing `AIPage` remains a focused RedQueen and ARES surface:

- RedQueen status, stats, verdict list and approval/rejection.
- ARES status, kill-switch, executions, rollback and audit verification.
- ARES ingestion sources and stats.

The SecOps Command Center links the SOC/SecOps backend layer to those existing
governed execution paths by exposing lifecycle actions in dry-run mode.

## Phase 6 Closure Coverage

The current frontend now covers the Phase 6 product workflow baseline:

- SecOps posture and readiness overview.
- Provider/action preflight before sensitive lifecycle execution.
- Provider readiness detail payload after preflight.
- Security event review.
- Security event materialization.
- SOC/SIEM export preview.
- SOC/SIEM send action blocked unless readiness indicates a live destination.
- Tenant policy creation/update.
- Tenant policy review.
- RedQueen verdict selection from the SecOps workspace.
- ARES approval evidence generation.
- ARES approval list and evidence bundle inspection.
- Security event lifecycle execution kept in dry-run mode from the UI.

This closes the repository-local product integration work. It does not claim
that external providers are active in a real production tenant.

## Validation

Frontend validation for this increment:

```powershell
cd VAELQORIX.XDR_COMMAND
corepack pnpm lint
corepack pnpm build
```

Both commands pass for the current frontend state.

## Remaining Phase 6 Work

- Validate with real external credentials for one identity provider.
- Validate with real external credentials for one DevSecOps provider.
- Validate with a real SOC/SIEM destination.
- Validate shared Redis state across multiple backend replicas.
- Select and validate the final LLM gateway and retrieval backend.
- Add deployment-target-specific IaC only after the target platform is fixed.
- Run load, resilience, backup, restore, rollback and incident drills in the target
  environment.
