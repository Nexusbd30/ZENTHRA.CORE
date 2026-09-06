# VAELQORIX Production Stage 1 Plan

## Objective

Move VAELQORIX from local pre-production validation to a real sandbox-proven autonomous defense system.

The target is not to add more isolated AI features. The target is to prove one complete, governed, auditable defensive execution path:

```text
Threat/Event
-> Attack Analysis
-> RedQueen verdict
-> ARES validation
-> Human approval
-> Provider dry-run
-> Provider live execution in sandbox
-> Read-back verification
-> Evidence bundle
-> Audit-chain verification
```

Recommended first provider path: DNS firewall.

Reason: DNS blocking has a smaller sandbox blast radius than endpoint isolation or identity lockdown, and the repository already contains DNS firewall, RedQueen, ARES, audit, approval, and SecOps readiness foundations.

## Current Code Baseline

Current local verification state:

```text
Backend tests: 387 passed
Backend coverage: 99%
Frontend lint: passed
Frontend production build: passed
```

Current posture:

- The backend is a modular FastAPI monolith.
- The frontend is React/Vite.
- RedQueen can issue governed verdicts.
- ARES can validate, execute, roll back, audit, and expose evidence.
- SecOps readiness, tenant policies, provider preflight, SOC event materialization, and controlled export paths exist.
- Attack analysis, ARES hunter trace, autonomy maturity, and defensive CTF lab are present in the current working tree.
- The system is not production-proven until real sandbox/provider validation is completed.

## Hardware And Environment Requirements

### Local Engineering Lab

Use this for coding, tests, Docker Compose, local provider simulation, and frontend/backend development.

```text
CPU: 12-16 cores
RAM: 64 GB
Storage: 2 TB NVMe SSD
GPU: optional; only needed for local LLM inference
Network: wired 1 Gbps
OS: Windows 11 Pro with WSL2 or Linux workstation
```

The GPU is not required for the cybersecurity control plane. Use external LLM/provider gateways unless local inference is a deliberate requirement.

### Recommended Pre-Production Lab

Use this to prove reliability, multi-replica behavior, Redis shared state, provider validation, and monitored execution.

```text
Kubernetes cluster:
  Nodes: 3
  CPU per node: 8-16 cores
  RAM per node: 32-64 GB
  Storage per node: 1 TB NVMe SSD
  Network: 1-10 Gbps

PostgreSQL:
  Preferred: managed Postgres
  Alternative: dedicated database node
  CPU: 8 cores
  RAM: 32 GB
  Storage: 1-2 TB NVMe SSD
  Requirement: backup and restore tested

Redis:
  Preferred: managed Redis
  Alternative: dedicated Redis cluster
  CPU: 4-8 cores
  RAM: 16-32 GB
  Storage: SSD if persistence/AOF is enabled
  Requirement: shared state validation across backend replicas

Observability:
  CPU: 8 cores
  RAM: 32 GB
  Storage: 2-4 TB SSD depending on retention
  Components: Prometheus, Grafana, Alertmanager, Blackbox Exporter
```

### Required Infrastructure Components

- Kubernetes cluster or equivalent container orchestration.
- Managed or dedicated PostgreSQL.
- Managed or dedicated Redis.
- Prometheus, Grafana, Alertmanager, and Blackbox Exporter.
- Secure isolated lab network.
- Managed switch with VLAN support.
- Firewall/router for the lab boundary.
- Backup target such as NAS or object storage.
- Secret storage: file-backed for lab, managed secret system for pre-production.
- One real sandbox provider:
  - DNS firewall provider, recommended first.
  - Microsoft Entra sandbox tenant.
  - GitHub/GHAS test organization.
  - SIEM/SOC test destination.

## Stage Work Plan

## Repo-Local Coding Status

Completed before hardware setup:

- DNS firewall provider contract boundary.
- Sandbox DNS firewall provider with apply, idempotent replay, read-back verification, remove, and verification-failure behavior.
- ARES DNS action execution split into resolve, apply, verify, verification_failed, and rollback paths.
- DNS provider rule ID persistence through the existing DNS firewall rule model.
- Attack Analysis UI path extended from verdict generation into ARES dry-run execution and evidence preview.
- Frontend API helper for `POST /api/v1/ares/execute`.
- RedQueen Brain lifecycle endpoint added at `POST /api/v1/brain/lifecycle`.
- RedQueen operator chatbot endpoint added at `POST /api/v1/brain/chat`.
- Brain lifecycle connects ARESX ingest, attack analysis, RedQueen verdict, ARES dry-run execution, and evidence in one backend contract.
- AI command center now exposes the brain lifecycle chain and a `Run Brain` dry-run control.
- AI command center now includes a RedQueen Chat panel that can request verdicts or route ARESX dry-run orders through the governed brain endpoint.
- Backend and frontend tests updated for the new contract.

Current verified gates:

```text
Backend full suite: 392 passed
Backend coverage: 99%
Backend Ruff: passed
Frontend tests: 34 passed, 3 skipped
Frontend lint: passed
Frontend production build: passed
```

Remaining work in this stage requires external environment setup:

- Real DNS provider or sandbox endpoint credentials.
- HTTPS provider callback.
- Multi-replica Redis validation.
- Kubernetes/pre-production deployment validation.
- Real rollback and provider read-back evidence.

### 1. Freeze Current Passing State

Actions:

- Review current uncommitted source changes.
- Keep source changes needed for attack analysis, ARES hunter trace, control maturity, and CTF lab.
- Remove or ignore generated frontend coverage output unless intentionally tracked.
- Commit the current passing baseline.
- Tag the baseline.

Suggested tag:

```text
phase-attack-analysis-control-baseline
```

Exit criteria:

```text
git status is clean except intentionally ignored local files
backend tests pass
frontend lint passes
frontend build passes
```

### 2. Define DNS Firewall Provider Contract

Required provider contract:

```text
POST /actions/dns_firewall_block
POST /actions/dns_firewall_unblock
GET  /actions/dns_firewall_rules/{id}
```

Required request fields:

```text
tenant_id
target
action_type
idempotency_key
change_ticket
requested_by
dry_run
```

Required provider response fields:

```text
provider_request_id
provider_rule_id
status
verification_url or read_back_reference
evidence
error_code
```

Security requirements:

- Authenticated HTTPS only.
- Shared token or signed request.
- Tenant ID required.
- Change ticket required for live execution.
- Idempotency key required.
- Unsafe targets rejected.
- Provider-side read-back supported.
- Rollback or compensation path supported.

### 3. Build Provider Sandbox Harness

Add a provider harness that behaves like a real external DNS control plane.

Expected behavior:

- Persist applied DNS rules.
- Reject unsafe targets.
- Reject missing tenant IDs.
- Reject duplicate unsafe requests.
- Enforce idempotency.
- Return provider evidence.
- Support read-back verification.
- Support unblock/rollback.

Suggested code areas:

```text
app/dns_firewall/providers.py
app/dns_firewall/service.py
app/actions/network.py
tests/unit/test_dns_firewall_provider_contract.py
```

This harness is for contract validation. It must not become a production mock path.

### 4. Harden ARES Execution States

ARES must not mark an action as verified only because dispatch succeeded.

Required execution states:

```text
planned
approved
dispatched
applied
verified
failed
rolled_back
verification_failed
```

Every real or sandbox action must persist:

```text
provider_request_id
provider_rule_id
idempotency_key
verification_result
evidence_hash
rollback_payload
duration_ms
actor
tenant_id
change_ticket
```

Exit criteria:

- Execution result records distinguish dispatch success from provider verification.
- Verification failure is visible in API response, database row, evidence bundle, and audit trail.
- Rollback records reason, actor, time, previous state, and result hash.

### 5. Connect Attack Analysis To Operator Flow

Frontend workflow:

```text
Attack Analysis page
-> select entity
-> view timeline and causal chain
-> issue RedQueen verdict
-> preview ARES plan
-> generate approval evidence
-> run dry-run execution
-> inspect execution evidence
-> inspect audit verification
```

Live execution must stay blocked unless all gates are true:

```text
provider_ready=true
human_approved=true
dry_run=false
change_ticket present
kill_switch off
tenant policy allows action
provider supports action
read_back available
```

Suggested frontend areas:

```text
VAELQORIX.XDR_COMMAND/src/modules/attack-analysis/
VAELQORIX.XDR_COMMAND/src/modules/ai/AIPage.jsx
VAELQORIX.XDR_COMMAND/src/api/vaelqorixApi.js
```

### 6. Add Multi-Replica Reliability Validation

Prove Redis-backed shared state works across replicas.

Required checks:

- ARES kill switch works across two backend replicas.
- Replay guard blocks duplicate execution across replicas.
- Rate limiting is shared.
- Idempotency prevents duplicate DNS block.
- Audit chain remains valid.
- Provider read-back is consistent.

Recommended sequence:

1. Docker Compose multi-replica validation.
2. Kubernetes pre-production validation.
3. Failure test: stop one backend replica during execution.
4. Failure test: Redis unavailable must fail closed for protected operations.

### 7. Run Production Readiness Gates

Required gates:

```text
Real or sandbox provider execution: passed
Read-back verification: passed
Rollback/compensation: passed
Audit chain verification: passed
Human approval enforcement: passed
Kill switch fail-closed: passed
Tenant policy enforcement: passed
Frontend dry-run/live gating: passed
Backend full tests: passed
Frontend lint/build: passed
```

### 8. Update Documentation And Closure Status

Update:

```text
docs/PROJECT_CLOSURE_STATUS.md
docs/PRODUCTION_READY_CHECKLIST.md
docs/PRODUCTION_RELEASE_RUNBOOK.md
docs/PHASE6_FRONTEND_BACKEND_MAP.md
```

Add evidence from:

- Test output.
- Provider sandbox execution.
- Read-back verification.
- Audit-chain verification.
- Rollback test.
- Multi-replica Redis validation.

## Safety Boundary

The system must not perform unrestricted internet tracing or autonomous external pursuit.

Allowed model:

```text
authorized sensors
owned assets
provider APIs
tenant-approved logs
threat intelligence feeds
auditable evidence
human approval for disruptive action
```

Disallowed model:

```text
unrestricted internet tracing
external targeting without authorization
autonomous offensive action
unapproved disruptive execution
```

RedQueen and ARES should trace activity through owned telemetry and authorized integrations only.

## Definition Of Done

Production Stage 1 is complete when this demonstration works end to end:

```text
A suspicious entity is detected.
Attack Analysis reconstructs the timeline.
RedQueen issues a signed verdict.
ARES validates the verdict.
Operator approves the action.
ARES applies a DNS block through the provider contract.
ARES verifies the block by reading provider state.
ARES records evidence and audit trail.
A duplicate request does not execute twice.
Rollback is available and recorded.
The audit chain verifies successfully.
```

The stage is not complete if the system only passes unit tests. It must pass the provider execution and verification path.

## Execution Order

1. Clean and commit the current passing baseline.
2. Implement the DNS firewall provider contract harness.
3. Harden ARES execution states and evidence payloads.
4. Add provider contract tests.
5. Wire the frontend operator flow.
6. Run backend and frontend quality gates.
7. Run multi-replica Redis/idempotency validation.
8. Execute sandbox DNS block, read-back verification, and rollback.
9. Update docs with evidence.
10. Tag the stage as complete only after the demonstration passes.
