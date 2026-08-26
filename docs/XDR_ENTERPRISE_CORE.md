# XDR Enterprise Core

This phase adds the first owned XDR operational core around RedQueen and ARES.

## Native Sensors

Native sensor normalizers live under `app/sensors/`:

- `endpoint_agent`: suspicious processes, outbound callbacks, critical file changes and local auth bursts.
- `network_sensor`: DNS callbacks, suspicious egress, netflow fan-out and lateral movement signals.
- `cloud_sensor`: high-risk cloud control-plane actions and weak session context.
- `k8s_sensor`: Kubernetes audit events, privileged pods and RBAC/service-account changes.

The sensors emit `SensorFinding` objects and ARESX-compatible event payloads.

## Detection Engine

The detection engine under `app/detection/` provides:

- built-in Sigma-lite style rules.
- kill-chain stage mapping.
- IOC enrichment.
- entity graph generation.
- correlation by entity with recommended actions.

## Enterprise Connectors

The connector framework under `app/connectors/` defines provider-grade contracts:

- readiness.
- capability matrix.
- preflight.
- execute-plan/dry-run.
- rollback metadata.
- provider evidence.
- idempotency.

Initial provider modules exist for Palo Alto, Cisco, Fortinet, CrowdStrike, Defender, SentinelOne, Splunk, Sentinel, QRadar, ServiceNow, Jira, OpenShift, RHACS, Quay and Ansible.

## Playbook Engine

The playbook engine under `app/playbooks/` supports JSON playbooks with:

- versioned playbook definitions.
- conditions.
- branching metadata.
- retries.
- approval gates.
- rollback metadata.
- dry-run preview.
- internal marketplace directory under `playbooks/`.

Initial playbook:

- `playbooks/active_defense/aggressive_containment.json`

## Case, Runtime And Compliance

The new product foundations also include:

- `app/cases/`: case creation and legal workflow packaging.
- `app/evidence/`: hashed evidence artifacts and JSON export.
- `app/runtime/`: queue, idempotency, backpressure and dead-letter foundations.
- `app/compliance/`: SOC 2 and ISO 27001 evidence mapping.

## API Surfaces

- `GET /api/v1/sensors/status`
- `POST /api/v1/sensors/normalize`
- `GET /api/v1/detection/status`
- `POST /api/v1/detection/evaluate`
- `GET /api/v1/connectors`
- `GET /api/v1/connectors/{provider}/readiness`
- `POST /api/v1/connectors/{provider}/preflight`
- `POST /api/v1/connectors/{provider}/execute`
- `GET /api/v1/playbooks`
- `POST /api/v1/playbooks/{playbook_id}/preview`
- `POST /api/v1/cases`
- `GET /api/v1/runtime/status`
- `POST /api/v1/runtime/playbooks/enqueue`
- `GET /api/v1/compliance/evidence`

## Current Boundary

This is the owned core and provider contract layer. Live vendor execution still requires real credentials, least-privilege permissions, network allowlists, customer authorization and provider-specific integration tests.
