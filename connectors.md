# VAELQORIX Local Connectors And Competitive Position

Date: 2026-09-13
Scope: local functional state, missing real connectors, telemetry readiness, and competitive analysis vs Cisco XDR, Palo Alto Cortex/XSIAM, and IBM QRadar Suite.

## 1. Current Local State

### Core platform

Status: functional locally.

Running and verified:

- Frontend: http://127.0.0.1:5173
- Backend FastAPI: http://127.0.0.1:8010
- Grafana: http://127.0.0.1:3000
- Prometheus: http://127.0.0.1:9090
- PostgreSQL container: healthy
- Redis container: healthy
- Alertmanager: running
- Blackbox exporter: running
- Windows exporter: running

Backend checks:

- `/health`: OK
- `/ready`: OK
- Admin login: OK
- `/users/me`: OK with real JWT
- Frontend API target: `http://127.0.0.1:8010`

Important: frontend login was failing because `.env.local` was overriding the API URL to port `8011`. That was corrected to `8010`.

### Tests/build already verified

- Frontend tests: passed
- Frontend build: passed
- Backend targeted health/monitoring/hardening tests: passed
- Monitoring production readiness route: passed in current local development mode

## 2. Telemetry State

### Working telemetry

The following telemetry paths are connected locally and working:

- CPU telemetry through Windows exporter
- Memory telemetry through Windows exporter
- Network telemetry through Windows exporter
- Backend health telemetry
- Database readiness telemetry
- Prometheus scrape health
- Alertmanager reachability
- Application logs
- Basic frontend/backend connectivity

Current monitoring diagnostics:

- Overall: up
- Backend: up
- Database: up
- Prometheus: up
- Alertmanager: up
- Windows exporter: up
- Logs: up
- GPU: missing

### GPU telemetry

GPU telemetry is now connected locally through a lightweight NVIDIA exporter.

Prometheus is configured to scrape a GPU exporter at:

```text
127.0.0.1:9400
```

Current source:

```text
nvidia-smi-exporter
```

Detected GPU:

```text
NVIDIA GeForce RTX 2050
```

Verified metrics:

- `up{job="gpu-exporter"} = 1`
- `nvidia_smi_utilization_gpu`
- `nvidia_smi_utilization_gpu_ratio`
- `nvidia_smi_memory_used_bytes`
- `nvidia_smi_memory_total_bytes`
- `nvidia_smi_temperature_gpu_celsius`
- `nvidia_smi_power_draw_watts`

Backend `/monitoring/gpu/summary` now reports:

```text
available=true
source=nvidia-smi-exporter
```

Next action:

- Keep `scripts/local_gpu_exporter.py` running while testing.
- After a reboot, run `scripts/start-local-gpu-exporter.ps1`.

## 3. AI State

### Current configuration

The backend is configured for real local AI, not mock mode:

```text
AI_ENABLED=true
AI_PROVIDER=ollama
AI_MODEL=llama3.1:8b
AI_BASE_URL=http://host.docker.internal:11434
AI_TIMEOUT_SEC=60
```

### Current status

Ollama is installed and running locally. The configured model is installed:

```text
llama3.1:8b
```

Verified checks:

- Ollama service responds on `127.0.0.1:11434`.
- `ollama list` shows `llama3.1:8b`.
- Direct Ollama chat test returned `VAELQORIX_AI_OK`.
- Backend container reached Ollama through `http://host.docker.internal:11434`.
- Backend-to-Ollama test returned `BACKEND_TO_OLLAMA_OK`.
- RedQueen `/api/v1/redqueen/verdict` produced a real LLM decision without `fallback-stub`.

AI status: connected locally.

Next action:

- Run one AI workflow from the frontend UI.
- Decide if `llama3.1:8b` is the permanent local model or if a faster/smaller model is needed for routine local testing.

## 4. ARES And Action Connectors

### Current state

ARES is configured in real/provider mode:

```text
ACTION_EXECUTION_MODE=provider
```

This is good because it means we are no longer pretending with frontend mock data.

RedQueen/ARES chat now accepts natural operator language for evidence retrieval. Example:

```text
dame las evidencias de hoy
```

This routes to `evidence_today` and returns today's verdicts, executions, audit records, and ARES evidence bundles without requiring the operator to send JSON.

Verified on 2026-09-15:

- `intent=evidence_today`
- Today's validation data returned 1 verdict, 1 audit record, and 1 ARES evidence bundle.
- Evidence source included local GPU telemetry validation for `local-gpu-telemetry`.

### Current gap

Real provider endpoints and credentials are still missing for the main action planes:

- Network/firewall
- Identity/Entra
- Endpoint/EDR
- SOAR
- Crypto/secrets
- DevSecOps/GitHub automation
- SOC webhook/case workflow

The backend can expose readiness and contracts, but the actual control providers need real URLs, tokens, or local adapters.

### Connector priority for tomorrow

Recommended order:

1. Identity connector: Entra/local identity adapter, because identity is central to XDR correlation.
2. Endpoint connector: local host/EDR-like adapter, because local response needs host facts.
3. Network/firewall connector: DNS/firewall provider, because containment actions need a real enforcement point.
4. SOAR/case connector: real ticket/case workflow after detection and action evidence exists.
5. Crypto/secrets connector: secret backend and key lifecycle for production hardening.

## 5. Competitive Position

### Cisco XDR

Cisco XDR is strong on telemetry-centric correlation across endpoint, network, firewall, email, identity, and DNS. Cisco also exposes REST APIs for custom integrations, automation workflows, findings ingestion, incidents, investigations, and threat intelligence.

Cisco's advantage:

- Mature telemetry breadth across major SOC vectors.
- Strong native Cisco ecosystem.
- Open API story for custom integrations.
- Talos threat intelligence.
- Automation workflows and incident operations are already productized.

VAELQORIX current position vs Cisco:

- We have the beginning of a similar architecture: telemetry, readiness, frontend contracts, ARES action mode, monitoring, and local infra.
- We are weaker today in real connector depth. Cisco already has productized integrations; VAELQORIX still needs real provider adapters.
- Our advantage is local-first control and transparency. We can run the whole core locally and inspect/debug line by line, which is harder with large SaaS platforms.
- To compete technically, we need real ingestion/action connectors for the six key XDR planes: endpoint, network, firewall/DNS, identity, email, and cloud.

### Palo Alto Cortex XDR/XSIAM

Palo Alto Cortex XSIAM is positioned as a unified AI-driven SOC platform combining SIEM, EDR, XDR, SOAR, cloud detection/response, attack surface management, UEBA, and threat intelligence. Its Cortex ecosystem includes marketplace/content-pack integrations, playbooks, automations, data normalization, ML analytics, and response workflows.

Palo Alto's advantage:

- Very mature unified SOC platform story.
- Huge catalog of detections, analytics, playbooks, and integrations.
- Strong endpoint, firewall, cloud, and network ecosystem.
- XSIAM has a serious data lake/normalization/automation advantage.
- Marketplace model makes connectors operationally easy for customers.

VAELQORIX current position vs Palo Alto:

- We have a local command center skeleton and backend/frontend contracts, but not yet the connector marketplace, analytics model depth, or response playbook library.
- Local AI runtime is now live through Ollama, but frontend UI workflow validation still needs one browser smoke test.
- We can differentiate by being local, inspectable, and modular, especially for users who want control instead of a closed enterprise platform.
- To get closer, VAELQORIX needs normalized event ingestion, case timeline reconstruction, action evidence, and a first set of real playbooks.

### IBM QRadar Suite

IBM QRadar Suite combines SIEM, SOAR, EDR/MDR, NDR, log management, data exploration, threat intelligence, and a unified analyst experience. IBM emphasizes an open XDR ecosystem, hundreds of integrations, App Exchange, DSM modules, flow data, Universal Cloud REST API, and federated search.

IBM's advantage:

- Very mature SIEM/log/flow history.
- Large integration ecosystem.
- Strong SOAR and case management heritage.
- Support for event logs, flow data, DSMs, REST API ingestion, and federated search.
- Enterprise trust and compliance posture.

VAELQORIX current position vs IBM:

- We are not yet close to QRadar's SIEM maturity, connector count, parser ecosystem, or enterprise case management depth.
- We do have a cleaner local development loop and a more flexible opportunity to build modern AI/agentic response from the ground up.
- The immediate gap is data normalization and parser/connector coverage.
- To compete with QRadar, VAELQORIX needs reliable log ingestion, flow ingestion, identity enrichment, case management, search, and saved investigation evidence.

## 6. Honest Scorecard

Scale: 1 = missing, 5 = strong local prototype, 10 = enterprise competitor maturity.

| Area | VAELQORIX Today | Cisco XDR | Palo Alto Cortex/XSIAM | IBM QRadar Suite |
|---|---:|---:|---:|---:|
| Local core running | 7 | 3 | 3 | 4 |
| Telemetry basics | 6 | 9 | 9 | 9 |
| GPU/local machine telemetry | 7 | 5 | 5 | 5 |
| AI assistant/runtime | 6 | 7 | 9 | 8 |
| Real connector depth | 2 | 9 | 10 | 10 |
| SIEM/log maturity | 3 | 7 | 9 | 10 |
| SOAR/playbooks | 3 | 8 | 10 | 9 |
| Endpoint response | 2 | 9 | 10 | 8 |
| Identity integration | 2 | 8 | 9 | 8 |
| Case management | 3 | 8 | 9 | 10 |
| Developer inspectability | 9 | 4 | 4 | 5 |
| Local-first operation | 9 | 3 | 3 | 5 |

Interpretation:

VAELQORIX is not yet competing on connector catalog, SIEM maturity, or enterprise packaged automation. It is competing on architecture direction, local-first control, transparency, local AI execution, real local machine telemetry, and speed of iteration. The product becomes meaningfully competitive only after real connectors replace readiness stubs.

## 7. What Must Be Built Next

### Immediate blockers

- Real provider URLs/tokens for ARES action planes
- Connector implementations beyond readiness/preflight stubs

### Minimum viable real connector set

To stop looking like a demo and start behaving like a real XDR command platform:

1. Identity connector
   - Local user/session events
   - Entra ID OAuth/API adapter when credentials exist
   - Failed login, impossible travel, risky user enrichment

2. Endpoint connector
   - Local Windows process/service/network facts
   - Isolation/quarantine contract, even if first implementation is guarded/manual
   - Evidence capture per action

3. Network/DNS connector
   - DNS blocklist action
   - Firewall rule action
   - Verification after action

4. SIEM/log connector
   - Structured event ingestion
   - Searchable timeline
   - Correlation IDs from event to alert to action

5. SOAR/case connector
   - Case creation
   - Task/action history
   - Analyst approval gates

6. Secret/crypto connector
   - No plain local secrets for real provider tokens
   - Key rotation plan
   - Audit trail for secret reads/writes

## 8. Tomorrow's Execution Plan

Recommended practical sequence:

1. Verify all services still up.
2. Run one AI request from the frontend UI to confirm browser-to-backend-to-Ollama flow.
3. Pick one first real ARES connector. Recommendation: identity or endpoint.
4. Replace one stub path with a real adapter.
5. Add integration test for that adapter contract.
6. Run frontend build, backend tests, and live smoke test.
7. Update this document with actual connector status.

## 9. Source Notes For Competitive Analysis

Sources checked on 2026-09-13:

- Cisco XDR integrations: https://www.cisco.com/site/us/en/products/security/xdr/integrations.html
- Cisco XDR APIs: https://developer.cisco.com/docs/cisco-xdr/introduction/
- Cisco XDR data sheet: https://www.cisco.com/c/en/us/products/collateral/security/xdr/xdr-ds.html
- Palo Alto Cortex: https://www.paloaltonetworks.com/cortex
- Palo Alto Cortex XSIAM: https://www.paloaltonetworks.com/cortex/cortex-xsiam
- Palo Alto Cortex XSIAM integrations docs: https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-3.x-Documentation/Integrations
- Palo Alto Cortex XDR integrations docs: https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-3.x-Documentation/About-Palo-Alto-Networks-integrations
- IBM threat detection and response: https://www.ibm.com/solutions/threat-detection-response
- IBM QRadar SIEM integrations: https://www.ibm.com/products/qradar-siem/integrations
- IBM QRadar platform overview: https://www.ibm.com/docs/en/security-qradar/security-qradar-siem/saas?topic=qradar-platform-overview
- IBM QRadar SOAR integrations: https://www.ibm.com/products/qradar-soar/integrations
- IBM QRadar Suite threat management: https://www.ibm.com/docs/en/cloud-paks/cp-security/1.11.0?topic=overview-qradar-suite-threat-management
