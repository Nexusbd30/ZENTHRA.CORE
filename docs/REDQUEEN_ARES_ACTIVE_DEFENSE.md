# RedQueen + ARES Active Defense

## Scope

This layer upgrades RedQueen and ARES for authorized active defense of owned business infrastructure.
It is intentionally not a hack-back system. The system may block, isolate, revoke, freeze, preserve evidence and report through configured internal connectors. It must not access, probe, exploit or retaliate against external systems.

## RedQueen Brain

RedQueen now enriches every verdict with three defensive intelligence blocks:

- `redqueen_analytical_profile`: diligence, posture and reasoning quality.
- `redqueen_attack_anticipation`: likely attack stage, horizon and preventive controls.
- `redqueen_bridge_trace`: observed bridge/origin traceability for blocking and evidence.

The bridge trace contract is `vaelqorix.redqueen.bridge_trace.v1`. It extracts indicators from threat perception, normalized payloads, identity context, DevSecOps context, MCP context and factors. The output includes:

- `origin_candidates`: IP, identity, session, device, repository, pipeline or runner candidates.
- `suspected_bridge`: strongest currently observed bridge.
- `pivot_chain`: internal path candidates into the target.
- `block_targets`: defensive controls ARES can apply inside owned systems.
- `trace_boundaries`: explicit limits, including no counter-intrusion and authorized assets only.

## ARES Brain

ARES now adds an active containment plan to the normal execution plan before Advisor and firewall checks. The contract is `vaelqorix.ares.aggressive_containment.v1`.

ARES containment can prepare:

- perimeter block for observed network indicators.
- identity/session revocation.
- endpoint or runner isolation.
- release/pipeline freeze when the bridge is DevSecOps.
- SOC traceability case with chain of custody.
- neutralization verification after disruptive actions.

The containment plan is still governed by:

- signed RedQueen verdict.
- policy matrix.
- human approval for disruptive active defense.
- ARES Advisor.
- ARES internal firewall.
- kill switch.
- rollback strategy where applicable.

## New Action

`aggressive_containment` is a high-severity cross-domain action. It is allowed only for high risk and always requires human approval. ARES executes it through the SOAR connector so production can route the steps to SIEM/SOC, firewall automation, EDR, IAM and DevSecOps integrations without bypassing governance.

## Endpoints

- `POST /api/v1/redqueen/bridge-trace`
- `POST /api/v1/ares/containment/plan`

## Production Connector Expectations

For production, route active containment steps through approved providers or signed webhooks:

- Network perimeter: firewall/WAF/NDR block list.
- Identity: Entra or equivalent token/session revocation.
- Endpoint: EDR host isolation.
- DevSecOps: GitHub/GHAS, Jenkins, SonarQube or artifact registry freeze.
- SOC/SIEM: Sentinel, Wazuh, QRadar or signed SOC webhook.

All connectors must preserve idempotency, evidence payloads and operator audit data.
