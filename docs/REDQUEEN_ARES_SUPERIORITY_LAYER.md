# RedQueen + ARES Superiority Layer

This layer adds strategic anticipation and response routing on top of the enterprise XDR core.

## RedQueen Strategic Anticipation

Contract: `vaelqorix.redqueen.strategic_anticipation.v1`

RedQueen now combines:

- existing attack anticipation.
- bridge trace indicators.
- native sensor events.
- detection correlation.
- MCP business context.
- blast radius and asset tier.

It produces:

- `stage_velocity`: `watch`, `forming`, `accelerating`, or `breakout_imminent`.
- `intervention_window`: `monitor`, `1-4h`, `15-60m`, or `0-15m`.
- `business_priority`: entity, business service, or crown-jewel protection.
- `next_best_actions`: ranked defensive actions mapped to provider families.
- `decision_advantage`: whether the system is acting before impact with native telemetry and bridge trace.

This is intended to move RedQueen from alert reasoning to defensive timing advantage.

## ARES Response Fabric

Contract: `vaelqorix.ares.response_fabric.v1`

ARES now translates RedQueen next-best actions into routed execution paths:

- firewall/WAF/NDR providers.
- IAM/IdP providers.
- EDR/Kubernetes/cloud providers.
- DevSecOps/artifact providers.
- SIEM/SOAR providers.
- case/legal providers.

For each route ARES records:

- candidate providers.
- selected provider.
- readiness state.
- live-ready vs contract-ready mode.
- urgency.
- blast radius.
- tenant id.
- evidence strategy.
- safety boundaries.

## Differentiator

The system can now show a full decision chain:

1. Native telemetry is normalized.
2. Detection rules match and correlate.
3. RedQueen predicts attacker velocity and intervention window.
4. RedQueen emits next-best defensive actions.
5. ARES maps those actions to the best ready connector route.
6. ARES preserves approval, firewall, kill switch and evidence controls.

The implementation remains legally bounded:

- no hack-back.
- no unauthorized external access.
- owned or explicitly authorized assets only.
- human approval for disruptive actions.
- immutable evidence trail.

## Remaining Product Work

This is a superior architectural core, but live superiority still depends on:

- real vendor connector execution with customer credentials.
- deployable endpoint/network/Kubernetes sensors.
- distributed playbook workers.
- SOC UI for bridge trace, response fabric and playbook execution.
- customer-scale benchmarks and tenant isolation validation.
