# RedQueen And ARES Defensive Expansion

## Objective

This phase expands RedQueen from a tactical verdict generator into a more
meticulous analytical brain, and expands ARES from an executor into an internal
defensive firewall for autonomous response.

## RedQueen Analytical Brain

RedQueen now emits `vaelqorix.redqueen.analytical_brain.v1` inside every
verdict. The profile captures:

- analytical posture
- diligence score
- evidence depth
- contradiction count
- high-impact markers
- negative controls
- MCP, RAG and drift context signals
- recommended guardrails

The profile is included in the signed verdict execution controls and propagated
into ARES evidence through the intelligence trace.

RedQueen also emits `vaelqorix.redqueen.attack_anticipation.v1` to anticipate
attack paths against business infrastructure. The contract captures:

- predicted targets
- attack horizon
- latest attack stage
- matched defensive markers
- early warnings
- preventive controls

The anticipation contract is exposed directly through
`POST /api/v1/redqueen/anticipate` and is embedded in signed verdict execution
controls.

## ARES Internal Firewall

ARES now evaluates a firewall decision before executing a plan. The firewall can
block execution when:

- MCP action policy denies the action.
- MCP tool policy denies the context.
- `firewall_policy.deny_actions` contains the action.
- `firewall_policy.allowed_actions` is present and omits the action.
- A protected target would receive a disruptive action without both
  `change_ticket` and `dependency_owner_approved`.
- ARES Advisor marks the plan unsafe while `enforce_advisor_firewall=true`.

Blocked executions are persisted as failed execution results and audited with
actor `ares_firewall`.

## ARES OS And Business Shield

ARES now emits `vaelqorix.ares.os_business_shield.v1` before execution. The
shield converts RedQueen attack anticipation into defensive layers for:

- identity
- network
- endpoint
- data
- business change control
- monitoring

The shield is exposed directly through `POST /api/v1/ares/shield/plan` and is
attached to lifecycle plans before Advisor and internal firewall evaluation.

## Operator Controls

Example execution controls:

```json
{
  "change_ticket": "CHG-123",
  "dependency_owner_approved": true,
  "enforce_advisor_firewall": true,
  "firewall_policy": {
    "protected_targets": ["database-prod-*", "identity-core"],
    "deny_actions": ["network_isolate"],
    "allowed_actions": ["observe", "soar_delegate", "require_mfa"]
  }
}
```

## Production Rule

RedQueen may decide, but ARES is still the only execution path. ARES must pass
signature validation, BlackNode validation, human approval when required,
Advisor review and the internal firewall before any operational step runs.

Preventive hardening uses `system_harden`, a controlled ARES action that
baselines OS posture, applies approved defensive hardening and verifies business
service health.
