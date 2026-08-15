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
