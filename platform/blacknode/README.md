# BlackNode

BlackNode is the security, governance and risk layer for NexusOps AI.

Every agent action must pass through authentication, authorization, risk evaluation, policy checks and audit recording.

Current implementation is mapped to:

- `app.core.security`
- `app.core.enterprise_security`
- `app.middlewares.audit_middleware`
- `app.models.audit_record`
- `app.ares.approval`

