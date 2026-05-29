# DOC-10 Phase 1 Closure

Fecha de cierre: 2026-05-27

## Decision

Fase 1 queda cerrada como nucleo backend listo para piloto controlado.

La fase no declara produccion completa. Declara que el nucleo RedQueen/ARES, Identity Defense, SecOps/DevSecOps, auditoria enterprise, seguridad operacional, contratos SOC/SIEM, MCP context, LLM contract y RAG local estan integrados, probados y documentados.

Estado validado:

- Backend suite: `193 passed`.
- Coverage total: `84%`.
- Alcance: piloto controlado, entorno autorizado, acciones defensivas y dry-run por defecto.

## Alcance Cerrado

### RedQueen

- Decision por dominio: `identity`, `devsecops`, `endpoint`, `network`, `crypto`, `generic`.
- Firma de verdicts.
- XAI/factores de decision.
- Contrato LLM `redqueen.llm_decision.v1`.
- Ajuste por capacidades de proveedor.
- Enriquecimiento con RAG y MCP context.

### ARES

- Validacion de firma, politica, kill switch, aprobacion humana y MCP policy.
- Planificacion y ejecucion defensiva.
- Persistencia de ejecuciones.
- Rollback donde aplica.
- Evidencia `intelligence_trace`.
- Audit chain para acciones y ejecuciones.

### Identity Defense

- Ingesta normalizada `identity_signal.v1`.
- Timeline y actividad por identidad.
- Triage de identidad.
- Lifecycle Identity -> RedQueen -> ARES.
- Provider registry y preflight.
- Primer contrato Microsoft Entra por webhook/SIEM.

### Microsoft Entra Webhook

- Firma HMAC SHA-256.
- Header `X-Zenthra-Signature`.
- Header anti-replay `X-Zenthra-Timestamp`.
- Ventana `ENTRA_WEBHOOK_MAX_SKEW_SEC`.
- Rate limit operacional.
- Replay guard.
- Evidencia de proveedor en `provider_evidence`.
- Auditoria de rechazos sin secretos.

### SecOps / DevSecOps

- Ingesta `devsecops_signal.v1`.
- Correlacion identidad-pipeline.
- Materializacion batch de correlaciones.
- Lifecycle DevSecOps -> RedQueen -> ARES.
- Provider registry y preflight.
- Posture SecOps.

### SOC / SIEM

- Eventos de seguridad sanitizados:
  - `GET /api/v1/secops/security/events`
- Export contract:
  - `POST /api/v1/secops/security/events/export`
  - contrato `soc_case.v1`
  - `ready_to_send=false` hasta conectar destino real
- Materializacion de abuso:
  - `POST /api/v1/secops/security/events/materialize`
  - source `secops:integration_security_abuse`
  - contrato `secops_integration_security_abuse.v1`
- Lifecycle de abuso materializado:
  - `POST /api/v1/secops/security/events/{source_event_id}/lifecycle`

### Enterprise Security

- Audit context persistido:
  - `tenant_id`
  - `actor_role`
  - `capability`
  - `request_id`
- RBAC por capability.
- Capabilities SOC separadas:
  - `soc:read`
  - `soc:materialize`
  - `soc:execute`
- Readiness enterprise:
  - `GET /api/v1/secops/enterprise/readiness`

### Observabilidad

- `/metrics` protegido por token interno.
- Metricas Prometheus:
  - `zenthra_security_webhook_rejections_total`
  - `zenthra_security_rate_limit_rejections_total`
  - `zenthra_security_replay_rejections_total`
  - `zenthra_soc_materializations_total`
  - `zenthra_soc_lifecycles_total`

### Rate Limit / Replay Store

- Interfaz de store preparada.
- Backend actual: `in_memory`.
- Readiness reporta que no es distribuido.
- Produccion requiere Redis, API Gateway o WAF distribuido.

## Endpoints Principales

### Identity

- `GET /api/v1/identity/providers`
- `GET /api/v1/identity/providers/{provider}`
- `POST /api/v1/identity/providers/{provider}/preflight`
- `GET /api/v1/identity/providers/entra/readiness`
- `POST /api/v1/identity/providers/entra/events`
- `POST /api/v1/identity/events`
- `GET /api/v1/identity/entities/{identity_id}/activity`
- `GET /api/v1/identity/entities/{identity_id}/events`
- `POST /api/v1/identity/entities/{identity_id}/triage`
- `POST /api/v1/identity/lifecycle`

### SecOps / DevSecOps

- `GET /api/v1/secops/status`
- `GET /api/v1/secops/posture`
- `GET /api/v1/secops/intelligence/status`
- `GET /api/v1/secops/enterprise/readiness`
- `GET /api/v1/secops/providers`
- `GET /api/v1/secops/providers/{provider}`
- `POST /api/v1/secops/providers/{provider}/preflight`
- `POST /api/v1/secops/signals`
- `GET /api/v1/secops/signals/summary`
- `POST /api/v1/secops/lifecycle`
- `GET /api/v1/secops/correlations/identity-pipeline/{actor_identity}`
- `POST /api/v1/secops/correlations/identity-pipeline/materialize`
- `POST /api/v1/secops/correlations/identity-pipeline/{actor_identity}/lifecycle`
- `GET /api/v1/secops/security/events`
- `POST /api/v1/secops/security/events/export`
- `POST /api/v1/secops/security/events/materialize`
- `POST /api/v1/secops/security/events/{source_event_id}/lifecycle`

### RedQueen / ARES / Audit / Metrics

- RedQueen event verdict endpoints are available through the existing RedQueen router.
- ARES lifecycle and operation endpoints are available through the existing ARES router.
- `GET /api/v1/audit/records`
- `GET /metrics`

## Contratos Cerrados

- `identity_signal.v1`
- `devsecops_signal.v1`
- `devsecops_identity_pipeline_correlation.v1`
- `secops_integration_security_abuse.v1`
- `soc_case.v1`
- `redqueen.llm_decision.v1`
- `zenthra.mcp_context.v1`
- `zenthra.mcp_tool_policy.v1`
- `threat_event.v1`

## Runbook Minimo

### Ejecutar tests backend

```powershell
.\venv\Scripts\pytest.exe --maxfail=0
```

Resultado esperado al cierre de Fase 1:

```text
193 passed
Coverage total: 84%
```

### Leer posture

```http
GET /api/v1/secops/posture
Authorization: Bearer <monitor-token>
```

### Leer readiness enterprise

```http
GET /api/v1/secops/enterprise/readiness
Authorization: Bearer <monitor-token>
X-Tenant-ID: tenant-alpha
```

### Consultar eventos SOC/SIEM

```http
GET /api/v1/secops/security/events
Authorization: Bearer <monitor-token>
```

### Materializar abuso de integracion

```http
POST /api/v1/secops/security/events/materialize
Authorization: Bearer <monitor-token>
Content-Type: application/json

{
  "min_count": 2,
  "limit": 100
}
```

### Lanzar lifecycle sobre abuso materializado

```http
POST /api/v1/secops/security/events/{source_event_id}/lifecycle
Authorization: Bearer <monitor-token>
Content-Type: application/json

{
  "human_approved": true,
  "execution_controls": {
    "dry_run": true,
    "change_ticket": "PILOT-001"
  }
}
```

### Export SOC/case management

```http
POST /api/v1/secops/security/events/export
Authorization: Bearer <monitor-token>
Content-Type: application/json

{
  "destination": "microsoft_sentinel",
  "format": "soc_case.v1",
  "include_items": true,
  "limit": 100
}
```

### Consultar metricas

```http
GET /metrics
Authorization: Bearer <monitor-token>
```

## Riesgos Aceptados En Piloto

- RAG sigue en memoria.
- Rate limit y replay guard siguen en `in_memory`.
- `soc_case.v1` genera payload pero no envia a destino externo.
- Entra Graph no ejecuta acciones activas todavia.
- Conectores DevSecOps reales no estan autenticados todavia.
- Frontend producto queda para Fase 4.
- Terraform/IaC queda para Fase 5.

## Criterio Para Entrar En Fase 2

Fase 2 empieza cuando se conecte el primer provider real con credenciales y permisos minimos:

- Microsoft Entra Graph controlado.
- GitHub Actions/GHAS o Azure DevOps.
- Wazuh/SIEM o Microsoft Sentinel.

Regla: ningun conector real debe saltarse RedQueen, ARES, audit chain, RBAC enterprise, MCP policy ni evidencia.

## Fases Siguientes

### Fase 2 - Integraciones Reales

- Microsoft Entra Graph.
- GitHub Actions/GHAS.
- Wazuh/SIEM o Microsoft Sentinel.
- Okta/Auth0 opcional.
- Webhooks entrantes/salientes.
- Secret management.

### Fase 3 - IA Enterprise

- Sustituir RAG in-memory por pgvector, Qdrant o Azure AI Search.
- Persistir knowledge documents versionados.
- MCP real con servidores autorizados.
- Evaluacion de decisiones LLM.
- Trazabilidad de prompts, fuentes y decisiones.

### Fase 4 - Plataforma Producto

- Frontend SecOps/SOC.
- Vista posture.
- Vista casos/incidentes.
- Vista RedQueen decisions.
- Vista ARES executions.
- Gestion de tenants, providers, policies y approvals.

### Fase 5 - Infra/IaC

- Docker produccion.
- Terraform.
- CI/CD security gates.
- Observabilidad completa.
- Secrets/Key Vault.
- Despliegue reproducible.

## Resultado

Fase 1 cerrada.

NEXUS queda como nucleo backend defensivo enterprise listo para piloto controlado y preparado para integraciones reales.
