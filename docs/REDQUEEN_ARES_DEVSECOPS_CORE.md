# RedQueen / ARES DevSecOps Core

Este documento fija el estado actual del nucleo defensivo de NEXUS y la ruta tecnica para convertirlo en una plataforma de ciberdefensa integrable en identidades, pipelines, SIEM/SOC y herramientas de seguridad.

Fase 1 queda cerrada formalmente en `docs/DOC-10_PHASE1_CLOSURE.md`.

## Objetivo

NEXUS queda orientado como un sistema de ciberdefensa hibrido:

- RedQueen: motor de percepcion, correlacion, razonamiento y decision.
- ARES: motor de validacion, planificacion, ejecucion controlada, rollback y evidencia.
- SecOps/DevSecOps: plano de control para senales de identidad, seguridad de pipeline y correlacion entre identidad y release.
- Intelligence: capa IA defensiva con RAG local, contrato LLM normalizado y contexto MCP gobernado.

El alcance actual es defensivo y autorizado. Las acciones operativas se limitan a contencion, reduccion de privilegios, bloqueo de despliegues, cuarentena de artefactos, revocacion de sesiones/tokens y delegacion auditada.

## Flujo Principal

```text
Identity / DevSecOps / Security tools
        |
        v
Ingestion normalized ThreatEvent
        |
        v
SecOps correlation + posture
        |
        v
RedQueen perception + RAG + MCP + LLM contract
        |
        v
Signed verdict + domain-aware action
        |
        v
ARES validation + advisor + plan + execution
        |
        v
ExecutionResult + intelligence_trace + audit chain
```

## RedQueen

RedQueen ya decide por dominio:

- `identity`
- `devsecops`
- `endpoint`
- `network`
- `crypto`
- `generic`

Acciones relevantes ya soportadas:

- Identidad: `require_mfa`, `revoke_session`, `degrade_privileges`, `identity_lockdown`.
- DevSecOps: `require_release_approval`, `revoke_pipeline_token`, `quarantine_artifact`, `block_deployment`.
- Genericas/infra: `observe`, `soar_delegate`, `crypto_rotate`, `endpoint_isolate`, `network_isolate`.

RedQueen aplica:

- Matriz de politica por accion.
- Seleccion de accion minima por riesgo.
- Ajuste por capacidades del proveedor de identidad.
- Normalizacion de salida LLM mediante `redqueen.llm_decision.v1`.
- Enriquecimiento con RAG y contexto MCP.

## ARES

ARES es el unico camino de ejecucion operativa. Ya cubre:

- Validacion de firma, politica, kill switch, aprobacion humana y allow/block MCP.
- Planificacion por accion.
- Ejecucion defensiva por dominio.
- Rollback para acciones reversibles.
- Persistencia de `ExecutionResult`.
- Evidencia adicional `intelligence_trace` con RAG, MCP, contrato LLM y factores de decision.

Esto permite auditar no solo que se ejecuto, sino por que RedQueen decidio esa accion y con que contexto IA.

## Identity Defense

El nucleo de identidad normaliza senales de proveedores como:

- Entra ID
- Okta
- Auth0
- Keycloak
- Google Workspace
- Active Directory
- GitHub
- AWS IAM
- Custom

Capacidades:

- Ingesta de senales de identidad.
- Timeline y actividad por entidad.
- Triage de identidad.
- Preflight por proveedor.
- Acciones defensivas segun capacidad del proveedor.

## SecOps / DevSecOps

SecOps funciona como plano de control DevSecOps:

- Ingesta `POST /api/v1/secops/signals`.
- Resumen `GET /api/v1/secops/signals/summary`.
- Postura `GET /api/v1/secops/posture`.
- Correlacion identidad-pipeline.
- Materializacion batch de correlaciones.
- Ciclo completo senal -> RedQueen -> ARES.

Tipos de senales soportadas:

- `sast_finding`
- `dependency_vuln`
- `secret_leak`
- `container_vuln`
- `iac_misconfig`
- `deployment_anomaly`
- `pipeline_identity_risk`

## Intelligence Core

La capa Intelligence ya existe como nucleo local:

- RAG defensivo en memoria.
- Base de conocimiento inicial para identidad, secretos, releases, correlacion identidad-pipeline y ejecucion gobernada MCP.
- Contrato LLM estable `redqueen.llm_decision.v1`.
- Estado de inteligencia expuesto en `GET /api/v1/secops/intelligence/status`.
- MCP context normalizado con:
  - `allowed_actions`
  - `blocked_actions`
  - `blast_radius`
  - `criticality`
  - `evidence_refs`
  - `tools`
  - `tool_results`

La decision de mantener RAG local ahora es deliberada: cierra el contrato del nucleo sin acoplar el sistema a una base vectorial concreta.

## Endpoints Clave

- `GET /api/v1/secops/status`
- `GET /api/v1/secops/posture`
- `GET /api/v1/secops/intelligence/status`
- `GET /api/v1/secops/enterprise/readiness`
- `POST /api/v1/secops/signals`
- `GET /api/v1/secops/signals/summary`
- `GET /api/v1/secops/correlations/identity-pipeline/{actor_identity}`
- `POST /api/v1/secops/correlations/identity-pipeline/{actor_identity}/lifecycle`
- `POST /api/v1/secops/correlations/identity-pipeline/materialize`
- `GET /api/v1/secops/security/events`
- `POST /api/v1/secops/security/events/export`
- `POST /api/v1/secops/security/events/materialize`
- `POST /api/v1/secops/security/events/{source_event_id}/lifecycle`
- `POST /api/v1/secops/lifecycle`
- `GET /api/v1/identity/providers`
- `GET /api/v1/identity/providers/entra/readiness`
- `POST /api/v1/identity/providers/entra/events`
- `POST /api/v1/identity/events`
- `POST /api/v1/identity/entities/{identity_id}/triage`
- `POST /api/v1/identity/lifecycle`

## Estado Actual

Ya esta cerrado a nivel MVP de nucleo:

- Identity telemetry hacia RedQueen/ARES.
- DevSecOps telemetry hacia RedQueen/ARES.
- Correlacion identidad-pipeline.
- Acciones defensivas por dominio.
- RAG local.
- Contrato LLM.
- Contexto MCP.
- Evidencia ARES con traza IA.
- Tests unitarios del flujo principal.
- Audit context enterprise con `tenant_id`, `actor_role`, `capability` y `request_id`.
- Primer contrato Microsoft Entra en modo webhook/SIEM hacia `identity_signal.v1`.
- Evidencia de proveedor externo persistida en eventos Identity (`provider_evidence`, `payload_sha256`, `evidence_refs`).
- Rate limit operacional para webhook Entra por tenant, IP cliente y provider.
- Replay guard para bloquear reutilizacion exacta de webhooks Entra firmados dentro del TTL.
- Auditoria hash-chain de rechazos de seguridad Entra (`401`, `409`, `429`) sin exponer secretos.
- Endpoint SOC/SIEM para eventos de seguridad sanitizados: `GET /api/v1/secops/security/events`.
- Materializacion de abuso contra integraciones en `ThreatEvent` con source `secops:integration_security_abuse`.
- Posture SecOps marca `security_event_monitoring=attention` cuando detecta abuso de integraciones.
- RedQueen clasifica `secops:integration_security_abuse` como dominio DevSecOps para mantener decision y ejecucion dentro de ARES.
- SecOps puede lanzar lifecycle RedQueen/ARES sobre abuso de integraciones materializado sin exponer payloads sensibles.
- Observabilidad Prometheus para rechazos webhook, rate limit, replay, materializaciones SOC y lifecycles SOC.
- Contrato export `soc_case.v1` para SIEM/case management sin envio externo todavia.
- Capabilities SOC separadas: `soc:read`, `soc:materialize`, `soc:execute`.
- Abstraccion de store para rate limit/replay con backend actual `in_memory` y recomendacion Redis/API Gateway para produccion.

Validacion reciente del nucleo:

- `193 passed` en la suite completa backend.
- Coverage total: `84%`.

## Lo Que Falta Para Produccion

Prioridad alta:

- Ejecutar piloto Entra Graph con `ACTION_EXECUTION_MODE=provider` y `ENTRA_GRAPH_ENABLED=true`.
- Sustituir RAG en memoria por backend vectorial sin cambiar contrato: pgvector, Qdrant o Azure AI Search.
- Conectar MCP real con servidores/herramientas autorizadas y mantener allow/block por accion.
- Integrar conectores reales para Entra ID, Okta, GitHub Actions, GitHub Advanced Security, Wazuh/SIEM.
- Completar llamadas Graph controladas para Entra ID: resolve, disable credentials y revoke sessions ya tienen adaptador; require MFA y privilege degradation requieren politica/bridge y grupos aprobados.
- Persistir knowledge documents versionados.
- Anadir migraciones si se decide almacenar nuevas columnas dedicadas a inteligencia.
- Elevar coverage de modulos compartidos y rutas ARES/RedQueen antiguas.

Prioridad media:

- Panel frontend para posture, intelligence status, correlaciones y ejecuciones ARES.
- Export de evidencia para SOC/case management.
- Integracion con alertmanager/SIEM via webhook.
- Politicas por tenant/organizacion.
- Terraform/IaC para despliegue reproducible cuando el nucleo este estable.

## Decision Tecnica

Terraform es viable, pero no debe ir antes del nucleo. La direccion correcta es:

1. Cerrar contrato de eventos, decisiones y ejecucion.
2. Cerrar integraciones IA/MCP/RAG/LLM.
3. Cerrar auditoria y seguridad operacional.
4. Entonces generar IaC para desplegar el sistema.

Ese orden evita automatizar infraestructura de una plataforma cuyo nucleo todavia se este moviendo.
