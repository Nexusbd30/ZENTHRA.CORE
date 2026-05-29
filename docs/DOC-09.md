# DOC-09 Integration Notes

Este documento describe la fusion del blueprint RedQueen/ARES v2.0 sobre la base actual y actua como registro vivo de integraciones enterprise.

- Fase 1 implementada en estructura y stubs operativos.
- Fase 1 cerrada formalmente en `docs/DOC-10_PHASE1_CLOSURE.md`.
- Fase 2+ preparadas como modulos plug-in sin romper API actual.

## 2026-05-27 - Enterprise Security Gate

Estado backend validado:

- Suite backend: `193 passed`.
- Coverage: `84%`.
- Gate enterprise activo en rutas mutantes Identity y SecOps/DevSecOps.

Cambios de seguridad:

- `tenant_id`, `actor_role`, `capability` y `request_id` se persisten en `audit_records`.
- El hash chain de auditoria incluye contexto enterprise.
- `/api/v1/audit/records` soporta filtros por `tenant_id` y `capability`.
- `require_enterprise_capability(...)` protege mutaciones de identidad y pipeline.
- `GET /api/v1/secops/enterprise/readiness` expone RBAC, tenant mode, audit readiness e integraciones preferidas.

Migracion:

- `alembic/versions/b1c2d3e4f5a6_add_enterprise_audit_context.py`

Gap restante:

- Persistir evidencia del proveedor externo una vez conectemos el primer backend real.

## 2026-05-27 - Microsoft Entra Integration Contract

Objetivo: preparar el primer provider real de identidad sin acoplar todavia el runtime a llamadas salientes Microsoft Graph.

Endpoints:

- `GET /api/v1/identity/providers/entra/readiness`
- `POST /api/v1/identity/providers/entra/events`

Contrato de entrada:

- Acepta eventos estilo Microsoft Entra Identity Protection o payloads equivalentes desde Sentinel/webhook.
- Normaliza a `identity_signal.v1`.
- Persiste como `ThreatEvent` con source `identity:entra`.
- Persiste evidencia enterprise en `ThreatEvent.normalized_payload.provider_evidence`.

Mapeo inicial:

- `tokenReplay` -> `token_reuse`
- `impossibleTravel` -> `impossible_travel`
- `suspiciousConsent` -> `suspicious_consent`
- `passwordSpray` / `leakedCredentials` -> `credential_attack`
- `maliciousIPAddress` -> `identity_compromise`

Configuracion:

- `ENTRA_GRAPH_ENABLED`
- `ENTRA_GRAPH_BASE_URL`
- `ENTRA_GRAPH_TOKEN_URL`
- `ENTRA_GRAPH_SCOPE`
- `ENTRA_TENANT_ID`
- `ENTRA_CLIENT_ID`
- `ENTRA_CLIENT_SECRET`
- `ENTRA_REQUIRE_MFA_POLICY_URL`
- `ENTRA_DEGRADE_PRIVILEGES_GROUP_IDS`
- `ENTRA_WEBHOOK_SECRET`
- `ENTRA_WEBHOOK_MAX_SKEW_SEC` (por defecto `300`)
- `ENTRA_WEBHOOK_RATE_LIMIT_ENABLED` (por defecto `true`)
- `ENTRA_WEBHOOK_RATE_LIMIT_REQUESTS` (por defecto `120`)
- `ENTRA_WEBHOOK_RATE_LIMIT_WINDOW_SEC` (por defecto `60`)
- `ENTRA_WEBHOOK_REPLAY_GUARD_ENABLED` (por defecto `true`)
- `ENTRA_WEBHOOK_REPLAY_TTL_SEC` (por defecto `300`)

Seguridad de webhook:

- Si `ENTRA_WEBHOOK_SECRET` esta configurado, `POST /api/v1/identity/providers/entra/events` exige firma HMAC.
- Header requerido: `X-Zenthra-Signature`.
- Header anti-replay requerido: `X-Zenthra-Timestamp` con Unix timestamp en segundos.
- Formato recomendado: `sha256=<hex_digest>`.
- El digest se calcula con HMAC-SHA256 sobre `timestamp + "." + body_json_exacto`.
- Si no hay firma, falta timestamp, el timestamp esta fuera de ventana o la firma no coincide, la API devuelve `401 Invalid Entra webhook signature`.

Evidencia persistida:

- `provider_evidence.kind`: `identity_provider_webhook`.
- `provider_evidence.payload_sha256`: hash SHA-256 del body recibido.
- `provider_evidence.signature`: algoritmo, timestamp, ventana de tolerancia y estado de verificacion.
- `provider_evidence.evidence_refs`: referencias estables para RedQueen, ARES, auditoria y futuro case management.
- No se persisten secretos ni el valor de la firma.

Rate limit operacional:

- El endpoint Entra aplica rate limit por `tenant_id + client_ip + provider`.
- Si se supera el limite, responde `429 Entra webhook rate limit exceeded`.
- La respuesta incluye `Retry-After`, `X-RateLimit-Limit` y `X-RateLimit-Remaining`.
- La implementacion actual es in-memory para piloto controlado; en despliegue multi-instancia debe moverse a Redis, API Gateway o WAF.

Replay guard:

- Si la firma es valida, el endpoint registra una clave derivada de `timestamp + signature + payload_sha256`.
- Si se reutiliza exactamente el mismo body firmado dentro del TTL, responde `409 Entra webhook replay detected`.
- La implementacion actual es in-memory; en despliegue multi-instancia debe moverse a Redis, base transaccional o API Gateway distribuido.

Auditoria de rechazos:

- Los rechazos `401`, `409` y `429` se registran en `audit_records` como `identity_entra_webhook_rejected`.
- La auditoria incluye `reason`, `status_code`, `tenant_id`, `capability`, `client_ip`, `source_event_id` y `payload_sha256`.
- No se registra el body completo, secretos ni valor de firma.

Exposicion SOC/SIEM:

- `GET /api/v1/secops/security/events` devuelve rechazos sanitizados para consumo SOC/SIEM.
- Filtros soportados: `event_type`, `reason`, `tenant_id`, `limit`.
- Incluye agregados `by_reason`, `by_provider`, `by_tenant`.
- `GET /api/v1/secops/posture` incluye `security_events`, `security_event_summary` y el control `security_event_monitoring`.
- Si existen rechazos de seguridad, `security_event_monitoring` queda en `attention` para revision SOC.

Materializacion RedQueen/ARES:

- `POST /api/v1/secops/security/events/materialize` agrupa rechazos por `tenant_id + provider + reason + client_ip`.
- Si un grupo supera `min_count`, crea un `ThreatEvent` deduplicado con source `secops:integration_security_abuse`.
- El evento usa `event_type=integration_security_abuse` y contrato `secops_integration_security_abuse.v1`.
- Solo se persisten agregados, `audit_record_ids`, `source_event_ids`, hashes SHA-256 de payload y `secrets_exposed=false`.
- No se persiste body completo, valor de firma ni secretos.
- RedQueen trata esta fuente como dominio DevSecOps para que ARES pueda contener abuso contra integraciones sin salir del circuito gobernado.
- `POST /api/v1/secops/security/events/{source_event_id}/lifecycle` ejecuta el ciclo RedQueen -> ARES sobre un abuso ya materializado.
- El lifecycle usa provider interno `secops`, contrato `secops_integration_security_abuse.v1`, soporte MCP/RAG/LLM y controles `dry_run`/aprobacion humana.

Observabilidad y export SOC:

- `/metrics` expone contadores Prometheus para rechazos webhook, rate limit, replay, materializaciones SOC y lifecycles SOC.
- Metricas principales:
  - `zenthra_security_webhook_rejections_total`
  - `zenthra_security_rate_limit_rejections_total`
  - `zenthra_security_replay_rejections_total`
  - `zenthra_soc_materializations_total`
  - `zenthra_soc_lifecycles_total`
- `POST /api/v1/secops/security/events/export` genera payload `soc_case.v1` para SIEM/case management.
- El export queda `ready_to_send=false` hasta conectar un destino real; el contrato evita secretos y payloads completos.
- RBAC enterprise separa capacidades SOC: `soc:read`, `soc:materialize`, `soc:execute`.
- Rate limit y replay guard ya exponen backend status. La implementacion actual usa `in_memory`; produccion requiere Redis, API Gateway o WAF distribuido.

Decision tecnica:

- La primera version prioriza webhook/SIEM ingestion y normalizacion defensiva.
- Las llamadas Graph activas empiezan en Fase 2 detras de `ENTRA_GRAPH_ENABLED=true`,
  `ACTION_EXECUTION_MODE=provider`, secrets externos, permisos minimos y evidencia auditada.
- El adaptador Entra Graph soporta resolucion de usuario, deshabilitar credenciales y revocar sesiones.
- `require_mfa` exige un bridge/politica aprobada (`ENTRA_REQUIRE_MFA_POLICY_URL`) porque Microsoft Graph no debe simular enforcement MFA sin Conditional Access o gobierno equivalente.
- `degrade_privileges` exige lista explicita de grupos aprobados (`ENTRA_DEGRADE_PRIVILEGES_GROUP_IDS`) para evitar remover privilegios fuera de alcance.
