# VAELQORIX AI / VAELQORIX.XDR_COMMAND - powered by VAELQORIX

Plataforma de ciberseguridad/SOC con:
- Backend `FastAPI` + `SQLAlchemy` + `Alembic`
- Frontend `React` + `Vite`
- Observabilidad con `Prometheus`, `Alertmanager`, `Grafana`, `Blackbox Exporter`
- Motor de correlacion SIEM para generar y deduplicar amenazas

## Direccion estrategica

Este repositorio mantiene el backend operativo de `VAELQORIX.XDR_COMMAND` y empieza su evolucion hacia `VAELQORIX AI`, el sistema operativo seguro para agentes empresariales bajo el paraguas `VAELQORIX`.

Los nuevos dominios estrategicos quedan definidos como:

- `CortexFlow`: runtime de agentes, razonamiento, planificacion y memoria.
- `VaelqorixFlow`: workflows, triggers, eventos, aprobaciones y orquestacion.
- `BlackNode`: seguridad, RBAC, auditoria, guardrails y motor de riesgo.
- `VaelqorixVault`: conocimiento, memoria, RAG, embeddings, retrieval y citas.
- `VaelqorixAPI`: integraciones, registry de tools, conectores y webhooks.

La migracion sera incremental: el runtime actual sigue siendo `app.main:app`, mientras `platform/`, `domains/`, `security/`, `observability/` y `docs/architecture/` fijan la estructura enterprise final.

Documentos base:

- [VAELQORIX AI Enterprise Blueprint](docs/VAELQORIX_AI_ENTERPRISE_BLUEPRINT.md)
- [Platform Architecture](docs/architecture/VAELQORIX_PLATFORM_ARCHITECTURE.md)
- [Domain Map](docs/architecture/VAELQORIX_DOMAIN_MAP.json)
- [BlackNode Security Architecture](docs/security/BLACKNODE_SECURITY_ARCHITECTURE.md)

## Estructura del proyecto

```text
VAELQORIX/
|- app/                        # Backend FastAPI
|  |- core/                    # Configuracion, seguridad JWT, observabilidad
|  |- db/                      # Engine, sesiones, dependencias de DB
|  |- models/                  # Modelos ORM (users, threats)
|  |- routers/                 # Endpoints API
|  |- schemas/                 # Esquemas Pydantic
|  |- services/                # Logica de negocio y correlacion
|  `- main.py                  # Punto de entrada FastAPI
|- alembic/                    # Migraciones de base de datos
|- tests/                      # Suite de tests
|- VAELQORIX.XDR_COMMAND/      # Frontend React/Vite/ tailwind
|- docker-compose.yml          # Stack de observabilidad + PostgreSQL
|- requirements.txt            # Dependencias Python del backend
`- .env.example                # Variables de entorno base
```

## Arquitectura funcional

- **Auth y RBAC**: JWT (`/auth/login`) con rol embebido (`admin`, `user`, etc.).
- **Gestion de usuarios**: CRUD en `/users` con endpoints protegidos por rol admin para operaciones sensibles.
- **Threat Management**: CRUD de amenazas en `/threats`, filtros SIEM y paginacion.
- **Correlation Engine**: servicio programado + endpoint manual para correlacionar alertas de Prometheus y abrir/cerrar incidentes.
- **Observabilidad interna**:
  - `/metrics` para Prometheus
  - `/monitoring/*` protegido con token interno (`VAELQORIX_MONITOR_TOKEN`)
  - webhook `/hooks/alertmanager` con whitelist IP

## Requisitos

- Python `3.13.x`
- Node.js `18+` (recomendado `20+`)
- Docker Desktop (para Prometheus/Grafana/Alertmanager/PostgreSQL)

## Configuracion backend

1. Crear entorno virtual:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

2. Instalar dependencias:

```powershell
pip install -r requirements.txt
```

3. Crear `.env` a partir de `.env.example` y ajustar valores.

Variables clave:
- `SECRET_KEY`
- `ACCESS_TOKEN_EXPIRE_MINUTES`
- `SQLALCHEMY_DATABASE_URI` **o** bloque `POSTGRES_*`
- `VAELQORIX_MONITOR_TOKEN`
- `PROMETHEUS_BASE`
- `ALERTMANAGER_BASE`

4. Ejecutar migraciones:

```powershell
alembic upgrade head
```

5. Levantar API:

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8010
```

## Configuracion frontend

Desde `VAELQORIX.XDR_COMMAND/`:

```powershell
corepack enable
corepack pnpm install
```

Variables frontend (`VAELQORIX.XDR_COMMAND/.env`):
- `VITE_API_URL=http://127.0.0.1:8010` para desarrollo local cuando Docker ya ocupa `8000`
- `VITE_VAELQORIX_MONITOR_TOKEN=` en produccion; solo usarlo en desarrollo local controlado
- `VITE_USE_MOCKS=false`

## Observabilidad (Docker)

Levantar stack:

```powershell
docker compose up -d
```

Servicios por defecto:
- Backend: `http://localhost:8000`
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000`
- Alertmanager: `http://localhost:9093`
- Blackbox: `http://localhost:9115`
- PostgreSQL: `localhost:56432`

## Diagnostico operativo

La UI incluye una pantalla dedicada en `/dashboard/diagnostics` para confirmar fuentes reales:

- Backend y base de datos
- Prometheus
- Alertmanager
- windows-exporter
- GPU exporter
- Logs del backend

El backend expone:

- `GET /monitoring/sources/diagnostics`
- `GET /monitoring/host/summary`
- `GET /monitoring/health/full`

Las rutas `/monitoring/*` aceptan `VAELQORIX_MONITOR_TOKEN` para automatizacion interna o JWT de usuario admin para la UI. `/metrics` sigue aceptando solo `VAELQORIX_MONITOR_TOKEN`.

## Endpoints principales

### Publicos
- `GET /health`
- `GET /ready`
- `POST /users/` (registro)
- `POST /auth/login`

### Protegidos JWT
- `GET /users/me`
- `GET /users/` (admin)
- `PUT /users/{user_id}` (admin)
- `DELETE /users/{user_id}` (admin)
- `GET /threats/`
- `POST /threats/` (admin)

### Protegidos con monitor token
- `GET /monitoring/health`
- `GET /monitoring/health/full`
- `GET /monitoring/alerts`
- `GET /monitoring/alerts/realtime`
- `GET /monitoring/query?q=...`
- `GET /monitoring/range?q=...`
- `POST /monitoring/correlation/run`

## Testing

Comando esperado:

```powershell
pytest
```

Estado detectado en este entorno:
- Backend cerrado en codigo de Fase 5: `276 passed`, cobertura total `93.51%`, Ruff y Mypy correctos.
- Frontend: `corepack pnpm run build` completa correctamente.
- CI exige Ruff, Mypy, guarda de codificacion y cobertura backend minima del `90%`.

## Hallazgos del analisis tecnico

1. El backend esta listo para piloto controlado, pero los proveedores externos todavia deben activarse y validarse con credenciales reales.
2. El despliegue actual es un monolito FastAPI modular. RedQueen, ARES e ingestion no deben separarse en deployments hasta disponer de entrypoints independientes.
3. Enterprise AI mantiene defaults seguros `local_stub` y `dry_run`; la activacion real exige readiness, preflight y evidencia de auditoria.
4. La configuracion local usa archivos `.env` ignorados por Git.
   - Solo se debe commitear `.env.example`; los secretos reales deben vivir en variables de entorno, vault o secretos del cluster.
5. Fase 4 continua como endurecimiento backend y code intelligence, sin iniciar frontend.
6. Hay entrypoints ASGI restringidos para RedQueen, ARES e ingestion; permanecen fuera del CD hasta completar routing interno, NetworkPolicies y estado distribuido de ARES.

## Recomendaciones inmediatas

1. Aplicar politicas tenant persistidas a todos los repositorios criticos antes de activar modo multi-tenant estricto.
2. Validar al menos un proveedor Identity, DevSecOps y SOC de extremo a extremo.
3. Seleccionar gateway LLM y backend de recuperacion vectorial.
4. Mantener `local_stub` y `dry_run` hasta superar readiness, preflight y validacion operativa.
5. Usar `POST /api/v1/code-intelligence/analyze` para inventariar componentes, dependencias, rutas y puntos de ejecucion sin ejecutar el codigo analizado.

Estado backend Fase 5:

- Kill-switch ARES con backend Redis opcional y fail-closed si Redis no esta disponible.
- Politicas tenant/provider persistidas y disponibles en `/api/v1/secops/tenant-policies`.
- La activacion productiva completa sigue dependiendo de secretos gestionados, proveedores reales y validacion externa.

## Licencia

Definir licencia del proyecto (actualmente no se detecta archivo `LICENSE`).

## ARESX Integration (RedQueen/ARES Blueprint v2.0)

Este repositorio ahora incluye una fusion de arquitectura **ARESX Fase 1** sobre la base existente de VAELQORIX:

- `app/core`: `logging.py`, `errors.py`, `signing.py`, `dependencies.py`
- `app/db`: `base.py`, `vector.py` (stub), `audit_store.py` (stub), `migrations/` (stub)
- `app/models`: modelos canonicos (`ThreatEvent`, `EntityProfile`, `RiskScore`, `Verdict`, `ExecutionResult`, `AuditRecord`, `PolicyRule`)
- `app/middlewares`: `request_id`, `audit_middleware`
- `app/health`: `router.py` y `checks.py` (`/system/health`, `/system/ready`)
- `app/ingestion`: router y adapters stub de Fase 1/2
- `app/redqueen`: router + `policy_matrix.py` stub
- `app/ares`: router + `kill_switch.py` stub
- `app/actions`: acciones base/stubs
- `ml/`: stubs de modelos para fases posteriores

### Nuevas rutas activas

- `GET /api/v1/ingestion/status`
- `GET /api/v1/redqueen/status`
- `POST /api/v1/redqueen/policy/evaluate?score=&action_type=`
- `GET /api/v1/ares/status`
- `POST /api/v1/ares/kill-switch/{on|off}`
- `GET /system/health`
- `GET /system/ready`

### Notas

- Esta integracion mantiene compatibilidad con endpoints existentes de auth/users/threats/monitoring.
- Los componentes de Fase 2-5 estan como **stubs estructurales** para evolucion incremental sin romper produccion.

## RedQueen/ARES Autonomous Control (LLM + Persistent Verdicts + Transactional Execution)

### 1) Activar LLM real (Ollama)

En `.env`:

```env
AI_ENABLED=true
AI_PROVIDER=ollama
AI_MODEL=llama3.1:8b
AI_BASE_URL=http://127.0.0.1:11434
AI_TIMEOUT_SEC=8
AI_TEMPERATURE=0.1
```

Notas:
- Si Ollama falla o no responde, el sistema hace fallback seguro a `local_stub` sin romper el ciclo.
- RedQueen exige salida JSON estructurada y valida acciones permitidas antes de firmar.
- 

### 2) Persistencia de decisiones y ejecuciones

Cada ciclo guarda en DB:
- `verdicts`: decision firmada (score, action, confidence, factors, requires_human, signature)
- `execution_results`: estado de ejecucion, evidencia, hash forense de resultado

Endpoints de trazabilidad:
- `GET /api/v1/redqueen/verdict/{verdict_id}`
- `GET /api/v1/ares/results/{verdict_id}`

### 3) Ejecutores reales con rollback transaccional

Configurar modo webhook en `.env`:

```env
ACTION_EXECUTION_MODE=webhook
ACTION_TIMEOUT_SEC=5
ACTION_SHARED_TOKEN=<token_compartido>
NETWORK_CONTROL_URL=https://your-network-controller/api/actions
IDENTITY_CONTROL_URL=https://your-iam-controller/api/actions
ENDPOINT_CONTROL_URL=https://your-edr-controller/api/actions
```

Comportamiento:
- `network_isolate`, `identity_lockdown`, `endpoint_isolate` ejecutan por pasos.
- Si un paso falla, ARES aplica rollback en orden inverso.
- Cada ejecucion queda registrada con hash.

### 4) Flujo operativo

1. `POST /api/v1/redqueen/verdict`
2. `POST /api/v1/ares/execute`
3. o todo en uno: `POST /api/v1/ares/lifecycle`

### 5) Gobernanza critica

- Veredictos requieren firma valida.
- Policy Matrix valida decision antes de ejecutar.
- Kill-switch global bloquea ejecucion inmediatamente.
- Riesgo alto puede requerir aprobacion humana (`requires_human=true`).
