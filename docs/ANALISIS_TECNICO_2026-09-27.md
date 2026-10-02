# Análisis técnico del proyecto VAELQORIX / NEXUS

Fecha: 27 de septiembre de 2026. Revisión local del repositorio; no se modificó el código de aplicación ni se desplegaron servicios.

## Dictamen

El proyecto tiene una base funcional amplia y una suite backend considerable, pero no está listo para un despliegue productivo multiusuario y multitenant sin corregir los bloqueos descritos aquí. La cobertura alta demuestra ejecución de código bajo pruebas, no integración real con proveedores ni seguridad de todos los flujos.

## Alcance y arquitectura

Inventario de código propio: 261 archivos Python y 26.239 líneas en `app`; 75 archivos y 15.534 líneas en `tests`; 63 archivos JS/JSX/CSS y 14.141 líneas en el frontend. El recuento estático identifica 185 declaraciones de rutas HTTP/WebSocket, no necesariamente 185 rutas únicas desplegadas. `ml` contiene ocho archivos y siete líneas: son marcadores estructurales, no modelos entrenados.

El núcleo es un monolito modular FastAPI con SQLAlchemy y Alembic. React/Vite implementa la consola; PostgreSQL aporta persistencia y Redis se contempla para controles distribuidos. Prometheus, Grafana, Alertmanager y Blackbox conforman la observabilidad.

La cadena principal conecta ingesta y normalización de eventos, análisis RedQueen, veredictos firmados, controles de ARES y ejecutores de acciones. Existen módulos de identidad, DevSecOps, DNS, detección, auditoría, evidencias, casos, playbooks y plataforma. Los entrypoints restringidos de RedQueen, ARES e ingesta existen, pero la API principal continúa incluyendo esos routers y el Ingress dirige `/api` al monolito. Desplegar esos procesos adicionales no implica que el tráfico principal se distribuya entre ellos.

## Validación ejecutada

| Comprobación | Resultado observado |
|---|---|
| Backend con configuración local | 99 pruebas aprobadas y una fallida; parada por `--maxfail=1` |
| Backend con IA externa desactivada, acciones `dry_run` y controles en memoria | 393 pruebas aprobadas; cobertura 98,46 %, supera 90 % |
| Ruff: `app tests scripts` | Dos errores I001: `app/brain/router.py` y `scripts/local_gpu_exporter.py` |
| Mypy: `app` | Correcto en 261 archivos; avisa de cuerpos sin anotaciones no comprobados |
| Guarda de codificación | Correcta |
| `production_preflight.py` | Correcto; es una inspección estática de patrones, no una prueba del despliegue |
| ESLint frontend | Correcto |
| Vitest con cobertura | 34 pruebas aprobadas, tres omitidas; comando fallido por cobertura |
| Cobertura frontend | Líneas 80,82 %; sentencias 79,18 %; funciones 78,05 %; ramas 65,48 %; exige 100 % |
| Build frontend | Correcto |
| Alembic heads | Dos heads: `c2d3e4f5a6b7` y `g2h3i4j5k6l7` |

La primera ejecución falla en `test_ares_accepts_signed_human_approval_for_high_risk`: recibe `failed` en vez de `executed`. También intenta contactar con Ollama y cae al stub al fallar la conexión. La segunda ejecución demuestra que la suite puede pasar con configuración controlada; no demuestra funcionamiento con proveedores reales. Su salida quedó en `.test-data/project-analysis-pytest.txt`.

## Hallazgos prioritarios

### 1. Crítico: registro público con elección de rol administrativo

`app/routers/users.py:58` expone el alta sin autenticación cuando está habilitada. `UserCreate` acepta `role` y `app/repositories/user_repository.py:30` persiste ese valor sin restringirlo. Reproducción local con SQLite en memoria: una llamada al manejador de alta con `role=admin` crea un usuario administrativo.

El impacto está condicionado a tener registro público activo: la configuración de producción lo prohíbe, pero el valor predeterminado de Settings y de Compose es verdadero. Separar el contrato de registro del de alta administrativa y forzar `user` en el servidor. Añadir una prueba negativa de elevación de privilegios. La suite actual incluso usa registro público con rol admin en una fixture.

### 2. Alto: secretos locales incluidos potencialmente en la imagen Docker

`Dockerfile` utiliza `COPY . .`. `.dockerignore` no excluye `secrets/`, mientras que el workspace contiene un archivo de token en esa carpeta. `.gitignore` sí lo excluye, pero eso no controla el contexto de construcción local de Docker.

Una construcción desde este directorio puede incorporar el archivo a la imagen. Excluir explícitamente secretos y reducir el contexto de construcción. No se leyó ni divulgó el token. No se inspeccionaron imágenes históricas; la rotación sería necesaria si se confirma que alguna imagen construida así se distribuyó.

### 3. Alto: el despliegue pide una migración ambigua

`infra/k8s/job-migrate.yaml:24` ejecuta `alembic upgrade head`, pero el grafo tiene dos heads, comprobados con el CLI. Compose utiliza `upgrade heads`, por lo que ambos despliegues tampoco tienen el mismo comportamiento.

Unificar el grafo con una revisión de merge o documentar y ejecutar explícitamente ambas ramas. Probar migración desde base vacía y actualización desde la revisión anterior. El CD además actualiza los deployments antes de ejecutar la migración y crea el Job con una imagen base antes de intentar cambiarla; preparar el manifiesto final de migración con el SHA correcto antes de crearlo.

### 4. Alto: el modo multitenant no garantiza aislamiento de identidad y datos

`app/core/security.py:263` exige una cabecera en modo estricto, pero toma el tenant directamente del cliente sin comprobar pertenencia del usuario. El modelo User no contiene membresías de tenant; `VerdictRepository.get_by_id` filtra únicamente por identificador. Varios routers críticos solo exigen administrador o token de monitorización.

Hay persistencia de tenant en algunas entidades, pero no una frontera de aislamiento completa. Antes de ofrecer múltiples organizaciones: resolver tenant desde membresías autenticadas, aplicar autorización por recurso y filtrar todas las consultas relevantes; verificar que tenant A nunca lee, aprueba o ejecuta datos de B. Los administradores actuales deben considerarse globales.

### 5. Alto: el proveedor vectorial configurado no selecciona una implementación externa

`app/db/vector.py:100` siempre crea `LocalVectorStore`. Su método `status` devuelve el nombre configurado, aunque los datos estén en un diccionario del proceso. Reproducción: configurar `qdrant` da `provider=qdrant`, pero la clase sigue siendo `LocalVectorStore`.

Esto permite superar la comprobación de configuración productiva sin disponer del almacenamiento distribuido anunciado. Los datos se pierden al reiniciar y divergen entre réplicas. Implementar una fábrica de proveedores real y comprobar conectividad/persistencia; mientras tanto, declarar honestamente la limitación local. Los embeddings actuales son hashing de tokens, no un modelo semántico aprendido.

### 6. Alto: capacidad RBAC definida pero inaccesible a sus roles

`require_enterprise_capability` depende de `require_admin_or_monitor_token`, que solo admite `admin`, `administrator` y `superadmin`. Por tanto, `analyst`, `viewer`, `secops_lead` y `security_admin` pueden ser rechazados antes de comprobar sus capacidades declaradas en `enterprise_security.py`.

Separar autenticación y comprobación de capacidades. Además, el token de monitorización sirve como credencial de control administrativo y evita esa comprobación de capacidades: conviene separar la credencial de métricas de las identidades de automatización autorizadas para actuar.

### 7. Alto: correlación duplicada al escalar la API

`app/main.py:128` usa un `asyncio.Lock` local, y cada arranque crea su propio scheduler cuando está habilitado. El CD lo habilita y Kubernetes configura al menos dos réplicas de API, hasta diez con HPA.

Esto ejecuta el trabajo periódico en cada proceso. El motor tiene deduplicación de incidentes, pero esa lógica no convierte el lock en distribuido ni elimina carreras entre consultas e inserciones. Usar un scheduler dedicado o elección de líder con exclusión distribuida; mantener idempotencia de persistencia.

### 8. Medio-alto: capacidades operativas aún parciales

`app/runtime/orchestrator.py` mantiene una cola `deque` en memoria. Guarda `idempotency_key`, pero no deduplica por ella, y no se encontró un consumidor conectado a esa cola. La lista de dead letters tampoco tiene límite. No equivale todavía a una cola distribuida con reintentos.

`run_kafka_consumer` existe, pero no se encontró su activación desde los entrypoints de aplicación. Habilitar la variable Kafka no inicia por sí solo el consumo.

`connector_execute_plan` devuelve `delegated` sin efectuar una llamada externa. Los módulos de varios proveedores solo exportan su descripción de capacidades; esto debe distinguirse de las integraciones específicas implementadas en identidad, GitHub y ejecutores webhook. Documentar cada conector como contrato, simulación o integración verificada.

### 9. Medio-alto: degradación de IA poco explícita

`SafeAIProvider` solo selecciona Ollama de forma explícita; cualquier otro nombre selecciona el stub. Ante errores también devuelve el stub, sin distinción de entorno. La validación de producción rechaza el nombre `local_stub`, pero no valida una lista cerrada de proveedores soportados.

La política posterior puede bloquear acciones, por lo que esto no prueba una ejecución peligrosa automática. Sí permite presentar una decisión sintética como continuidad normal. Exigir proveedor soportado, indicar estado degradado y bloquear automatismos que requieran inferencia real cuando no esté disponible.

### 10. Medio: CI y pruebas no cubren las garantías declaradas

Los workflows revisados ejecutan lint y build del frontend, pero no Vitest ni su umbral de cobertura. `SecOpsPage` tiene 0,94 % de cobertura de líneas y `PlatformVisibilityPage` 3,5 %. Hay tres pruebas omitidas y avisos de navegación no implementada en jsdom.

El backend prueba principalmente sobre SQLite creado con `Base.metadata.create_all`, lo que no valida el grafo de Alembic ni las particularidades de PostgreSQL. La dependencia de configuración local explica diferencias de ejecución. Incorporar configuración de test explícita, migraciones reales y pruebas de aislamiento/autorización; no perseguir porcentajes sin comprobar resultados de negocio.

### 11. Medio: restricciones de red y salud incompletas

La NetworkPolicy permite entrada solo desde pods del mismo namespace. Si el controlador Ingress está en otro namespace, se necesitará una regla específica para que llegue a la aplicación. Es una incompatibilidad condicionada a la topología del cluster, no un fallo observado en uno desplegado.

Los checks básicos de salud consultan la base de datos, pero no prueban todos los componentes críticos. Un estado ready no acredita por sí solo Redis, proveedor IA, controladores de acciones o almacenamiento vectorial.

### 12. Medio: frontend, documentación y mantenimiento

El frontend centraliza correctamente las peticiones HTTP, pero no establece un contexto tenant general; solo algunos helpers añaden la cabecera. Esto deja flujos incompatibles con endpoints que la exigen en modo estricto. AuthContext interpreta JSON de localStorage sin protección frente a contenido corrupto y mantiene datos locales de usuario cuando falta el token; debe distinguir mejor sesión validada, estado offline y caché de interfaz.

README conserva cifras antiguas de pruebas y afirmaciones de fases que no representan uniformemente el estado actual. El código mezcla implementación funcional, contratos y placeholders bajo nombres productivos. Los servicios más grandes llegan a 1.155 y 866 líneas, elevando el coste de revisar autorizaciones y efectos externos.

## Fortalezas

Existe separación por dominios y capas, contratos Pydantic, pruebas extensas del backend y mecanismos de firma, aprobación humana y kill-switch. Hay soporte Redis para controles específicos, persistencia de evidencias y auditoría, y un frontend que compila y tiene lint limpio. Los manifiestos incluyen usuario no privilegiado, restricciones de capacidades, probes y recursos. Son bases útiles que conviene preservar.

## Orden de trabajo recomendado

1. Corregir alta administrativa pública y excluir secretos del contexto Docker.
2. Resolver el grafo de migraciones y verificar una instalación reproducible con PostgreSQL.
3. Definir si el siguiente piloto es de una sola organización; completar membresías, filtros y pruebas antes de activar multitenancy.
4. Corregir RBAC y separar credenciales de monitorización y ejecución.
5. Hacer reales los proveedores declarados y la persistencia vectorial; resolver scheduler y colas antes de escalar réplicas.
6. Integrar pruebas frontend en CI y validar un flujo completo con proveedor real en un entorno controlado.
7. Actualizar documentación y estados de disponibilidad según evidencia reproducible.

## Límites de la revisión

Se inspeccionó el inventario global y se profundizó en rutas críticas de seguridad, persistencia, IA, frontend y despliegue; no se afirma haber auditado cada línea. No se realizó pentest, validación visual en navegador, despliegue Kubernetes, prueba de carga, restauración de backups ni auditoría actualizada de vulnerabilidades de dependencias. No se verificaron credenciales o proveedores reales. El análisis no acredita preparación productiva por el mero hecho de superar pruebas locales.
