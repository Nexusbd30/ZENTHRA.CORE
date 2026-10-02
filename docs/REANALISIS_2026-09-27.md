# Reanálisis del proyecto — 27 de septiembre de 2026

Revisión local sobre HEAD `9b8789c`. Se conserva sin modificar el informe previo `ANALISIS_TECNICO_2026-09-27.md`. No se modificó código de aplicación ni se desplegaron servicios.

## Dictamen

La base funcional es amplia: backend FastAPI modular, consola React, persistencia SQL y controles de firma, aprobación y ejecución. Sin embargo, los bloqueos de autorización, aislamiento y despliegue siguen presentes. No hay evidencia suficiente para considerarlo listo para producción multitenant.

## Comprobaciones repetidas

| Comprobación | Resultado actual |
|---|---|
| Backend pytest, IA `local_stub`, acciones `dry_run`, controles en memoria | 393 pruebas aprobadas; cobertura 98,46 %; supera el umbral del 90 % |
| Ruff sobre app, tests y scripts | Dos I001 en `app/brain/router.py` y `scripts/local_gpu_exporter.py` |
| Alembic mediante `venv/Scripts/alembic.exe heads` | Dos heads: `c2d3e4f5a6b7` y `g2h3i4j5k6l7` |
| ESLint frontend | Correcto |
| Build frontend | Correcto |
| Vitest con cobertura | 34 aprobadas, 3 omitidas; falla el umbral del 100 % |
| Cobertura frontend | Líneas 80,82 %; ramas 65,48 %; funciones 78,20 %; sentencias 79,22 % |

La salida backend está en `.test-data/reanalysis-pytest.txt`. Las pruebas backend usan SQLite y creación de tablas con metadata; no verifican las migraciones reales ni las integraciones de producción. En esta revisión no se repitieron mypy, auditoría de dependencias, pruebas visuales, carga ni despliegues.

## Hallazgos confirmados por lectura actual

1. **Crítico si se habilita el registro público:** `app/routers/users.py:58` permite alta sin autenticación; `UserCreate` acepta `role` y `app/repositories/user_repository.py:30` lo persiste. La configuración productiva prohíbe registro público, pero Settings y Compose lo activan por defecto. Forzar el rol básico en el alta pública y separar el alta administrativa.
2. **Alto, contexto Docker:** `Dockerfile:8` copia el contexto completo y `.dockerignore` no excluye `secrets/`, carpeta presente en el workspace. Una construcción local puede incluir su contenido. No se leyeron secretos ni se inspeccionaron imágenes distribuidas.
3. **Alto, migraciones:** Kubernetes usa `upgrade head` con dos heads. Los workflows actualizan las imágenes de aplicaciones antes de migrar y crean el Job antes de intentar cambiar su imagen. Unificar el grafo y preparar el Job con la imagen correcta antes de ejecutarlo.
4. **Alto, aislamiento y RBAC:** `app/core/security.py:263` toma el tenant de una cabecera sin comprobar membresía. Su dependencia previa solo admite administradores o token de monitorización, lo que impide llegar a la comprobación de capacidades a otros roles. El token de monitorización evita esa comprobación. `VerdictRepository.get_by_id` tampoco filtra tenant.
5. **Alto, almacenamiento anunciado:** `app/db/vector.py:100` instancia siempre `LocalVectorStore`, mientras `status()` muestra el proveedor configurado. No representa una integración vectorial externa ni persistencia entre reinicios.
6. **Medio-alto, procesamiento incompleto:** `app/runtime/orchestrator.py` guarda trabajos en una deque local, no deduplica la clave de idempotencia y acumula dead letters sin límite. La búsqueda de `run_kafka_consumer` en app solo encuentra su definición; no se localizó activación desde los entrypoints.
7. **Medio, calidad:** siguen fallando Ruff y el umbral frontend. CI ejecuta lint y build del frontend, pero no su suite Vitest. SecOpsPage tiene 0,94 % de cobertura de líneas y PlatformVisibilityPage 3,5 %.

## Hallazgo adicional: logs globales accesibles a usuarios básicos

`app/routers/users.py:109` expone `/users/runtime-logs` a cualquier usuario activo. En la línea 122 descarta la identidad y llama a `list_runtime_logs` sin contexto de usuario o tenant. `app/services/runtime_log_service.py:23` lee archivos globales y la línea 111 devuelve además la línea original en `raw`.

Esto permite a un usuario básico consultar actividad global cuando hay logs disponibles. La sensibilidad concreta depende de lo que se haya registrado; no se afirma que los archivos contengan credenciales. Restringir la capacidad de lectura y, para multitenancy, almacenar y filtrar eventos por tenant desde el origen. Incorporar pruebas negativas de usuario básico y de acceso entre organizaciones.

## Prioridad de corrección

1. Cerrar elevación de privilegios por registro, acceso general a logs e inclusión de secretos en imágenes.
2. Resolver migraciones y validar una instalación PostgreSQL desde cero.
3. Completar membresías, autorización por recurso y separación del token de monitorización.
4. Implementar persistencia e integraciones que correspondan a los proveedores declarados; cerrar consumidores y deduplicación antes de escalar.
5. Corregir Ruff e incorporar pruebas frontend a CI con cobertura de flujos críticos.

Los resultados locales muestran estabilidad de lo probado bajo simulación, pero no acreditan aislamiento entre organizaciones ni funcionamiento con proveedores reales.
