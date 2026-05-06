# ZENTHRA Frontend (React + Vite)

Frontend real-time para ZENTHRA.CORE_SECURITY. Consumimos el backend FastAPI y las rutas de observabilidad sin datos mock.

## Configuración

1) Copia `.env.example` a `.env` y rellena valores reales:
```
VITE_API_URL=http://<backend>/api        # o http://localhost:8000 si haces port-forward
VITE_ZENTHRA_MONITOR_TOKEN=<token-interno>  # el mismo que usa Prometheus para /monitoring/*
VITE_PROMETHEUS_PUBLIC_URL=http://<prometheus>:9090  # opcional
```

2) Instala dependencias:
```
npm install
```

3) Desarrollo:
```
npm run dev -- --host
```

4) Build producción:
```
npm run build
npm run preview   # sirve el build localmente para validar
```

## Despliegue con Docker

- Construye el frontend con `npm run build` y sirve `dist/` detrás del reverse proxy que expone el backend.
- Ajusta `VITE_API_URL` al dominio del proxy (idealmente mismo dominio + ruta `/api` para evitar CORS).
- Inyecta `VITE_ZENTHRA_MONITOR_TOKEN` solo en entornos seguros; no lo dejes vacío si usas las vistas de monitorización.

## Conexión sin mocks

- Todos los datos provienen del backend:
  - Alertas: `/monitoring/alerts/realtime` → Alertmanager.
  - Salud infra: `/monitoring/health/full`.
  - Usuarios/Amenazas: `/users`, `/threats`.
- Se eliminaron los mocks y cualquier dato ficticio; si un servicio no responde se mostrará error en pantalla.
