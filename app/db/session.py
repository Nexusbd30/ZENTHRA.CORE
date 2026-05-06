# =============================================================
# 🗄️ session.py — DB Engine & Sessions (v3.19 Alembic-SAFE)
# ZENTHRA.CORE_SECURITY · Capa de Persistencia
# =============================================================
# Centraliza:
#   - Creación del engine de SQLAlchemy (SQLite / PostgreSQL)
#   - SessionLocal (sesiones por request / job)
#   - Dependency get_db() para FastAPI
#
# Diseño:
#   - SQLite en dev (simple, sin pool real)
#   - PostgreSQL en prod (pooling + pre_ping)
#   - Compatible con Alembic (engine único y consistente)
# =============================================================

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Wrapper legacy → fuente única: app.core.settings.settings
from app.core.config import settings

# =============================================================
# 🔎 Helpers
# =============================================================

def _is_sqlite(uri: str) -> bool:
    """
    Detecta si el backend es SQLite.
    Se usa para ajustar argumentos del engine.
    """
    return (uri or "").strip().lower().startswith("sqlite")


# URI efectiva de la DB (ya procesada por settings.py)
DB_URI = (settings.SQLALCHEMY_DATABASE_URI or "").strip()

# Flag de backend
IS_SQLITE = _is_sqlite(DB_URI)


# =============================================================
# 🔌 Engine
# =============================================================
# Reglas:
# - SQLite:
#     • check_same_thread=False (FastAPI es multi-thread)
#     • Sin pooling real
# - PostgreSQL:
#     • pool_pre_ping=True  → evita conexiones muertas
#     • pool_size razonable → API + scheduler
#     • max_overflow        → picos de carga
#
# future=True:
#   - Activa comportamiento SQLAlchemy 2.x
# =============================================================

engine_kwargs: dict[str, object] = {
    "future": True,
}

if IS_SQLITE:
    # SQLite (DEV)
    engine_kwargs["connect_args"] = {
        "check_same_thread": False
    }
else:
    # PostgreSQL (PROD / DEV avanzado)
    engine_kwargs.update(
        {
            "pool_pre_ping": True,   # detecta y recicla conexiones rotas
            "pool_size": 10,         # conexiones persistentes
            "max_overflow": 20,      # conexiones extra en picos
            "pool_recycle": 1800,    # recicla cada 30 min (opcional)
        }
    )

# Engine único de la aplicación
# ⚠️ Alembic debe usar ESTE engine indirectamente vía settings
engine = create_engine(DB_URI, **engine_kwargs)


# =============================================================
# 🧩 SessionLocal
# =============================================================
# Configuración elegida:
# - autocommit=False → commits explícitos
# - autoflush=False  → control manual del flush
# - expire_on_commit=False
#     • Muy útil en APIs: permite devolver objetos tras commit
#       sin reconsultar la DB
# =============================================================

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
    future=True,
)


# =============================================================
# 💉 FastAPI Dependency — get_db
# =============================================================
def get_db():
    """
    Crea una sesión de BD por request / job.

    Uso típico:
        def endpoint(db: Session = Depends(get_db)):
            ...

    Garantías:
      - Siempre cierra la sesión
      - Compatible con:
          • Requests HTTP
          • Background tasks
          • Scheduler / correlation engine
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
