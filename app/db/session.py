# =============================================================
# ðŸ—„ï¸ session.py â€” DB Engine & Sessions (v3.19 Alembic-SAFE)
# VAELQORIX.XDR_COMMAND Â· Capa de Persistencia
# =============================================================
# Centraliza:
#   - CreaciÃ³n del engine de SQLAlchemy (SQLite / PostgreSQL)
#   - SessionLocal (sesiones por request / job)
#   - Dependency get_db() para FastAPI
#
# DiseÃ±o:
#   - SQLite en dev (simple, sin pool real)
#   - PostgreSQL en prod (pooling + pre_ping)
#   - Compatible con Alembic (engine Ãºnico y consistente)
# =============================================================

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Wrapper legacy â†’ fuente Ãºnica: app.core.settings.settings
from app.core.config import settings

# =============================================================
# ðŸ”Ž Helpers
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
# ðŸ”Œ Engine
# =============================================================
# Reglas:
# - SQLite:
#     â€¢ check_same_thread=False (FastAPI es multi-thread)
#     â€¢ Sin pooling real
# - PostgreSQL:
#     â€¢ pool_pre_ping=True  â†’ evita conexiones muertas
#     â€¢ pool_size razonable â†’ API + scheduler
#     â€¢ max_overflow        â†’ picos de carga
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
            "connect_args": {"connect_timeout": 5},
            "pool_pre_ping": True,   # detecta y recicla conexiones rotas
            "pool_size": 10,         # conexiones persistentes
            "max_overflow": 20,      # conexiones extra en picos
            "pool_recycle": 1800,    # recicla cada 30 min (opcional)
        }
    )

# Engine Ãºnico de la aplicaciÃ³n
# âš ï¸ Alembic debe usar ESTE engine indirectamente vÃ­a settings
engine = create_engine(DB_URI, **engine_kwargs)


# =============================================================
# ðŸ§© SessionLocal
# =============================================================
# ConfiguraciÃ³n elegida:
# - autocommit=False â†’ commits explÃ­citos
# - autoflush=False  â†’ control manual del flush
# - expire_on_commit=False
#     â€¢ Muy Ãºtil en APIs: permite devolver objetos tras commit
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
# ðŸ’‰ FastAPI Dependency â€” get_db
# =============================================================
def get_db():
    """
    Crea una sesiÃ³n de BD por request / job.

    Uso tÃ­pico:
        def endpoint(db: Session = Depends(get_db)):
            ...

    GarantÃ­as:
      - Siempre cierra la sesiÃ³n
      - Compatible con:
          â€¢ Requests HTTP
          â€¢ Background tasks
          â€¢ Scheduler / correlation engine
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
