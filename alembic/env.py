# ==========================================================
# Alembic env.py â€” VAELQORIX.XDR_COMMAND (v3.3 Postgres Safe)
# UbicaciÃ³n: VAELQORIX/alembic/env.py
# ==========================================================
# âœ… Fuente de verdad de DB URL: app.core.settings (.env)
# âœ… Autogenerate: Base.metadata + import de modelos (side-effect)
# âœ… Postgres-ready: engine_from_config + NullPool (migraciones limpias)
# âœ… Windows-safe: sin hardcodear credenciales en alembic.ini
# ==========================================================

from __future__ import annotations

import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

# ----------------------------------------------------------
# Alembic Config (lee alembic.ini)
# ----------------------------------------------------------
config = context.config

# Logging segÃºn alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ----------------------------------------------------------
# âœ… Fuente de verdad: settings del proyecto
# ----------------------------------------------------------
# ----------------------------------------------------------
# âœ… Importar modelos para que Alembic los detecte en autogenerate
# (NO borrar aunque parezca unused)
# ----------------------------------------------------------
import app.models  # noqa: F401, E402
from app.core.config import settings  # noqa: E402

# ----------------------------------------------------------
# âœ… Metadata real
# ----------------------------------------------------------
from app.models.base import Base  # noqa: E402

target_metadata = Base.metadata


def get_url() -> str:
    """
    Devuelve la URL efectiva desde settings (.env).
    """
    if os.environ.get("ALEMBIC_DATABASE_URI"):
        return str(os.environ["ALEMBIC_DATABASE_URI"])
    return str(settings.SQLALCHEMY_DATABASE_URI)


def _is_sqlite(url: str) -> bool:
    return (url or "").lower().startswith("sqlite")


def run_migrations_offline() -> None:
    """
    OFFLINE:
      - No abre conexiÃ³n real
      - Genera SQL (Ãºtil para revisar)
    """
    url = get_url()

    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        compare_server_default=True,
        dialect_opts={"paramstyle": "named"},
        # SQLite a veces requiere batch mode para ALTER TABLE
        render_as_batch=_is_sqlite(url),
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    ONLINE:
      - Abre conexiÃ³n real contra la DB
      - Ejecuta migraciones
    """
    # âœ… Inyectamos la URL del settings en runtime (NO dependemos de alembic.ini)
    ini_section = config.get_section(config.config_ini_section) or {}
    ini_section["sqlalchemy.url"] = get_url()

    # âœ… NullPool: para migraciones es preferible no mantener pool abierto
    connectable = engine_from_config(
        ini_section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        future=True,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            # SQLite batch mode si fuese el caso
            render_as_batch=_is_sqlite(get_url()),
        )

        with context.begin_transaction():
            context.run_migrations()


# ----------------------------------------------------------
# Selector de modo
# ----------------------------------------------------------
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
