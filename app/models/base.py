# =============================================================
# 🧱 Base ORM — ZENTHRA.CORE_SECURITY
# =============================================================
# Punto central para la base declarativa de SQLAlchemy.
#
# - Todos los modelos deben heredar de `Base`.
# - Compatible con SQLAlchemy 2.x.
# =============================================================

from sqlalchemy.orm import declarative_base

Base = declarative_base()