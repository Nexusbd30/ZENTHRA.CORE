# app/core/bootstrap_admin.py
# ==========================================================
# 👑 Bootstrap Admin — ZENTHRA.CORE_SECURITY
# ==========================================================
# Responsabilidad:
#   - Crear un usuario administrador inicial de forma SEGURA
#   - Comportamiento IDEMPOTENTE (no duplica usuarios)
#   - Controlado 100% por variables de entorno (.env)
#
# Cuándo se ejecuta:
#   - En el startup de la aplicación (desde main.py)
#
# Por qué existe:
#   - Evitar seeds hardcodeados en main.py
#   - Evitar errores de validación (EmailStr, etc.)
#   - Permitir despliegues limpios en DEV / PROD
# ==========================================================

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

# ----------------------------------------------------------
# 🔐 Utilidad de seguridad para hashear contraseñas
# ----------------------------------------------------------
from app.core.security import get_password_hash

# ----------------------------------------------------------
# ⚙️ Settings globales de la aplicación
# ----------------------------------------------------------
# Aquí se leen las variables:
#   - BOOTSTRAP_ADMIN_ENABLED
#   - BOOTSTRAP_ADMIN_EMAIL
#   - BOOTSTRAP_ADMIN_PASSWORD
from app.core.settings import settings

# ----------------------------------------------------------
# 🧱 Modelo de usuario (SQLAlchemy)
# ----------------------------------------------------------
from app.models.user import User

# ----------------------------------------------------------
# 📝 Logger de la aplicación
# ----------------------------------------------------------
logger = logging.getLogger("zenthra")


def bootstrap_admin(db: Session) -> None:
    """
    Crea un usuario administrador inicial de forma controlada.

    Reglas de funcionamiento:
    --------------------------------------------------------
    1) SOLO se ejecuta si:
       BOOTSTRAP_ADMIN_ENABLED = true

    2) Requiere obligatoriamente:
       - BOOTSTRAP_ADMIN_EMAIL
       - BOOTSTRAP_ADMIN_PASSWORD

    3) Es IDEMPOTENTE:
       - Si el usuario ya existe → NO se crea otro
       - Si existe pero no es admin → se promociona a admin

    4) Nunca lanza excepciones hacia fuera:
       - Si algo falta, lo deja en logs y sale
    """

    # ------------------------------------------------------
    # 🔒 Feature flag de seguridad
    # ------------------------------------------------------
    # Si el bootstrap no está habilitado explícitamente,
    # salimos sin hacer absolutamente nada.
    if not getattr(settings, "BOOTSTRAP_ADMIN_ENABLED", False):
        return

    # ------------------------------------------------------
    # 📥 Leer variables de entorno
    # ------------------------------------------------------
    # Normalizamos el email:
    #   - strip() → elimina espacios
    #   - lower() → evita duplicados por mayúsculas
    email = (getattr(settings, "BOOTSTRAP_ADMIN_EMAIL", "") or "").strip().lower()

    # La contraseña se usa SOLO para generar el hash
    password = getattr(settings, "BOOTSTRAP_ADMIN_PASSWORD", None)

    # ------------------------------------------------------
    # ⚠️ Validación mínima de configuración
    # ------------------------------------------------------
    if not email or not password:
        logger.warning(
            "⚠️ Bootstrap admin habilitado pero faltan "
            "BOOTSTRAP_ADMIN_EMAIL o BOOTSTRAP_ADMIN_PASSWORD"
        )
        return

    # ------------------------------------------------------
    # 🔍 Buscar si el usuario ya existe
    # ------------------------------------------------------
    existing = db.query(User).filter(User.email == email).first()

    if existing:
        # --------------------------------------------------
        # 🛠️ Caso: el usuario ya existe
        # --------------------------------------------------
        # No duplicamos usuarios.
        # Si por cualquier motivo no tiene rol admin,
        # lo promocionamos (útil tras migraciones).
        if getattr(existing, "role", None) != "admin":
            existing.role = "admin"
            db.add(existing)
            db.commit()

            logger.info(
                "✅ Bootstrap admin: usuario existente promovido a admin (%s)",
                email,
            )
        return

    # ------------------------------------------------------
    # 🆕 Crear usuario administrador nuevo
    # ------------------------------------------------------
    admin = User(
        full_name="ZENTHRA SuperAdmin",
        email=email,
        hashed_password=get_password_hash(password),
        role="admin",
        is_active=True,
    )

    # Persistir en base de datos
    db.add(admin)
    db.commit()

    logger.info("🟢 Bootstrap admin creado (%s)", email)
