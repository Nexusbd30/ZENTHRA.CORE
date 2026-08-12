# app/core/bootstrap_admin.py
# ==========================================================
# ðŸ‘‘ Bootstrap Admin â€” VAELQORIX.XDR_COMMAND
# ==========================================================
# Responsabilidad:
#   - Crear un usuario administrador inicial de forma SEGURA
#   - Comportamiento IDEMPOTENTE (no duplica usuarios)
#   - Controlado 100% por variables de entorno (.env)
#
# CuÃ¡ndo se ejecuta:
#   - En el startup de la aplicaciÃ³n (desde main.py)
#
# Por quÃ© existe:
#   - Evitar seeds hardcodeados en main.py
#   - Evitar errores de validaciÃ³n (EmailStr, etc.)
#   - Permitir despliegues limpios en DEV / PROD
# ==========================================================

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

# ----------------------------------------------------------
# ðŸ” Utilidad de seguridad para hashear contraseÃ±as
# ----------------------------------------------------------
from app.core.security import get_password_hash

# ----------------------------------------------------------
# âš™ï¸ Settings globales de la aplicaciÃ³n
# ----------------------------------------------------------
# AquÃ­ se leen las variables:
#   - BOOTSTRAP_ADMIN_ENABLED
#   - BOOTSTRAP_ADMIN_EMAIL
#   - BOOTSTRAP_ADMIN_PASSWORD
from app.core.settings import settings

# ----------------------------------------------------------
# ðŸ§± Modelo de usuario (SQLAlchemy)
# ----------------------------------------------------------
from app.models.user import User

# ----------------------------------------------------------
# ðŸ“ Logger de la aplicaciÃ³n
# ----------------------------------------------------------
logger = logging.getLogger("vaelqorix")


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
       - Si el usuario ya existe â†’ NO se crea otro
       - Si existe pero no es admin â†’ se promociona a admin

    4) Nunca lanza excepciones hacia fuera:
       - Si algo falta, lo deja en logs y sale
    """

    # ------------------------------------------------------
    # ðŸ”’ Feature flag de seguridad
    # ------------------------------------------------------
    # Si el bootstrap no estÃ¡ habilitado explÃ­citamente,
    # salimos sin hacer absolutamente nada.
    if not getattr(settings, "BOOTSTRAP_ADMIN_ENABLED", False):
        return

    # ------------------------------------------------------
    # ðŸ“¥ Leer variables de entorno
    # ------------------------------------------------------
    # Normalizamos el email:
    #   - strip() â†’ elimina espacios
    #   - lower() â†’ evita duplicados por mayÃºsculas
    email = (getattr(settings, "BOOTSTRAP_ADMIN_EMAIL", "") or "").strip().lower()

    # La contraseÃ±a se usa SOLO para generar el hash
    password = getattr(settings, "BOOTSTRAP_ADMIN_PASSWORD", None)

    # ------------------------------------------------------
    # âš ï¸ ValidaciÃ³n mÃ­nima de configuraciÃ³n
    # ------------------------------------------------------
    if not email or not password:
        logger.warning(
            "âš ï¸ Bootstrap admin habilitado pero faltan "
            "BOOTSTRAP_ADMIN_EMAIL o BOOTSTRAP_ADMIN_PASSWORD"
        )
        return

    # ------------------------------------------------------
    # ðŸ” Buscar si el usuario ya existe
    # ------------------------------------------------------
    existing = db.query(User).filter(User.email == email).first()

    if existing:
        # --------------------------------------------------
        # ðŸ› ï¸ Caso: el usuario ya existe
        # --------------------------------------------------
        # No duplicamos usuarios.
        # Si por cualquier motivo no tiene rol admin,
        # lo promocionamos (Ãºtil tras migraciones).
        if getattr(existing, "role", None) != "admin":
            existing.role = "admin"
            db.add(existing)
            db.commit()

            logger.info(
                "âœ… Bootstrap admin: usuario existente promovido a admin (%s)",
                email,
            )
        return

    # ------------------------------------------------------
    # ðŸ†• Crear usuario administrador nuevo
    # ------------------------------------------------------
    admin = User(
        full_name="VAELQORIX SuperAdmin",
        email=email,
        hashed_password=get_password_hash(password),
        role="admin",
        is_active=True,
    )

    # Persistir en base de datos
    db.add(admin)
    db.commit()

    logger.info("ðŸŸ¢ Bootstrap admin creado (%s)", email)
