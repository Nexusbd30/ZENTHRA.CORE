# app/scripts/fix_invalid_user_emails.py
# ==========================================================
# 🔧 Fix invalid user emails (SQL-only) — ZENTHRA
# ==========================================================
# Por qué SQL-only:
# - Tu modelo User tiene una relationship("ThreatModel")
# - Si ThreatModel no está importado cuando se configura el mapper,
#   SQLAlchemy explota al hacer db.query(User)
#
# Este script evita ORM y ejecuta SQL directo para:
# - Cambiar emails con dominio ".local" -> ".dev"
# - Desbloquear /users (Pydantic EmailStr rechaza ".local")
# ==========================================================

from __future__ import annotations

from sqlalchemy import text

from app.core.settings import settings
from app.db.session import SessionLocal

FROM_DOMAIN = ".local"
TO_DOMAIN = ".dev"


def main() -> None:
    print("✅ Script ejecutándose (SQL-only)...")
    print("🔎 DB =", settings.SQLALCHEMY_DATABASE_URI)

    db = SessionLocal()
    try:
        # Total usuarios
        total = db.execute(text("SELECT COUNT(*) FROM users")).scalar_one()
        print(f"📦 Total usuarios en DB: {total}")

        # Mostrar antes
        rows = db.execute(
            text("SELECT id, email, role FROM users ORDER BY email")
        ).fetchall()

        print("📋 Usuarios ANTES:")
        for r in rows:
            print(f"- {r.id} | {r.email} | {r.role}")

        # Update seguro: reemplaza .local al final por .dev
        result = db.execute(
            text(
                """
                UPDATE users
                SET email = regexp_replace(email, :from_domain || '$', :to_domain)
                WHERE email ~ (:from_domain || '$')
                """
            ),
            {"from_domain": FROM_DOMAIN, "to_domain": TO_DOMAIN},
        )
        updated = int(getattr(result, "rowcount", 0) or 0)
        db.commit()

        print(f"\n✅ Usuarios actualizados: {updated}\n")

        # Mostrar después
        rows_after = db.execute(
            text("SELECT id, email, role FROM users ORDER BY email")
        ).fetchall()

        print("📋 Usuarios DESPUÉS:")
        for r in rows_after:
            print(f"- {r.id} | {r.email} | {r.role}")

    finally:
        db.close()


if __name__ == "__main__":
    main()
