from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session


def db_check(db: Session) -> dict:
    try:
        db.execute(text("SELECT 1"))
        return {"name": "database", "status": "up"}
    except Exception as exc:
        return {"name": "database", "status": "down", "error": str(exc)}


def app_check() -> dict:
    return {"name": "app", "status": "up"}


def run_checks(db: Session) -> dict:
    checks = [app_check(), db_check(db)]
    overall = "up" if all(c["status"] == "up" for c in checks) else "degraded"
    return {"overall": overall, "checks": checks}
