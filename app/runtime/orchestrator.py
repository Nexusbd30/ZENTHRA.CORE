from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import or_, text, update
from sqlalchemy.exc import IntegrityError

from app.core.settings import settings
from app.core.tenant_context import current_tenant
from app.db.session import SessionLocal
from app.models.runtime_state import RuntimeJob


class RuntimeQueue:
    """Durable tenant jobs with unique keys and fenced worker leases."""

    def __init__(self, name: str, max_size: int = 1000, session_factory=None, max_attempts: int = 3):
        self.name = name
        self.max_size = max_size
        self.session_factory = session_factory
        self.max_attempts = max_attempts

    def _session(self):
        db = (self.session_factory or SessionLocal)()
        db.info["tenant_id"] = current_tenant.get() or settings.DEFAULT_TENANT_ID
        return db

    def _lock(self, db):
        if db.get_bind().dialect.name == "postgresql":
            key = int.from_bytes(hashlib.sha256(f"{db.info['tenant_id']}:{self.name}".encode()).digest()[:8], "big", signed=True)
            db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})
        elif db.get_bind().dialect.name == "sqlite":
            db.execute(text("BEGIN IMMEDIATE"))

    def _query(self, db):
        return db.query(RuntimeJob).filter(RuntimeJob.queue == self.name)

    @staticmethod
    def _payload(row):
        return {"job_id": row.job_id, "idempotency_key": row.idempotency_key,
                "payload": json.loads(row.payload_json), "status": row.status,
                "queued_at": row.queued_at.isoformat(), "attempts": row.attempts,
                "lease_token": row.lease_token}

    def enqueue(self, payload: dict, *, idempotency_key: str | None = None) -> dict:
        key = idempotency_key or uuid4().hex
        serialized = json.dumps(payload, sort_keys=True)
        with self._session() as db:
            self._lock(db)
            previous = self._query(db).filter(RuntimeJob.idempotency_key == key).first()
            if previous:
                if previous.payload_json != serialized:
                    raise HTTPException(status_code=409, detail="Idempotency key reused with different payload")
                return {"status": previous.status, "job": self._payload(previous), "duplicate": True}
            if self._query(db).filter(RuntimeJob.status.in_(["queued", "running"])).count() >= self.max_size:
                return {"status": "backpressure", "reason": "queue_capacity"}
            row = RuntimeJob(queue=self.name, idempotency_key=key, payload_json=serialized, status="queued")
            db.add(row)
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                previous = self._query(db).filter(RuntimeJob.idempotency_key == key).one()
                if previous.payload_json != serialized:
                    raise HTTPException(status_code=409, detail="Idempotency key reused with different payload") from None
                return {"status": previous.status, "job": self._payload(previous), "duplicate": True}
            return {"status": "queued", "job": self._payload(row), "duplicate": False}

    def claim(self, *, lease_seconds: int = 60) -> dict | None:
        now = datetime.utcnow()
        with self._session() as db:
            eligible = or_(RuntimeJob.status == "queued", (RuntimeJob.status == "running") & (RuntimeJob.lease_until < now))
            for row in self._query(db).filter(eligible).order_by(RuntimeJob.queued_at).all():
                token = uuid4().hex
                claimed = db.execute(update(RuntimeJob).where(
                    RuntimeJob.job_id == row.job_id, eligible,
                ).values(status="running", attempts=RuntimeJob.attempts + 1, lease_token=token,
                         lease_until=now + timedelta(seconds=max(1, lease_seconds))))
                db.commit()
                if claimed.rowcount:
                    db.refresh(row)
                    if row.attempts > self.max_attempts:
                        row.status = "dead_letter"
                        row.error = "worker_lease_exhausted"
                        db.commit()
                        continue
                    return self._payload(row)
        return None

    def finish(self, job_id: str, lease_token: str, *, error: str = "") -> bool:
        with self._session() as db:
            row = self._query(db).filter(RuntimeJob.job_id == job_id, RuntimeJob.status == "running",
                                         RuntimeJob.lease_token == lease_token,
                                         RuntimeJob.lease_until >= datetime.utcnow()).first()
            if row is None:
                return False
            status = "completed" if not error else ("dead_letter" if row.attempts >= self.max_attempts else "queued")
            changed = db.execute(update(RuntimeJob).where(
                RuntimeJob.job_id == job_id, RuntimeJob.lease_token == lease_token,
                RuntimeJob.status == "running", RuntimeJob.lease_until >= datetime.utcnow(),
            ).values(status=status, error=error[:2000], lease_token="", lease_until=None))
            db.commit()
            return bool(changed.rowcount)

    def prune(self, *, retention_days: int = 30) -> int:
        with self._session() as db:
            count = self._query(db).filter(RuntimeJob.status.in_(["completed", "dead_letter"]),
                RuntimeJob.queued_at < datetime.utcnow() - timedelta(days=max(1, retention_days))).delete()
            db.commit()
            return count

    @property
    def items(self):
        with self._session() as db:
            return [self._payload(row) for row in self._query(db).filter(RuntimeJob.status == "queued").all()]

    def stats(self) -> dict:
        with self._session() as db:
            return {"name": self.name, "queued": self._query(db).filter(RuntimeJob.status == "queued").count(),
                    "dead_letters": self._query(db).filter(RuntimeJob.status == "dead_letter").count(),
                    "max_size": self.max_size, "persistent": True, "backend": "sql"}


PLAYBOOK_QUEUE = RuntimeQueue("playbook-execution")
