from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware


class AuditMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.logger = logging.getLogger("aresx.audit")

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        request_id = getattr(request.state, "request_id", "n/a")
        self.logger.info(
            "audit method=%s path=%s status=%s request_id=%s",
            request.method,
            request.url.path,
            response.status_code,
            request_id,
        )
        return response
