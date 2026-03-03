from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

_AUTH_PREFIX = "/api/v1/auth/"

STATUS_CODES: dict[int, str] = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    409: "CONFLICT",
    422: "VALIDATION_ERROR",
    429: "TOO_MANY_REQUESTS",
    500: "INTERNAL_SERVER_ERROR",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class AuthEnvelopeMiddleware(BaseHTTPMiddleware):
    """Wrap /api/v1/auth/* responses in a standard success/error envelope.

    All other paths pass through unchanged so existing endpoints are unaffected.

    Middleware execution order (outermost → innermost):
        CORSMiddleware → AuthEnvelopeMiddleware → attach_request_id → route

    Because attach_request_id sets request.state.request_id *before* it calls
    its own call_next, the value is available here when we wrap the response.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        if not request.url.path.startswith(_AUTH_PREFIX):
            return await call_next(request)

        response = await call_next(request)

        # Consume the body iterator exactly once.
        raw_body: bytes = b"".join([chunk async for chunk in response.body_iterator])

        # request_id is set by the inner attach_request_id middleware.
        # Fall back to a fresh UUID if the middleware order is ever misconfigured.
        request_id: str = getattr(request.state, "request_id", None) or str(uuid4())

        meta = {
            "request_id": request_id,
            "timestamp": _now_iso(),
        }

        try:
            original = json.loads(raw_body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            original = raw_body.decode(errors="replace")

        if 200 <= response.status_code < 300:
            envelope = {
                "success": True,
                "data": original,
                "meta": meta,
            }
        else:
            # Extract the human-readable message from FastAPI's error body.
            if isinstance(original, dict):
                raw_detail = original.get("detail", "An error occurred")
                # Validation errors surface detail as a list of error objects.
                if isinstance(raw_detail, list):
                    message: str = "; ".join(
                        str(item.get("msg", item)) for item in raw_detail
                    )
                else:
                    message = str(raw_detail)
            else:
                message = str(original)

            code = STATUS_CODES.get(response.status_code, "ERROR")
            envelope = {
                "success": False,
                "error": {
                    "code": code,
                    "message": message,
                    "details": None,
                },
                "meta": meta,
            }

        new_response = JSONResponse(
            content=envelope,
            status_code=response.status_code,
        )

        # Forward the X-Request-ID header that attach_request_id placed on the
        # inner response so callers can correlate logs without parsing the body.
        x_req_id = response.headers.get("x-request-id")
        if x_req_id:
            new_response.headers["X-Request-ID"] = x_req_id

        return new_response
