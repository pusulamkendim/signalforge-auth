from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class Meta(BaseModel):
    request_id: str
    timestamp: str  # ISO 8601


class SuccessResponse(BaseModel):
    success: bool = True
    data: Any
    meta: Meta


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: dict[str, Any] | None = None


class ErrorResponse(BaseModel):
    success: bool = False
    error: ErrorDetail
    meta: Meta
