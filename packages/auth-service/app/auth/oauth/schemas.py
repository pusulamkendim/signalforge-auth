from __future__ import annotations

from pydantic import BaseModel, Field


class OAuthExchangeRequest(BaseModel):
    """Request body for POST /oauth/exchange."""

    code: str = Field(..., min_length=32)
