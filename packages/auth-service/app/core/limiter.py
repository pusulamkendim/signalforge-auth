from __future__ import annotations

# Rate limiter singleton — shared across the application.
# Import ``limiter`` and ``_rate_limit_exceeded_handler`` in main.py,
# then decorate endpoints with @limiter.limit("N/period").

from slowapi import Limiter, _rate_limit_exceeded_handler  # noqa: F401
from slowapi.errors import RateLimitExceeded  # noqa: F401
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
