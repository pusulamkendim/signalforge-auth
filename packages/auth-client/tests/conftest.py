from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from auth_client.client import AuthClient


@pytest.fixture
def mock_auth_client() -> MagicMock:
    """AuthClient with verify_token mocked — no HTTP calls."""
    client = MagicMock(spec=AuthClient)
    client.verify_token = AsyncMock()
    return client
