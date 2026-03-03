from __future__ import annotations

from typing import Optional

from jose import JWTError, jwt


class LocalTokenVerifier:
    """Verifies JWTs locally without calling the auth service.

    Useful when the consuming service has the SECRET_KEY available
    and wants to avoid the HTTP round-trip overhead.

    **Warning:** This does NOT check revocation (token_version bump, explicit
    logout). Use AuthClient.verify_token() for full validation including
    revocation and session checks.
    """

    def __init__(self, secret_key: str, algorithm: str = "HS256") -> None:
        self._secret_key = secret_key
        self._algorithm = algorithm

    def verify_token(self, token: str) -> Optional[dict]:
        """Decode and verify a JWT locally. Returns the payload dict or None."""
        try:
            return jwt.decode(token, self._secret_key, algorithms=[self._algorithm])
        except JWTError:
            return None
