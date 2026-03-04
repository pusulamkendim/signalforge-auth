from __future__ import annotations

# EmailService — sends transactional emails via Resend and persists delivery
# records in the email_logs table. Each send is wrapped in a try/except so
# that a provider failure never crashes the calling request; the error is
# recorded in EmailLog instead.

from datetime import datetime, timezone

import resend
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import EmailLog, User
from app.core.config import get_auth_settings


class EmailService:
    """Send transactional emails via Resend and record every attempt in EmailLog."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        settings = get_auth_settings()
        resend.api_key = settings.resend_api_key
        self._from = settings.email_from
        self._frontend_url = settings.frontend_url

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def send_verification_email(self, user: User, plain_token: str) -> None:
        """Send the email-verification link and log the outcome."""
        link = f"{self._frontend_url}/verify-email?token={plain_token}"
        subject = "Please verify your email address"
        html = (
            f"<p>Hi,</p>"
            f"<p>Click the link below to verify your email address. "
            f"This link expires in 24 hours.</p>"
            f'<p><a href="{link}">Verify email</a></p>'
            f"<p>If you did not create an account, you can ignore this email.</p>"
        )
        await self._send(
            user=user,
            subject=subject,
            html=html,
            email_type="verification",
        )

    async def send_password_reset_email(self, user: User, plain_token: str) -> None:
        """Send the password-reset link and log the outcome."""
        link = f"{self._frontend_url}/reset-password?token={plain_token}"
        subject = "Reset your password"
        html = (
            f"<p>Hi,</p>"
            f"<p>Click the link below to reset your password. "
            f"This link expires in 1 hour.</p>"
            f'<p><a href="{link}">Reset password</a></p>'
            f"<p>If you did not request a password reset, you can ignore this email.</p>"
        )
        await self._send(
            user=user,
            subject=subject,
            html=html,
            email_type="password_reset",
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _send(
        self,
        user: User,
        subject: str,
        html: str,
        email_type: str,
    ) -> None:
        log = EmailLog(
            user_id=user.id,
            to_email=user.email,
            email_type=email_type,
            status="queued",
        )
        self.db.add(log)
        await self.db.flush()

        try:
            result = resend.Emails.send(
                {
                    "from": self._from,
                    "to": user.email,
                    "subject": subject,
                    "html": html,
                }
            )
            log.status = "sent"
            log.provider_id = result.get("id") if isinstance(result, dict) else None
            log.sent_at = datetime.now(timezone.utc)
        except Exception as exc:  # noqa: BLE001
            log.status = "failed"
            log.error = str(exc)

        await self.db.commit()
