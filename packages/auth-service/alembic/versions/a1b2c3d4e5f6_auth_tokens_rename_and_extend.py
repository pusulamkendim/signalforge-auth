"""auth_tokens_rename_and_extend

Rename email_verification_tokens → auth_tokens,
add ip_address / user_agent columns,
drop the unused new_email column,
and normalise the token type value from 'email_confirm' to 'email_verification'.

Revision ID: a1b2c3d4e5f6
Revises: 71e2f77f8e8e
Create Date: 2026-03-04 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = "71e2f77f8e8e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Rename table
    op.rename_table("email_verification_tokens", "auth_tokens")

    # 2. Add missing columns
    op.add_column("auth_tokens", sa.Column("ip_address", sa.String(), nullable=True))
    op.add_column("auth_tokens", sa.Column("user_agent", sa.String(), nullable=True))

    # 3. Drop the email-change column (out of scope for this feature)
    op.drop_column("auth_tokens", "new_email")

    # 4. Normalise type value: 'email_confirm' → 'email_verification'
    op.execute(
        "UPDATE auth_tokens SET type = 'email_verification' WHERE type = 'email_confirm'"
    )


def downgrade() -> None:
    # Reverse order

    # 4. Restore original type value
    op.execute(
        "UPDATE auth_tokens SET type = 'email_confirm' WHERE type = 'email_verification'"
    )

    # 3. Restore new_email column
    op.add_column(
        "auth_tokens",
        sa.Column("new_email", sa.String(), nullable=True),
    )

    # 2. Drop added columns
    op.drop_column("auth_tokens", "user_agent")
    op.drop_column("auth_tokens", "ip_address")

    # 1. Rename back
    op.rename_table("auth_tokens", "email_verification_tokens")
