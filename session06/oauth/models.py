"""
Session 6 OAuth Supplement: SQLAlchemy ORM Models

Two models support dual authentication (password + OAuth):

- User: Local user account. hashed_password is nullable so that
  OAuth-only users (who never set a password) can exist.
- OAuthAccount: Links a provider identity (e.g., GitLab user ID)
  to a local User. The UniqueConstraint on (provider, provider_user_id)
  prevents duplicate OAuth links.

See the supplement slides Step 5 for the matching code.
"""

from sqlalchemy import (
    Column, Integer, String, Boolean, ForeignKey, UniqueConstraint
)
from sqlalchemy.orm import relationship

from database import Base


class User(Base):
    """
    Local user account.

    Attributes:
        id: Primary key.
        username: Unique username (from OAuth provider or registration).
        email: Email address.
        hashed_password: Bcrypt hash, or None for OAuth-only users.
        is_active: Whether the account is active.
        oauth_accounts: Linked OAuth provider accounts.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, nullable=True)
    hashed_password = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)

    oauth_accounts = relationship("OAuthAccount", back_populates="user")

    def __repr__(self) -> str:
        return f"<User(id={self.id}, username='{self.username}')>"


class OAuthAccount(Base):
    """
    Links an external OAuth identity to a local User.

    Attributes:
        id: Primary key.
        user_id: Foreign key to users.id.
        provider: OAuth provider name (e.g., "gitlab", "github").
        provider_user_id: The user's ID at the provider (as a string).

    The UniqueConstraint ensures each provider identity maps to exactly
    one local account.
    """
    __tablename__ = "oauth_accounts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    provider = Column(String, nullable=False)
    provider_user_id = Column(String, nullable=False)

    user = relationship("User", back_populates="oauth_accounts")

    __table_args__ = (
        UniqueConstraint("provider", "provider_user_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<OAuthAccount(provider='{self.provider}', "
            f"provider_user_id='{self.provider_user_id}')>"
        )
