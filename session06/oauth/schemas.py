"""
Session 6 OAuth Supplement: Pydantic Schemas

Request and response schemas for the dual-auth API:

- UserCreate / UserResponse: Registration and user info responses.
- Token: JWT token response (shared by both password and OAuth flows).
- OAuthUserInfo: Parsed user profile from GitLab's /api/v4/user endpoint.
"""

from pydantic import BaseModel, ConfigDict, Field
from typing import Optional


# =============================================================================
# User Schemas
# =============================================================================

class UserCreate(BaseModel):
    """Schema for password-based user registration."""
    username: str = Field(..., min_length=1, max_length=100)
    email: str = Field(..., description="User email address")
    password: str = Field(
        ..., min_length=8, description="Password (min 8 characters)"
    )


class UserResponse(BaseModel):
    """
    Schema for user responses.

    Never includes password or hash fields.
    model_config enables reading from SQLAlchemy model instances.
    """
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: Optional[str] = None
    is_active: bool


# =============================================================================
# Token Schema
# =============================================================================

class Token(BaseModel):
    """
    JWT token response.

    OAuth2 specification requires 'access_token' and 'token_type' fields.
    This schema is returned by both POST /token and GET /auth/callback.
    """
    access_token: str
    token_type: str = "bearer"


# =============================================================================
# OAuth Schemas
# =============================================================================

class OAuthUserInfo(BaseModel):
    """
    User profile data returned by GitLab's /api/v4/user endpoint.

    Only the fields needed for account creation are included.
    GitLab returns many more fields; these are the ones we use.
    """
    id: int
    username: str
    email: Optional[str] = None
    name: Optional[str] = None
    avatar_url: Optional[str] = None
