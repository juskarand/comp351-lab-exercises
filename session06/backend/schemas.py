"""
Session 6: Pydantic Schemas for Authentication

This module includes schemas for:
- User registration and response
- Authentication tokens
- Task operations (now user-scoped)
"""

from pydantic import BaseModel, ConfigDict, Field, EmailStr
from typing import Optional
from datetime import datetime


# =============================================================================
# User Schemas
# =============================================================================

class UserCreate(BaseModel):
    """
    Schema for user registration.

    EmailStr validates that the email format is correct.
    Password minimum length is enforced via Field constraints.
    """
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="Password (min 8 characters)")


class LoginRequest(BaseModel):
    """
    Schema for JSON-based login.

    Used by the /login endpoint as an alternative to the OAuth2
    form-based /token endpoint.
    """
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., description="User password")


class User(BaseModel):
    """
    Schema for user responses.

    Note: Never include password/hashed_password in response schemas!
    model_config enables reading from SQLAlchemy model instances.
    """
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    is_active: bool


# =============================================================================
# Token Schemas
# =============================================================================

class Token(BaseModel):
    """
    Schema for JWT token response.

    OAuth2 specification requires 'access_token' and 'token_type' fields.
    """
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """
    Schema for data extracted from JWT token.

    This is used internally after decoding a token.
    """
    email: Optional[str] = None


# =============================================================================
# Task Schemas (same as Session 5, but now user-scoped)
# =============================================================================

class TaskCreate(BaseModel):
    """Schema for creating a new task."""
    title: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)


class TaskUpdate(BaseModel):
    """Schema for updating a task."""
    title: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    completed: Optional[bool] = None


class Task(BaseModel):
    """
    Schema for task responses.

    Now includes owner_id to show task ownership.
    model_config enables reading from SQLAlchemy model instances.
    """
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: Optional[str] = None
    completed: bool
    created_at: datetime
    owner_id: int
