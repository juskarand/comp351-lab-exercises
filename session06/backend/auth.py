"""
Session 6: Authentication Utilities

This module provides JWT token creation and password hashing:
- Password hashing with bcrypt (secure, industry-standard)
- JWT token creation and verification
- FastAPI dependency for getting the current user

Key security concepts:
- Never store plain-text passwords
- Use strong hashing algorithms (bcrypt)
- JWTs are signed, not encrypted (don't put secrets in them)
- Token expiration prevents stolen tokens from working forever
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from database import get_db
import models
import schemas

# =============================================================================
# Configuration
# In production, these should be environment variables!
# =============================================================================

# Secret key for signing JWTs
# Generate with: openssl rand -hex 32
SECRET_KEY = "your-secret-key-change-in-production-use-env-var"

# Algorithm for JWT signing
ALGORITHM = "HS256"

# Token expiration time
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# =============================================================================
# Password Hashing
# =============================================================================

# CryptContext handles password hashing with bcrypt
# bcrypt is designed to be slow, making brute-force attacks impractical
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a hash.

    Args:
        plain_password: The password to verify
        hashed_password: The stored hash to check against

    Returns:
        True if password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hash a password for storage.

    Args:
        password: Plain text password

    Returns:
        Secure hash string suitable for database storage
    """
    return pwd_context.hash(password)


# =============================================================================
# JWT Token Operations
# =============================================================================

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.

    Args:
        data: Data to encode in the token (e.g., {"sub": "user@example.com"})
        expires_delta: Custom expiration time (optional)

    Returns:
        Encoded JWT string

    Note:
        - 'sub' (subject) is a standard JWT claim for the user identifier
        - 'exp' (expiration) is automatically enforced by jwt.decode()
    """
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt


def decode_token(token: str) -> Optional[str]:
    """
    Decode and validate a JWT token.

    Args:
        token: The JWT string to decode

    Returns:
        The email (subject) from the token, or None if invalid
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        return email
    except JWTError:
        return None


# =============================================================================
# FastAPI Security Dependencies
# =============================================================================

# OAuth2PasswordBearer extracts the token from the Authorization header
# tokenUrl is the endpoint where clients get tokens (for Swagger UI)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> models.User:
    """
    FastAPI dependency to get the current authenticated user.

    This dependency:
    1. Extracts the JWT from the Authorization header
    2. Decodes and validates the token
    3. Looks up the user in the database
    4. Returns the user object or raises 401 Unauthorized

    Usage:
        @app.get("/protected")
        def protected_route(user: models.User = Depends(get_current_user)):
            return {"message": f"Hello, {user.email}"}
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Decode the token
    email = decode_token(token)
    if email is None:
        raise credentials_exception

    # Look up user in database
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception

    return user


async def get_current_active_user(
    current_user: models.User = Depends(get_current_user)
) -> models.User:
    """
    Dependency that also checks if the user is active.

    Builds on get_current_user to add an additional check.
    This pattern is useful for admin-only routes or deactivated accounts.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user
