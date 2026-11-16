"""
Session 6 OAuth Supplement: Authentication Utilities

Password hashing and JWT operations shared by both authentication flows.

Key design: create_access_token() is the convergence point. Both the
password login (POST /token) and the OAuth callback (GET /auth/callback)
call this function to produce an identical JWT. Protected endpoints
cannot distinguish which flow authenticated the user.

Environment variables:
    JWT_SECRET_KEY: Secret for signing JWTs (required in production).
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from database import get_db
import models

load_dotenv()

# =============================================================================
# Configuration
# =============================================================================

SECRET_KEY = os.environ.get(
    "JWT_SECRET_KEY", "change-me-generate-a-real-secret"
)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# =============================================================================
# Password Hashing
# =============================================================================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a plain-text password for storage."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a stored bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


# =============================================================================
# JWT Token Operations
# =============================================================================

def create_access_token(
    data: dict, expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT access token.

    Args:
        data: Claims to encode (must include "sub" for the username).
        expires_delta: Custom expiration time. Defaults to
            ACCESS_TOKEN_EXPIRE_MINUTES.

    Returns:
        Encoded JWT string.

    This function is called by both the password flow and the OAuth flow.
    The resulting JWT is identical regardless of authentication method.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# =============================================================================
# FastAPI Security Dependencies
# =============================================================================

# OAuth2PasswordBearer extracts the token from the Authorization header.
# tokenUrl tells Swagger UI where to obtain tokens.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    """
    FastAPI dependency: extract and validate JWT, return the User.

    Works identically for tokens issued by the password flow or OAuth flow
    because both flows produce JWTs with the same structure (sub=username).

    Raises:
        HTTPException 401: If the token is invalid or the user does not exist.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(models.User).filter(
        models.User.username == username
    ).first()
    if user is None:
        raise credentials_exception

    return user
