"""
Session 6 OAuth Supplement: FastAPI Application

Demonstrates dual authentication -- password-based login AND GitLab OAuth --
converging on the same JWT format. Protected endpoints work identically
regardless of which flow authenticated the user.

Endpoints:
    POST /users/              - Register with username/email/password
    POST /token               - Password login -> JWT
    GET  /auth/login/gitlab   - Start GitLab OAuth flow (redirects browser)
    GET  /auth/callback       - GitLab OAuth callback -> JWT
    GET  /users/me            - Protected: current user info

Run with:
    uvicorn main:app --reload

Test at:
    http://localhost:8000/docs (Swagger UI)
"""

from datetime import timedelta

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from database import engine, get_db, Base
import models
import schemas
from auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)
from oauth import (
    start_gitlab_login,
    validate_state,
    exchange_code_for_token,
    get_gitlab_user_info,
)

# Create database tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Session 6 OAuth Supplement: Dual Auth Demo",
    description="Password + GitLab OAuth authentication with shared JWT",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# User Registration (password-based)
# =============================================================================

@app.post("/users/", response_model=schemas.UserResponse, status_code=201)
def create_user(
    user: schemas.UserCreate, db: Session = Depends(get_db)
):
    """Register a new user with username, email, and password."""
    existing = db.query(models.User).filter(
        models.User.username == user.username
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )

    db_user = models.User(
        username=user.username,
        email=user.email,
        hashed_password=hash_password(user.password),
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


# =============================================================================
# Password Login
# =============================================================================

@app.post("/token", response_model=schemas.Token)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """
    Password-based login.

    Accepts OAuth2 password form with 'username' and 'password' fields.
    The 'username' field contains the username (not email) in this demo.

    Returns a JWT access token identical in format to the OAuth flow.
    """
    user = db.query(models.User).filter(
        models.User.username == form_data.username
    ).first()

    if (
        not user
        or user.hashed_password is None
        or not verify_password(form_data.password, user.hashed_password)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": access_token, "token_type": "bearer"}


# =============================================================================
# GitLab OAuth Login
# =============================================================================

@app.get("/auth/login/gitlab")
async def gitlab_login():
    """
    Start the GitLab OAuth2 Authorization Code flow.

    Generates a state parameter (CSRF protection) and redirects the
    browser to GitLab's authorization page. After the user authenticates,
    GitLab redirects back to /auth/callback with an authorization code.
    """
    authorization_url = start_gitlab_login()
    return RedirectResponse(authorization_url)


@app.get("/auth/callback", response_model=schemas.Token)
async def gitlab_callback(
    code: str,
    state: str,
    db: Session = Depends(get_db),
):
    """
    Handle the GitLab OAuth callback.

    Steps:
    1. Validate the state parameter (CSRF protection).
    2. Exchange the authorization code for a GitLab access token.
    3. Fetch user info from GitLab using the access token.
    4. Find or create a local user linked to the GitLab identity.
    5. Issue a local JWT (same format as the password flow).

    The GitLab access token is used only to fetch user info and is
    not stored. The application issues its own JWT for session management.
    """
    # Step 1: Validate state (CSRF protection)
    validate_state(state)

    # Step 2: Exchange authorization code for GitLab access token
    token_data = await exchange_code_for_token(code)

    # Step 3: Fetch user profile from GitLab
    gitlab_user = await get_gitlab_user_info(token_data["access_token"])

    # Step 4: Find or create local user
    user = get_or_create_oauth_user(
        db,
        provider="gitlab",
        provider_id=str(gitlab_user["id"]),
        username=gitlab_user["username"],
        email=gitlab_user.get("email", ""),
    )

    # Step 5: Issue local JWT (same function as password flow)
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


# =============================================================================
# OAuth User Management
# =============================================================================

def get_or_create_oauth_user(
    db: Session,
    provider: str,
    provider_id: str,
    username: str,
    email: str,
) -> models.User:
    """
    Find an existing user by OAuth identity, or create a new one.

    If the OAuth account already exists, return the linked user.
    Otherwise, create a new User and OAuthAccount pair.

    OAuth-only users have hashed_password=None because they never
    set a local password.
    """
    # Check if this OAuth account already exists
    oauth_account = db.query(models.OAuthAccount).filter(
        models.OAuthAccount.provider == provider,
        models.OAuthAccount.provider_user_id == provider_id,
    ).first()

    if oauth_account:
        return db.query(models.User).filter(
            models.User.id == oauth_account.user_id
        ).first()

    # Create new local user (no password -- OAuth-only)
    user = models.User(username=username, email=email)
    db.add(user)
    db.flush()  # Assigns user.id without committing

    # Link the OAuth identity
    oauth_account = models.OAuthAccount(
        user_id=user.id,
        provider=provider,
        provider_user_id=provider_id,
    )
    db.add(oauth_account)
    db.commit()
    db.refresh(user)

    return user


# =============================================================================
# Protected Endpoint
# =============================================================================

@app.get("/users/me", response_model=schemas.UserResponse)
async def read_users_me(
    current_user: models.User = Depends(get_current_user),
):
    """
    Return the current authenticated user's profile.

    This endpoint works identically for users who authenticated
    via password (POST /token) or via OAuth (GET /auth/callback).
    The get_current_user dependency validates the JWT without
    knowing which flow produced it.
    """
    return current_user


# =============================================================================
# Health Check
# =============================================================================

@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    """Health check with database connectivity status."""
    user_count = db.query(models.User).count()
    oauth_count = db.query(models.OAuthAccount).count()
    return {
        "status": "healthy",
        "database": "connected",
        "user_count": user_count,
        "oauth_account_count": oauth_count,
    }
