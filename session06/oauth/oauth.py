"""
Session 6 OAuth Supplement: GitLab OAuth2 Flow

Manual implementation of the OAuth2 Authorization Code flow using httpx.
No Authlib -- every HTTP request is explicit for pedagogical transparency.

State management uses a simple in-memory dict (not production-ready,
but clear for teaching). In production, use server-side sessions or
a database-backed store.

Environment variables (loaded via python-dotenv):
    GITLAB_BASE_URL: GitLab instance URL (e.g., https://sc-gitlab.ufv.ca)
    GITLAB_CLIENT_ID: OAuth application ID from GitLab
    GITLAB_CLIENT_SECRET: OAuth application secret from GitLab
    GITLAB_REDIRECT_URI: Callback URL registered with GitLab

See the supplement slides Steps 2-4 for the matching code.
"""

import os
import secrets
import time
from typing import Any

import httpx
from dotenv import load_dotenv
from fastapi import HTTPException

load_dotenv()

# =============================================================================
# GitLab OAuth Configuration
# =============================================================================

GITLAB_BASE_URL = os.environ.get("GITLAB_BASE_URL", "https://sc-gitlab.ufv.ca")
GITLAB_CLIENT_ID = os.environ.get("GITLAB_CLIENT_ID", "")
GITLAB_CLIENT_SECRET = os.environ.get("GITLAB_CLIENT_SECRET", "")
GITLAB_REDIRECT_URI = os.environ.get(
    "GITLAB_REDIRECT_URI", "http://localhost:8000/auth/callback"
)

# Scopes requested from GitLab
GITLAB_SCOPES = "read_user openid profile email"

# =============================================================================
# State Management
# =============================================================================

# In-memory state store: maps state token -> timestamp of creation.
# Entries older than STATE_TTL_SECONDS are considered expired.
pending_states: dict[str, float] = {}
STATE_TTL_SECONDS = 600  # 10 minutes


def _cleanup_expired_states() -> None:
    """Remove state entries older than STATE_TTL_SECONDS."""
    now = time.time()
    expired = [
        state for state, created_at in pending_states.items()
        if now - created_at > STATE_TTL_SECONDS
    ]
    for state in expired:
        del pending_states[state]


def validate_state(state: str) -> None:
    """
    Validate and consume a state parameter from the callback.

    Raises HTTPException 400 if the state is missing or expired.
    The state is deleted after validation (single use).
    """
    _cleanup_expired_states()

    if state not in pending_states:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired state parameter",
        )
    del pending_states[state]


# =============================================================================
# OAuth Flow Functions
# =============================================================================

def start_gitlab_login() -> str:
    """
    Generate a state token and return the GitLab authorization URL.

    The caller should redirect the browser to this URL.

    Returns:
        Full GitLab authorization URL with query parameters.
    """
    _cleanup_expired_states()

    state = secrets.token_urlsafe(32)
    pending_states[state] = time.time()

    # Build the authorization URL with required parameters
    params = (
        f"client_id={GITLAB_CLIENT_ID}"
        f"&redirect_uri={GITLAB_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope={GITLAB_SCOPES.replace(' ', '+')}"
        f"&state={state}"
    )
    return f"{GITLAB_BASE_URL}/oauth/authorize?{params}"


async def exchange_code_for_token(code: str) -> dict[str, Any]:
    """
    Exchange an authorization code for an access token (server-to-server).

    This is the POST to /oauth/token described in Step 3 of the slides.
    The client_secret is sent here and never reaches the browser.

    Args:
        code: The authorization code from the callback query parameter.

    Returns:
        Token response dict containing 'access_token' and related fields.

    Raises:
        HTTPException 502: If the token exchange fails.
    """
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{GITLAB_BASE_URL}/oauth/token",
            data={
                "client_id": GITLAB_CLIENT_ID,
                "client_secret": GITLAB_CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": GITLAB_REDIRECT_URI,
            },
        )

    if resp.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail="Token exchange failed",
        )

    return resp.json()


async def get_gitlab_user_info(access_token: str) -> dict[str, Any]:
    """
    Fetch the authenticated user's profile from GitLab's API.

    Uses the access token obtained from exchange_code_for_token().
    The token is sent as a Bearer token in the Authorization header.

    Args:
        access_token: GitLab OAuth access token.

    Returns:
        Dict with user profile fields (id, username, email, name, etc.).

    Raises:
        HTTPException 502: If the user info request fails.
    """
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{GITLAB_BASE_URL}/api/v4/user",
            headers={"Authorization": f"Bearer {access_token}"},
        )

    if resp.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail="Failed to retrieve user info from GitLab",
        )

    return resp.json()
