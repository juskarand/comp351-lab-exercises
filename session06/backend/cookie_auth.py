"""
Cookie-Based Authentication - CSRF Vulnerability Demonstration

This module shows an ALTERNATIVE authentication approach using session cookies
instead of Bearer tokens. This is provided for EDUCATIONAL COMPARISON purposes
to demonstrate why Bearer tokens are more secure against CSRF attacks.

⚠️ WARNING: This code is intentionally vulnerable to CSRF attacks for pedagogical purposes.
DO NOT use this pattern in production without proper CSRF token protection.

PEDAGOGICAL PURPOSE:
- Compare session cookie authentication (CSRF-vulnerable) with Bearer tokens (CSRF-resistant)
- Understand how browser auto-attachment of cookies enables CSRF
- Learn why Bearer tokens in Authorization headers are safer

COMPARISON WITH main.py:
- main.py uses Bearer tokens in Authorization header (CSRF-resistant)
- This file uses session cookies (CSRF-vulnerable without CSRF tokens)

NOTE: This is a CODE READING exercise. This file cannot be run standalone as it
lacks the full Flask application setup and session management infrastructure.
Students should READ this code and COMPARE it with main.py to understand the
security differences.
"""

from fastapi import FastAPI, Response, Cookie, HTTPException
from pydantic import BaseModel
import secrets

app = FastAPI()

# In-memory session storage (simplified for demonstration)
# In production, use Redis, database, or secure session middleware
active_sessions = {}


class LoginRequest(BaseModel):
    """Login credentials submitted by user"""
    email: str
    password: str


class TransferRequest(BaseModel):
    """Money transfer request (example sensitive operation)"""
    to_email: str
    amount: int


@app.post("/login")
def login(credentials: LoginRequest, response: Response):
    """
    Login endpoint using session cookies.

    SECURITY PATTERN: Session Cookie Authentication
    - Server generates a session ID after validating credentials
    - Session ID is stored in a cookie via Set-Cookie header
    - Browser AUTOMATICALLY includes this cookie in all subsequent requests

    CSRF VULNERABILITY:
    The automatic cookie attachment is what makes this vulnerable to CSRF.
    An attacker's website can trigger requests to this API, and the browser
    will automatically include the victim's session cookie!

    Args:
        credentials: User email and password
        response: FastAPI Response object for setting cookies

    Returns:
        Success message

    Raises:
        HTTPException: If credentials are invalid
    """
    # Validate credentials (simplified - real apps use password hashing)
    # In production: bcrypt.checkpw(password.encode(), hashed_password)
    if credentials.email == "user@example.com" and credentials.password == "password123":
        # Generate a secure session ID
        session_id = secrets.token_urlsafe(32)

        # Store session server-side
        active_sessions[session_id] = {
            "email": credentials.email,
            "user_id": 1
        }

        # ⚠️ CSRF RISK: Set session ID as cookie
        # The browser will AUTO-SEND this cookie with every request
        # This includes requests initiated by an attacker's website!
        response.set_cookie(
            key="session_id",
            value=session_id,
            httponly=True,  # Prevents JavaScript access (good for XSS protection)
            secure=False,   # Should be True in production (HTTPS only)
            samesite="lax"  # Provides SOME CSRF protection, but not complete
        )

        return {"message": "Logged in successfully"}
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")


@app.post("/api/transfer")
def transfer_money(transfer: TransferRequest, session_id: str = Cookie(None)):
    """
    Money transfer endpoint - CSRF VULNERABLE!

    VULNERABILITY EXPLANATION:
    This endpoint trusts ANY request that includes a valid session cookie.
    The browser automatically sends cookies, even for requests from other sites.

    CSRF ATTACK SCENARIO:
    1. Victim logs in to yourbank.com (gets session cookie)
    2. Victim visits evil.com (while still logged in)
    3. evil.com contains malicious JavaScript:
       ```
       fetch('https://yourbank.com/api/transfer', {
           method: 'POST',
           credentials: 'include',  // Tells browser to send cookies!
           body: JSON.stringify({to_email: 'attacker@evil.com', amount: 1000})
       })
       ```
    4. Browser AUTOMATICALLY includes victim's session cookie
    5. Server sees valid session, processes transfer
    6. Money transferred without victim's knowledge!

    WHY THIS WORKS:
    - Browser sends cookies automatically (convenience becomes vulnerability)
    - Server cannot distinguish between legitimate requests and CSRF attacks
    - No CSRF token to verify request origin

    DEFENSE (not implemented here):
    - Add CSRF token to form/request (random value tied to session)
    - Verify CSRF token on server before processing
    - Use SameSite=Strict cookie attribute (but breaks some workflows)

    Args:
        transfer: Transfer details (recipient and amount)
        session_id: Session ID from cookie (automatically provided by browser)

    Returns:
        Transfer confirmation

    Raises:
        HTTPException: If not authenticated
    """
    # Check if session exists
    if not session_id or session_id not in active_sessions:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Get user from session
    user = active_sessions[session_id]

    # ⚠️ CSRF VULNERABILITY:
    # We trust this request because it has a valid session cookie
    # BUT: An attacker's website can trigger this request with the victim's cookie!
    # The browser auto-sends the cookie even for cross-origin requests

    # Process the transfer (simplified)
    return {
        "message": f"Transferred ${transfer.amount} to {transfer.to_email}",
        "from": user["email"]
    }


@app.get("/api/profile")
def get_profile(session_id: str = Cookie(None)):
    """
    Get user profile - Also CSRF vulnerable for state-changing operations.

    Note: GET requests for CSRF are less dangerous because browsers have
    some protections (e.g., Simple CORS requests). However, POST/PUT/DELETE
    via fetch() with credentials: 'include' are highly vulnerable.

    Args:
        session_id: Session ID from cookie

    Returns:
        User profile data

    Raises:
        HTTPException: If not authenticated
    """
    if not session_id or session_id not in active_sessions:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = active_sessions[session_id]

    return {
        "email": user["email"],
        "user_id": user["user_id"]
    }


# ============================================================================
# COMPARISON WITH BEARER TOKEN AUTHENTICATION (from main.py)
# ============================================================================

"""
BEARER TOKEN APPROACH (main.py):

@app.post("/api/transfer")
def transfer_money(transfer: TransferRequest, authorization: str = Header(None)):
    # Extract token from Authorization header
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(status_code=401, detail="Missing token")

    token = authorization.split(' ')[1]

    # Verify JWT signature
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_email = payload['sub']

        # Process transfer
        return {"message": f"Transferred ${transfer.amount}"}

    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


WHY BEARER TOKENS ARE CSRF-RESISTANT:

1. Manual Attachment Required:
   - Token is stored in localStorage or JavaScript variable
   - JavaScript MUST explicitly add it to Authorization header
   - fetch('/api/transfer', {
         headers: { 'Authorization': `Bearer ${token}` }
     })

2. Same-Origin Policy Protection:
   - Attacker's website (evil.com) cannot access yourbank.com's localStorage
   - Browser blocks cross-origin localStorage access
   - Attacker cannot read token to include in request

3. No Auto-Attachment:
   - Unlike cookies, Authorization headers are NOT sent automatically
   - Even if attacker triggers a request, there's no token in the header
   - Request fails authentication

CSRF ATTACK FAILS WITH BEARER TOKENS:

Attacker tries:
fetch('https://yourbank.com/api/transfer', {
    method: 'POST',
    headers: {
        'Authorization': 'Bearer ???'  // Attacker doesn't have the token!
    },
    body: JSON.stringify({to_email: 'attacker@evil.com', amount: 1000})
})

Result: Request has no valid token, server rejects it (401 Unauthorized)


TRADE-OFFS:

Session Cookies:
  ✓ Easy to implement
  ✓ Server controls session lifetime
  ✗ CSRF vulnerable without CSRF tokens
  ✗ Requires server-side session storage

Bearer Tokens (JWT):
  ✓ CSRF resistant (no auto-attachment)
  ✓ Stateless (no server-side session storage)
  ✗ Vulnerable to XSS if not careful (must protect localStorage)
  ✗ Cannot revoke tokens easily (once signed, valid until expiration)


WHEN TO USE EACH:

Session Cookies:
  - Traditional web apps with server-rendered pages
  - When you need server-side session control
  - MUST implement CSRF token protection

Bearer Tokens:
  - Single-page applications (SPAs)
  - Mobile apps
  - Microservices / API-first architecture
  - When CSRF resistance is priority
"""


# ============================================================================
# STUDENT EXERCISE: Activity 6 Part 4
# ============================================================================

"""
ACTIVITY 6 PART 4 INSTRUCTIONS:

1. READ this file (cookie_auth.py) carefully
2. READ main.py to see the Bearer token approach
3. COMPARE the two authentication methods:
   - How does the client attach credentials?
   - How does the server verify credentials?
   - Can an attacker's website trigger authenticated requests?

4. TEST CSRF resistance of main.py (Bearer tokens):
   a. Login to get a JWT token
   b. Try to make a curl request WITHOUT the Authorization header
   c. Observe the request is rejected (401 Unauthorized)
   d. This demonstrates why Bearer tokens resist CSRF

5. DOCUMENT your findings:
   - Explain why cookie-based auth is vulnerable to CSRF
   - Explain why Bearer token auth resists CSRF
   - Describe the role of Same-Origin Policy in protecting Bearer tokens

6. SUBMIT:
   - Your curl commands showing the CSRF resistance test
   - A written explanation (200-300 words) of the security comparison
"""
