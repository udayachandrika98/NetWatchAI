"""GitHub OAuth (web-app flow) for NetWatchAI.

Layered alongside the password auth in src/auth.py — if the three OAuth env vars
are set, the dashboard offers a "Sign in with GitHub" path; otherwise the
password gate is unchanged. This keeps the demo experience working.

Env vars (all required to enable OAuth):
  GITHUB_OAUTH_CLIENT_ID
  GITHUB_OAUTH_CLIENT_SECRET
  GITHUB_OAUTH_REDIRECT_URI       # e.g. http://localhost:8501/

Optional:
  ALLOWED_GITHUB_USERS            # comma-separated logins; empty = any user
"""
from __future__ import annotations

import os
import secrets
from urllib.parse import urlencode

import requests

AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
USER_URL = "https://api.github.com/user"

ENV_CLIENT_ID = "GITHUB_OAUTH_CLIENT_ID"
ENV_CLIENT_SECRET = "GITHUB_OAUTH_CLIENT_SECRET"
ENV_REDIRECT_URI = "GITHUB_OAUTH_REDIRECT_URI"
ENV_ALLOWED_USERS = "ALLOWED_GITHUB_USERS"


def is_configured() -> bool:
    """True iff all three OAuth env vars are populated."""
    return all(os.environ.get(k) for k in (ENV_CLIENT_ID, ENV_CLIENT_SECRET, ENV_REDIRECT_URI))


def is_user_allowed(login: str) -> bool:
    """Check `login` against ALLOWED_GITHUB_USERS. Empty allowlist = any user."""
    raw = os.environ.get(ENV_ALLOWED_USERS, "").strip()
    if not raw:
        return True
    allowed = {u.strip().lower() for u in raw.split(",") if u.strip()}
    return login.lower() in allowed


def make_state() -> str:
    """One-time, unpredictable token to bind the redirect to this browser session."""
    return secrets.token_urlsafe(32)


def authorize_url(state: str) -> str:
    """Build the GitHub authorize URL the user gets redirected to."""
    params = {
        "client_id": os.environ[ENV_CLIENT_ID],
        "redirect_uri": os.environ[ENV_REDIRECT_URI],
        "state": state,
        "scope": "read:user",
        "allow_signup": "false",
    }
    return f"{AUTHORIZE_URL}?{urlencode(params)}"


def exchange_code(code: str, state: str, expected_state: str) -> dict:
    """Exchange the callback `code` for an access token, then fetch the user.

    Returns: {login, name, avatar_url, id}
    Raises: ValueError on state mismatch or auth failure.
    """
    if not secrets.compare_digest(state, expected_state):
        raise ValueError("state mismatch — possible CSRF, refusing to exchange")

    token_resp = requests.post(
        TOKEN_URL,
        data={
            "client_id": os.environ[ENV_CLIENT_ID],
            "client_secret": os.environ[ENV_CLIENT_SECRET],
            "code": code,
            "redirect_uri": os.environ[ENV_REDIRECT_URI],
        },
        headers={"Accept": "application/json"},
        timeout=10,
    )
    token_resp.raise_for_status()
    payload = token_resp.json()
    if "access_token" not in payload:
        raise ValueError(f"GitHub rejected the code: {payload.get('error_description') or payload}")

    access_token = payload["access_token"]
    user_resp = requests.get(
        USER_URL,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=10,
    )
    user_resp.raise_for_status()
    u = user_resp.json()

    if not is_user_allowed(u.get("login", "")):
        raise ValueError(
            f"GitHub user '{u.get('login')}' is not on the allowlist "
            f"(set ALLOWED_GITHUB_USERS to include them)"
        )

    return {
        "login": u.get("login"),
        "name": u.get("name") or u.get("login"),
        "avatar_url": u.get("avatar_url"),
        "id": u.get("id"),
    }
