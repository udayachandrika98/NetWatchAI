"""Unit tests for src/oauth_github.py.

HTTP calls are mocked — no real network access.
"""
from unittest.mock import MagicMock, patch

import pytest

from src import oauth_github

ENV_FULL = {
    "GITHUB_OAUTH_CLIENT_ID": "test_client",
    "GITHUB_OAUTH_CLIENT_SECRET": "test_secret",
    "GITHUB_OAUTH_REDIRECT_URI": "http://localhost:8501/",
}


def test_is_configured_false_without_env(monkeypatch):
    for k in ENV_FULL:
        monkeypatch.delenv(k, raising=False)
    assert oauth_github.is_configured() is False


def test_is_configured_true_with_full_env(monkeypatch):
    for k, v in ENV_FULL.items():
        monkeypatch.setenv(k, v)
    assert oauth_github.is_configured() is True


def test_is_configured_false_with_partial_env(monkeypatch):
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "x")
    monkeypatch.delenv("GITHUB_OAUTH_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("GITHUB_OAUTH_REDIRECT_URI", raising=False)
    assert oauth_github.is_configured() is False


def test_is_user_allowed_empty_allowlist_permits_anyone(monkeypatch):
    monkeypatch.delenv("ALLOWED_GITHUB_USERS", raising=False)
    assert oauth_github.is_user_allowed("anybody") is True


def test_is_user_allowed_respects_allowlist(monkeypatch):
    monkeypatch.setenv("ALLOWED_GITHUB_USERS", "alice, bob, CAROL")
    assert oauth_github.is_user_allowed("alice")
    assert oauth_github.is_user_allowed("BOB")
    assert oauth_github.is_user_allowed("carol")
    assert oauth_github.is_user_allowed("eve") is False


def test_make_state_returns_distinct_tokens():
    s1 = oauth_github.make_state()
    s2 = oauth_github.make_state()
    assert s1 != s2
    assert len(s1) >= 32


def test_authorize_url_contains_required_params(monkeypatch):
    for k, v in ENV_FULL.items():
        monkeypatch.setenv(k, v)
    url = oauth_github.authorize_url("STATE123")
    assert url.startswith(oauth_github.AUTHORIZE_URL)
    assert "client_id=test_client" in url
    assert "state=STATE123" in url
    assert "scope=read%3Auser" in url
    assert "redirect_uri=http%3A%2F%2Flocalhost%3A8501%2F" in url


def test_exchange_code_rejects_state_mismatch(monkeypatch):
    for k, v in ENV_FULL.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(ValueError, match="state mismatch"):
        oauth_github.exchange_code(code="abc", state="wrong", expected_state="right")


def test_exchange_code_happy_path(monkeypatch):
    for k, v in ENV_FULL.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("ALLOWED_GITHUB_USERS", raising=False)

    token_response = MagicMock()
    token_response.json.return_value = {"access_token": "gho_abc", "token_type": "bearer"}
    token_response.raise_for_status.return_value = None

    user_response = MagicMock()
    user_response.json.return_value = {
        "login": "octocat", "name": "The Octocat", "id": 1, "avatar_url": "https://example/x.png"
    }
    user_response.raise_for_status.return_value = None

    with patch("src.oauth_github.requests.post", return_value=token_response) as post_mock, \
         patch("src.oauth_github.requests.get", return_value=user_response) as get_mock:
        user = oauth_github.exchange_code(code="code123", state="S", expected_state="S")

    assert user == {
        "login": "octocat", "name": "The Octocat", "id": 1, "avatar_url": "https://example/x.png"
    }
    post_mock.assert_called_once()
    get_mock.assert_called_once()
    sent_data = post_mock.call_args.kwargs["data"]
    assert sent_data["code"] == "code123"
    assert sent_data["client_secret"] == "test_secret"


def test_exchange_code_rejects_user_not_in_allowlist(monkeypatch):
    for k, v in ENV_FULL.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("ALLOWED_GITHUB_USERS", "alice")

    token_response = MagicMock()
    token_response.json.return_value = {"access_token": "gho_abc"}
    token_response.raise_for_status.return_value = None

    user_response = MagicMock()
    user_response.json.return_value = {"login": "mallory", "name": "Mallory", "id": 2, "avatar_url": ""}
    user_response.raise_for_status.return_value = None

    with patch("src.oauth_github.requests.post", return_value=token_response), \
         patch("src.oauth_github.requests.get", return_value=user_response):
        with pytest.raises(ValueError, match="not on the allowlist"):
            oauth_github.exchange_code(code="c", state="s", expected_state="s")


def test_exchange_code_handles_github_error(monkeypatch):
    for k, v in ENV_FULL.items():
        monkeypatch.setenv(k, v)
    error_response = MagicMock()
    error_response.json.return_value = {"error": "bad_verification_code",
                                        "error_description": "The code is invalid"}
    error_response.raise_for_status.return_value = None
    with patch("src.oauth_github.requests.post", return_value=error_response):
        with pytest.raises(ValueError, match="The code is invalid"):
            oauth_github.exchange_code(code="c", state="s", expected_state="s")
