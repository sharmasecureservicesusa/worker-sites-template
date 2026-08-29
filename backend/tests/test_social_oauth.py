from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.config import clear_settings_cache
from app.services import login_oauth_member
from app.social_oauth import (
    SocialOAuthError,
    sign_oauth_state,
    verify_oauth_state,
)


def test_oauth_state_roundtrip():
    state = sign_oauth_state("test-secret", provider="google", next_path="/library")
    assert verify_oauth_state("test-secret", state, "google") == "/library"


def test_oauth_state_rejects_wrong_provider():
    state = sign_oauth_state("test-secret", provider="google", next_path="/library")
    with pytest.raises(SocialOAuthError):
        verify_oauth_state("test-secret", state, "github")


def test_google_start_unconfigured(client: TestClient):
    response = client.get("/auth/google")
    assert response.status_code == 503


def test_login_oauth_member_creates_member(client, app):
    from sqlalchemy.orm import Session

    from app.db import get_engine

    with Session(get_engine()) as session:
        member = login_oauth_member(
            session,
            provider="google",
            subject="google-subject-1",
            email="oauth@workers.club",
            display_name="OAuth Ada",
            email_verified=True,
        )
        assert member.email == "oauth@workers.club"
        assert member.email_verified is True
        assert member.password_hash is None

        again = login_oauth_member(
            session,
            provider="google",
            subject="google-subject-1",
            email="oauth@workers.club",
            display_name="OAuth Ada",
            email_verified=True,
        )
        assert again.id == member.id


def test_google_callback_creates_session(client: TestClient, monkeypatch):
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "google-test-id")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "google-test-secret")
    clear_settings_cache()

    state = sign_oauth_state("test-secret-key-not-for-production", provider="google", next_path="/dashboard")

    async def fake_exchange(settings, provider, *, code):  # noqa: ARG001
        from app.social_oauth import SocialProfile

        assert code == "abc123"
        return SocialProfile(
            subject="google-subject-99",
            email="social@workers.club",
            display_name="Social Member",
            email_verified=True,
        )

    with patch("app.routers.social.exchange_code", new=AsyncMock(side_effect=fake_exchange)):
        response = client.get("/auth/google/callback?code=abc123&state=" + state)

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    assert client.cookies.get("members_session")

    me = client.get("/api/me")
    assert me.status_code == 200
    assert me.json()["email"] == "social@workers.club"
