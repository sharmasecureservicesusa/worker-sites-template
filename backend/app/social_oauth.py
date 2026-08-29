from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx

from app.config import Settings


@dataclass(frozen=True)
class SocialProfile:
    subject: str
    email: str
    display_name: str
    email_verified: bool


class SocialOAuthError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def provider_enabled(settings: Settings, provider: str) -> bool:
    if provider == "google":
        return bool(settings.google_client_id and settings.google_client_secret)
    if provider == "github":
        return bool(settings.github_client_id and settings.github_client_secret)
    return False


def enabled_providers(settings: Settings) -> list[str]:
    providers: list[str] = []
    if provider_enabled(settings, "google"):
        providers.append("google")
    if provider_enabled(settings, "github"):
        providers.append("github")
    return providers


def redirect_uri(settings: Settings, provider: str) -> str:
    return f"{settings.public_base_url.rstrip('/')}/auth/{provider}/callback"


def sign_oauth_state(secret: str, *, provider: str, next_path: str) -> str:
    payload = {
        "provider": provider,
        "next": next_path,
        "exp": int(time.time()) + 600,
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(raw + b"." + sig.encode("ascii")).decode("ascii")


def verify_oauth_state(secret: str, state: str, provider: str) -> str:
    try:
        decoded = base64.urlsafe_b64decode(state.encode("ascii"))
        raw, sig = decoded.rsplit(b".", 1)
        expected = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig.decode("ascii")):
            raise SocialOAuthError("Invalid OAuth state.", 400)
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SocialOAuthError("Invalid OAuth state.", 400) from exc
    if payload.get("provider") != provider:
        raise SocialOAuthError("Invalid OAuth state.", 400)
    if int(payload.get("exp", 0)) < int(time.time()):
        raise SocialOAuthError("OAuth state expired. Try again.", 400)
    return payload.get("next") or "/dashboard"


def authorize_url(settings: Settings, provider: str, *, state: str) -> str:
    redirect = redirect_uri(settings, provider)
    if provider == "google":
        params = {
            "client_id": settings.google_client_id,
            "redirect_uri": redirect,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "access_type": "online",
            "prompt": "select_account",
        }
        return "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
    if provider == "github":
        params = {
            "client_id": settings.github_client_id,
            "redirect_uri": redirect,
            "scope": "read:user user:email",
            "state": state,
        }
        return "https://github.com/login/oauth/authorize?" + urlencode(params)
    raise SocialOAuthError("Unknown provider.", 400)


async def exchange_code(settings: Settings, provider: str, *, code: str) -> SocialProfile:
    redirect = redirect_uri(settings, provider)
    async with httpx.AsyncClient(timeout=20.0) as client:
        if provider == "google":
            return await _google_profile(client, settings, code=code, redirect_uri=redirect)
        if provider == "github":
            return await _github_profile(client, settings, code=code, redirect_uri=redirect)
    raise SocialOAuthError("Unknown provider.", 400)


async def _google_profile(
    client: httpx.AsyncClient,
    settings: Settings,
    *,
    code: str,
    redirect_uri: str,
) -> SocialProfile:
    token_resp = await client.post(
        "https://oauth2.googleapis.com/token",
        data={
            "code": code,
            "client_id": settings.google_client_id,
            "client_secret": settings.google_client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        },
        headers={"Accept": "application/json"},
    )
    if token_resp.status_code >= 400:
        raise SocialOAuthError("Google sign-in failed.", 502)
    access_token = token_resp.json().get("access_token")
    if not access_token:
        raise SocialOAuthError("Google sign-in failed.", 502)

    user_resp = await client.get(
        "https://openidconnect.googleapis.com/v1/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if user_resp.status_code >= 400:
        raise SocialOAuthError("Google sign-in failed.", 502)
    data: dict[str, Any] = user_resp.json()
    email = (data.get("email") or "").strip().lower()
    if not email:
        raise SocialOAuthError("Google did not return an email address.", 400)
    return SocialProfile(
        subject=str(data.get("sub") or ""),
        email=email,
        display_name=(data.get("name") or email.split("@", 1)[0]).strip()[:120],
        email_verified=bool(data.get("email_verified", True)),
    )


async def _github_profile(
    client: httpx.AsyncClient,
    settings: Settings,
    *,
    code: str,
    redirect_uri: str,
) -> SocialProfile:
    token_resp = await client.post(
        "https://github.com/login/oauth/access_token",
        data={
            "client_id": settings.github_client_id,
            "client_secret": settings.github_client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        },
        headers={"Accept": "application/json"},
    )
    if token_resp.status_code >= 400:
        raise SocialOAuthError("GitHub sign-in failed.", 502)
    access_token = token_resp.json().get("access_token")
    if not access_token:
        raise SocialOAuthError("GitHub sign-in failed.", 502)

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    user_resp = await client.get("https://api.github.com/user", headers=headers)
    if user_resp.status_code >= 400:
        raise SocialOAuthError("GitHub sign-in failed.", 502)
    user: dict[str, Any] = user_resp.json()
    subject = str(user.get("id") or "")
    email = (user.get("email") or "").strip().lower()
    if not email:
        emails_resp = await client.get("https://api.github.com/user/emails", headers=headers)
        if emails_resp.status_code >= 400:
            raise SocialOAuthError("GitHub did not return an email address.", 400)
        for row in emails_resp.json():
            if row.get("primary") and row.get("verified"):
                email = (row.get("email") or "").strip().lower()
                break
        if not email:
            for row in emails_resp.json():
                if row.get("verified"):
                    email = (row.get("email") or "").strip().lower()
                    break
    if not email:
        raise SocialOAuthError("GitHub did not return a verified email address.", 400)
    display = (user.get("name") or user.get("login") or email.split("@", 1)[0]).strip()[:120]
    return SocialProfile(
        subject=subject,
        email=email,
        display_name=display,
        email_verified=True,
    )
