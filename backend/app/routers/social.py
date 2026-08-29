from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_session
from app.routers.auth import clear_session_cookie, set_session_cookie
from app.security import safe_next_path
from app.services import AuthError, create_session, login_oauth_member
from app.social_oauth import (
    SocialOAuthError,
    authorize_url,
    exchange_code,
    provider_enabled,
    sign_oauth_state,
    verify_oauth_state,
)
from app.templating import templates

router = APIRouter()


def _client_meta(request: Request) -> tuple[str | None, str | None]:
    return request.headers.get("user-agent"), request.client.host if request.client else None


@router.get("/auth/google")
@router.get("/auth/github")
async def social_start(request: Request, next: str = "/dashboard"):
    provider = request.url.path.rsplit("/", 1)[-1]
    settings = get_settings()
    if not provider_enabled(settings, provider):
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "error": f"{provider.title()} sign-in is not configured.",
                "next": safe_next_path(next),
                "settings": settings,
            },
            status_code=503,
        )
    state = sign_oauth_state(settings.secret_key, provider=provider, next_path=safe_next_path(next))
    return RedirectResponse(authorize_url(settings, provider, state=state), status_code=302)


@router.get("/auth/google/callback")
@router.get("/auth/github/callback")
async def social_callback(
    request: Request,
    session: Session = Depends(get_session),
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
):
    provider = "google" if request.url.path.endswith("/google/callback") else "github"
    settings = get_settings()
    if error:
        return RedirectResponse("/login?" + urlencode({"notice": "Social sign-in was cancelled."}), status_code=303)
    if not code or not state:
        return RedirectResponse("/login?" + urlencode({"error": "Missing OAuth response."}), status_code=303)
    if not provider_enabled(settings, provider):
        return RedirectResponse("/login?" + urlencode({"error": "Social sign-in is not configured."}), status_code=303)

    try:
        next_path = verify_oauth_state(settings.secret_key, state, provider)
        profile = await exchange_code(settings, provider, code=code)
        member = login_oauth_member(
            session,
            provider=provider,
            subject=profile.subject,
            email=profile.email,
            display_name=profile.display_name,
            email_verified=profile.email_verified,
        )
    except SocialOAuthError as exc:
        return RedirectResponse("/login?" + urlencode({"error": exc.message}), status_code=303)
    except AuthError as exc:
        return RedirectResponse("/login?" + urlencode({"error": exc.message}), status_code=303)

    ua, ip = _client_meta(request)
    token = create_session(session, member, hours=settings.session_hours, user_agent=ua, ip_address=ip)
    response = RedirectResponse(next_path, status_code=303)
    set_session_cookie(response, token)
    return response
