from __future__ import annotations

from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from jwt import InvalidTokenError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_session
from app.keys import SigningKeys
from app.models import Member
from app.security import (
    issue_access_token,
    pkce_challenge_s256,
    safe_next_path,
    verify_access_token,
)
from app.services import (
    AuthError,
    client_redirects,
    consume_auth_code,
    create_auth_code,
    create_refresh_token,
    get_oauth_client,
    rotate_refresh_token,
)
from app.templating import templates

router = APIRouter()


def keys(request: Request) -> SigningKeys:
    return request.app.state.signing_keys


def load_bearer_member(request: Request, session: Session) -> Member | None:
    header = request.headers.get("authorization") or ""
    if not header.lower().startswith("bearer "):
        return None
    token = header.split(" ", 1)[1].strip()
    try:
        payload = verify_access_token(token, keys(request).private_key, get_settings().public_base_url)
    except InvalidTokenError:
        return None
    member = session.get(Member, payload.get("sub"))
    if member is None or not member.is_active:
        return None
    return member


@router.get("/.well-known/openid-configuration")
@router.get("/.well-known/oauth-authorization-server")
def discovery(request: Request):
    issuer = get_settings().public_base_url.rstrip("/")
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth/authorize",
        "token_endpoint": f"{issuer}/oauth/token",
        "userinfo_endpoint": f"{issuer}/oauth/userinfo",
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
    }


@router.get("/.well-known/jwks.json")
def jwks(request: Request):
    return keys(request).jwks()


@router.get("/oauth/authorize")
def authorize(
    request: Request,
    session: Session = Depends(get_session),
    response_type: str = "",
    client_id: str = "",
    redirect_uri: str = "",
    state: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "S256",
    scope: str = "openid profile email",
):
    member = getattr(request.state, "member", None)
    if member is None:
        nxt = request.url.path + (("?" + request.url.query) if request.url.query else "")
        return RedirectResponse("/login?next=" + quote(safe_next_path(nxt), safe=""), status_code=303)
    if response_type != "code":
        return JSONResponse({"error": "unsupported_response_type"}, status_code=400)
    if code_challenge_method != "S256" or not code_challenge:
        return JSONResponse({"error": "invalid_request", "error_description": "PKCE S256 is required"}, status_code=400)
    client = get_oauth_client(session, client_id)
    if client is None or redirect_uri not in client_redirects(client):
        return JSONResponse({"error": "unauthorized_client"}, status_code=400)
    code = create_auth_code(
        session,
        client=client,
        member=member,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )
    params = {"code": code}
    if state:
        params["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}{urlencode(params)}", status_code=302)


@router.post("/oauth/token")
async def token(request: Request, session: Session = Depends(get_session)):
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        form = await request.json()
    else:
        raw = await request.form()
        form = dict(raw)
    grant_type = form.get("grant_type")
    client_id = form.get("client_id") or get_settings().oauth_first_party_client_id
    client = get_oauth_client(session, client_id)
    if client is None:
        return JSONResponse({"error": "invalid_client"}, status_code=401)
    settings = get_settings()
    signing = keys(request)
    try:
        if grant_type == "authorization_code":
            code = form.get("code") or ""
            redirect_uri = form.get("redirect_uri") or ""
            verifier = form.get("code_verifier") or ""
            row = consume_auth_code(session, code=code, client_id=client.id, redirect_uri=redirect_uri)
            if row.code_challenge_method != "S256" or pkce_challenge_s256(verifier) != row.code_challenge:
                return JSONResponse({"error": "invalid_grant", "error_description": "PKCE verification failed"}, status_code=400)
            member = session.get(Member, row.member_id)
            if member is None:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            refresh = create_refresh_token(
                session, client_id=client.id, member_id=member.id, days=settings.refresh_token_days
            )
        elif grant_type == "refresh_token":
            member, refresh = rotate_refresh_token(
                session,
                refresh_token=form.get("refresh_token") or "",
                client_id=client.id,
                days=settings.refresh_token_days,
            )
        else:
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
    except AuthError as exc:
        return JSONResponse({"error": "invalid_grant", "error_description": exc.message}, status_code=exc.status_code)

    access = issue_access_token(
        key=signing.private_key,
        kid=signing.kid,
        issuer=settings.public_base_url,
        audience=client.id,
        member_id=member.id,
        email=member.email,
        name=member.display_name,
        role=member.role,
        minutes=settings.access_token_minutes,
    )
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": settings.access_token_minutes * 60,
        "scope": "openid profile email",
    }


@router.get("/oauth/userinfo")
def userinfo(request: Request, session: Session = Depends(get_session)):
    member = getattr(request.state, "member", None) or load_bearer_member(request, session)
    if member is None:
        return JSONResponse({"error": "invalid_token"}, status_code=401)
    return {
        "sub": member.id,
        "email": member.email,
        "email_verified": member.email_verified,
        "name": member.display_name,
        "role": member.role,
    }


@router.get("/oauth/callback")
def callback(request: Request, code: str | None = None, error: str | None = None):
    member = getattr(request.state, "member", None)
    return templates.TemplateResponse(
        request,
        "oauth_callback.html",
        {"code": code, "error": error, "member": member, "section": "profile", "settings": get_settings()},
    )
