from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jwt import InvalidTokenError
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware

from app.bootstrap import bootstrap
from app.config import get_settings
from app.db import get_engine
from app.keys import load_signing_keys
from app.models import Member
from app.routers import api, auth, oauth, site
from app.security import verify_access_token
from app.services import load_session_member
from app.templating import templates

PUBLIC_EXACT = {
    "/health",
    "/favicon.ico",
    "/robots.txt",
    "/login",
    "/register",
    "/verify",
    "/forgot",
    "/reset",
    "/api/auth/register",
    "/api/auth/login",
    "/api/auth/verify",
    "/api/auth/forgot",
    "/api/auth/reset",
    "/api/auth/logout",
    "/logout",
    "/oauth/token",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/jwks.json",
}
PUBLIC_PREFIXES = ("/static/",)


def is_public(path: str) -> bool:
    if path in PUBLIC_EXACT:
        return True
    return any(path.startswith(prefix) for prefix in PUBLIC_PREFIXES)


class MembershipGate(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if is_public(path):
            settings = get_settings()
            raw = request.cookies.get(settings.cookie_name)
            if raw:
                with Session(get_engine()) as session:
                    request.state.member = load_session_member(session, raw)
            else:
                request.state.member = None
            response = await call_next(request)
            _secure_headers(response)
            return response

        member = authenticate_request(request)
        if member is None:
            if _wants_json(request, path):
                response = JSONResponse({"detail": "Authentication required"}, status_code=401)
                _secure_headers(response)
                return response
            nxt = path
            if request.url.query:
                nxt = f"{path}?{request.url.query}"
            response = RedirectResponse(f"/login?next={quote(nxt, safe='')}", status_code=303)
            _secure_headers(response)
            return response
        request.state.member = member
        response = await call_next(request)
        _secure_headers(response)
        return response


def authenticate_request(request: Request) -> Member | None:
    settings = get_settings()
    header = request.headers.get("authorization") or ""
    with Session(get_engine()) as session:
        if header.lower().startswith("bearer "):
            token = header.split(" ", 1)[1].strip()
            try:
                payload = verify_access_token(
                    token,
                    request.app.state.signing_keys.private_key,
                    settings.public_base_url,
                )
            except InvalidTokenError:
                return None
            member = session.get(Member, payload.get("sub"))
            if member and member.is_active and member.email_verified:
                session.expunge(member)
                return member
            return None
        raw = request.cookies.get(settings.cookie_name)
        member = load_session_member(session, raw)
        if member is not None:
            session.expunge(member)
        return member


def _wants_json(request: Request, path: str) -> bool:
    if path.startswith("/api/") or path in {"/oauth/token", "/oauth/userinfo"}:
        return True
    accept = request.headers.get("accept", "")
    return "application/json" in accept and "text/html" not in accept


def _secure_headers(response) -> None:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"


@asynccontextmanager
async def lifespan(app: FastAPI):
    bootstrap()
    app.state.signing_keys = load_signing_keys(get_settings())
    yield


def create_app() -> FastAPI:
    application = FastAPI(
        title="Workers Club",
        description="Members-only club with OpenAuth-compatible authentication and a Dolt ledger.",
        lifespan=lifespan,
        redirect_slashes=False,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    application.add_middleware(MembershipGate)
    application.include_router(auth.router)
    application.include_router(oauth.router)
    application.include_router(site.router)
    application.include_router(api.router)

    static_dir = Path(__file__).parent / "static"
    application.mount("/static", StaticFiles(directory=static_dir), name="static")

    @application.get("/health")
    def health():
        return {"ok": True, "service": "workers-club"}

    @application.get("/favicon.ico")
    def favicon():
        return FileResponse(static_dir / "favicon.svg", media_type="image/svg+xml")

    @application.get("/robots.txt")
    def robots():
        return PlainTextResponse("User-agent: *\nDisallow: /\n")

    @application.exception_handler(404)
    async def not_found(request: Request, exc):  # noqa: ARG001
        if is_public(request.url.path) or getattr(request.state, "member", None) is None:
            if request.url.path.startswith("/api/"):
                return JSONResponse({"detail": "Not found"}, status_code=404)
        return templates.TemplateResponse(
            request,
            "not_found.html",
            {"member": getattr(request.state, "member", None), "section": "", "settings": get_settings()},
            status_code=404,
        )

    return application


app = create_app()
