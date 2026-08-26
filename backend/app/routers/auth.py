from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session
from starlette.responses import Response

from app.config import get_settings
from app.db import get_session
from app.security import safe_next_path
from app.templating import templates
from app.services import (
    AuthError,
    authenticate_member,
    change_password,
    create_session,
    register_member,
    request_password_reset,
    reset_password,
    revoke_session,
    update_profile,
    verify_email_code,
)

router = APIRouter()
NOTICE = {
    "signed-in": "Welcome back.",
    "registered": "Check your email for a verification code.",
    "verified": "Email verified. You can sign in.",
    "signed-out": "You have been signed out.",
    "reset-sent": "If that email is a member, a reset code is on its way.",
    "reset-ok": "Password updated. Sign in with your new password.",
    "saved": "Saved.",
}


def set_session_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        settings.cookie_name,
        token,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        max_age=settings.session_hours * 3600,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(settings.cookie_name, path="/")


def wants_json(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "application/json" in accept and "text/html" not in accept


def error_response(request: Request, template: str, status_code: int, message: str, **context):
    if wants_json(request) or request.url.path.startswith("/api/"):
        return JSONResponse({"detail": message}, status_code=status_code)
    return templates.TemplateResponse(
        request,
        template,
        {"error": message, "settings": get_settings(), **context},
        status_code=status_code,
    )


@router.get("/login")
def login_form(request: Request, next: str = "/dashboard", notice: str | None = None):
    if getattr(request.state, "member", None):
        return RedirectResponse(safe_next_path(next), status_code=303)
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "next": safe_next_path(next),
            "notice": NOTICE.get(notice or "", ""),
            "settings": get_settings(),
        },
    )


@router.post("/login")
@router.post("/api/auth/login")
def login(
    request: Request,
    session: Session = Depends(get_session),
    email: str = Form(...),
    password: str = Form(...),
    next: str = Form("/dashboard"),
):
    try:
        member = authenticate_member(session, email=email, password=password)
    except AuthError as exc:
        return error_response(request, "login.html", exc.status_code, exc.message, next=safe_next_path(next), settings=get_settings())
    raw = create_session(
        session,
        member,
        hours=get_settings().session_hours,
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
    )
    if request.url.path.startswith("/api/"):
        response = JSONResponse({"email": member.email, "display_name": member.display_name, "role": member.role})
    else:
        response = RedirectResponse(safe_next_path(next), status_code=303)
    set_session_cookie(response, raw)
    return response


@router.get("/register")
def register_form(request: Request):
    if getattr(request.state, "member", None):
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse(request, "register.html", {"settings": get_settings()})


@router.post("/register")
@router.post("/api/auth/register")
def register(
    request: Request,
    session: Session = Depends(get_session),
    email: str = Form(...),
    display_name: str = Form(...),
    password: str = Form(...),
):
    try:
        member, code = register_member(session, email=email, display_name=display_name, password=password)
    except AuthError as exc:
        return error_response(
            request,
            "register.html",
            exc.status_code,
            exc.message,
            email=email,
            display_name=display_name,
        )
    payload = {"email": member.email, "notice": "registered"}
    if get_settings().debug:
        payload["debug_code"] = code
    if request.url.path.startswith("/api/"):
        return JSONResponse(payload, status_code=201)
    query = urlencode({"email": member.email, "notice": "registered", **({"debug_code": code} if get_settings().debug else {})})
    return RedirectResponse(f"/verify?{query}", status_code=303)


@router.get("/verify")
def verify_form(request: Request, email: str = "", notice: str | None = None, debug_code: str | None = None):
    return templates.TemplateResponse(
        request,
        "verify.html",
        {
            "email": email,
            "notice": NOTICE.get(notice or "", notice or ""),
            "debug_code": debug_code if get_settings().debug else None,
            "settings": get_settings(),
        },
    )


@router.post("/verify")
@router.post("/api/auth/verify")
def verify(
    request: Request,
    session: Session = Depends(get_session),
    email: str = Form(...),
    code: str = Form(...),
):
    try:
        verify_email_code(session, email=email, code=code)
    except AuthError as exc:
        return error_response(request, "verify.html", exc.status_code, exc.message, email=email)
    if request.url.path.startswith("/api/"):
        return JSONResponse({"ok": True})
    return RedirectResponse("/login?notice=verified", status_code=303)


@router.get("/forgot")
def forgot_form(request: Request, notice: str | None = None):
    return templates.TemplateResponse(
        request,
        "forgot.html",
        {"notice": NOTICE.get(notice or "", ""), "settings": get_settings()},
    )


@router.post("/forgot")
@router.post("/api/auth/forgot")
def forgot(request: Request, session: Session = Depends(get_session), email: str = Form(...)):
    code = request_password_reset(session, email)
    if request.url.path.startswith("/api/"):
        body = {"ok": True}
        if get_settings().debug and code:
            body["debug_code"] = code
        return JSONResponse(body)
    query = urlencode({"email": email, **({"debug_code": code} if get_settings().debug and code else {})})
    return RedirectResponse(f"/reset?{query}&notice=reset-sent", status_code=303)


@router.get("/reset")
def reset_form(request: Request, email: str = "", notice: str | None = None, debug_code: str | None = None):
    return templates.TemplateResponse(
        request,
        "reset.html",
        {
            "email": email,
            "notice": NOTICE.get(notice or "", notice or ""),
            "debug_code": debug_code if get_settings().debug else None,
            "settings": get_settings(),
        },
    )


@router.post("/reset")
@router.post("/api/auth/reset")
def reset(
    request: Request,
    session: Session = Depends(get_session),
    email: str = Form(...),
    code: str = Form(...),
    password: str = Form(...),
):
    try:
        reset_password(session, email=email, code=code, password=password)
    except AuthError as exc:
        return error_response(request, "reset.html", exc.status_code, exc.message, email=email)
    if request.url.path.startswith("/api/"):
        return JSONResponse({"ok": True})
    return RedirectResponse("/login?notice=reset-ok", status_code=303)


@router.post("/logout")
@router.post("/api/auth/logout")
def logout(request: Request, session: Session = Depends(get_session)):
    settings = get_settings()
    revoke_session(session, request.cookies.get(settings.cookie_name))
    if request.url.path.startswith("/api/"):
        response = JSONResponse({"ok": True})
    else:
        response = RedirectResponse("/login?notice=signed-out", status_code=303)
    clear_session_cookie(response)
    return response


@router.post("/profile")
def save_profile(
    request: Request,
    session: Session = Depends(get_session),
    display_name: str = Form(...),
):
    member = request.state.member
    try:
        update_profile(session, member, display_name=display_name)
    except AuthError as exc:
        return error_response(request, "profile.html", exc.status_code, exc.message, member=member, section="profile")
    return RedirectResponse("/profile?notice=saved", status_code=303)


@router.post("/profile/password")
def save_password(
    request: Request,
    session: Session = Depends(get_session),
    current_password: str = Form(...),
    new_password: str = Form(...),
):
    member = request.state.member
    try:
        change_password(session, member, current_password=current_password, new_password=new_password)
    except AuthError as exc:
        return error_response(request, "profile.html", exc.status_code, exc.message, member=member, section="profile")
    return RedirectResponse("/profile?notice=saved", status_code=303)
