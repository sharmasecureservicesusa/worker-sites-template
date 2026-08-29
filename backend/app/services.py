from __future__ import annotations

import hmac
import json
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.db import dolt_commit
from app.models import (
    AuthSession,
    Member,
    OAuthAuthCode,
    OAuthClient,
    OAuthRefreshToken,
    Resource,
    VerificationCode,
)
from app.security import (
    hash_password,
    new_id,
    normalize_email,
    numeric_code,
    random_token,
    sha256_hex,
    utcnow,
    valid_email,
    valid_password,
    verify_password,
)


class AuthError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, list] = {}

    def too_many(self, key: str, limit: int, window_seconds: int) -> bool:
        now = utcnow()
        bucket = [ts for ts in self._hits.get(key, []) if (now - ts).total_seconds() < window_seconds]
        if len(bucket) >= limit:
            self._hits[key] = bucket
            return True
        bucket.append(now)
        self._hits[key] = bucket
        return False


rate_limiter = RateLimiter()


def get_member_by_email(session: Session, email: str) -> Member | None:
    return session.scalar(select(Member).where(Member.email == normalize_email(email)))


def register_member(session: Session, *, email: str, display_name: str, password: str) -> tuple[Member, str]:
    email = normalize_email(email)
    display_name = display_name.strip()
    if not valid_email(email):
        raise AuthError("Enter a valid email address.")
    if not display_name or len(display_name) > 120:
        raise AuthError("Display name is required.")
    if not valid_password(password):
        raise AuthError("Password must be at least 10 characters and include a letter and a number.")
    if get_member_by_email(session, email):
        raise AuthError("An account with that email already exists.", 409)

    now = utcnow()
    member = Member(
        id=new_id(),
        email=email,
        display_name=display_name,
        password_hash=hash_password(password),
        role="member",
        email_verified=False,
        is_active=True,
        created_at=now,
        updated_at=now,
    )
    session.add(member)
    session.flush()
    code = issue_verification_code(session, member, "verify_email")
    session.commit()
    dolt_commit(session, f"Register member {email}")
    return member, code


def issue_verification_code(session: Session, member: Member, purpose: str) -> str:
    now = utcnow()
    code = numeric_code(6)
    row = VerificationCode(
        id=new_id(),
        member_id=member.id,
        purpose=purpose,
        code_hash=sha256_hex(code),
        expires_at=now + timedelta(minutes=20),
        used_at=None,
        created_at=now,
    )
    session.add(row)
    return code


def verify_email_code(session: Session, *, email: str, code: str) -> Member:
    member = get_member_by_email(session, email)
    if member is None:
        raise AuthError("We could not verify that code.")
    consume_code(session, member, "verify_email", code)
    member.email_verified = True
    member.updated_at = utcnow()
    session.commit()
    dolt_commit(session, f"Verify email for {member.email}")
    return member


def consume_code(session: Session, member: Member, purpose: str, code: str) -> None:
    now = utcnow()
    rows = session.scalars(
        select(VerificationCode)
        .where(
            VerificationCode.member_id == member.id,
            VerificationCode.purpose == purpose,
            VerificationCode.used_at.is_(None),
        )
        .order_by(VerificationCode.created_at.desc())
    ).all()
    for row in rows:
        if row.expires_at < now:
            continue
        if hmac_eq(row.code_hash, sha256_hex(code.strip())):
            row.used_at = now
            return
    raise AuthError("That code is invalid or expired.")


def hmac_eq(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)


def authenticate_member(session: Session, *, email: str, password: str) -> Member:
    email = normalize_email(email)
    if rate_limiter.too_many(f"login:{email}", limit=8, window_seconds=900):
        raise AuthError("Too many sign-in attempts. Try again in a few minutes.", 429)
    member = get_member_by_email(session, email)
    if member is None or not verify_password(password, member.password_hash):
        raise AuthError("Email or password is incorrect.", 401)
    if not member.is_active:
        raise AuthError("This membership is disabled.", 403)
    if not member.email_verified:
        raise AuthError("Verify your email before signing in.", 403)
    return member


def create_session(
    session: Session,
    member: Member,
    *,
    hours: int,
    user_agent: str | None,
    ip_address: str | None,
) -> str:
    raw = random_token(32)
    now = utcnow()
    row = AuthSession(
        id=new_id(),
        member_id=member.id,
        token_hash=sha256_hex(raw),
        expires_at=now + timedelta(hours=hours),
        revoked_at=None,
        user_agent=(user_agent or "")[:512] or None,
        ip_address=(ip_address or "")[:64] or None,
        created_at=now,
    )
    session.add(row)
    session.commit()
    dolt_commit(session, f"Create session for {member.email}")
    return raw


def load_session_member(session: Session, raw_token: str | None) -> Member | None:
    if not raw_token:
        return None
    row = session.scalar(select(AuthSession).where(AuthSession.token_hash == sha256_hex(raw_token)))
    now = utcnow()
    if row is None or row.revoked_at is not None or row.expires_at < now:
        return None
    member = session.get(Member, row.member_id)
    if member is None or not member.is_active or not member.email_verified:
        return None
    return member


def revoke_session(session: Session, raw_token: str | None) -> None:
    if not raw_token:
        return
    row = session.scalar(select(AuthSession).where(AuthSession.token_hash == sha256_hex(raw_token)))
    if row is None or row.revoked_at is not None:
        return
    row.revoked_at = utcnow()
    session.commit()
    dolt_commit(session, "Revoke session")


def request_password_reset(session: Session, email: str) -> str | None:
    member = get_member_by_email(session, email)
    if member is None or not member.is_active:
        return None
    code = issue_verification_code(session, member, "reset_password")
    session.commit()
    dolt_commit(session, f"Password reset requested for {member.email}")
    return code


def reset_password(session: Session, *, email: str, code: str, password: str) -> Member:
    if not valid_password(password):
        raise AuthError("Password must be at least 10 characters and include a letter and a number.")
    member = get_member_by_email(session, email)
    if member is None:
        raise AuthError("We could not reset that password.")
    consume_code(session, member, "reset_password", code)
    member.password_hash = hash_password(password)
    member.updated_at = utcnow()
    for row in session.scalars(select(AuthSession).where(AuthSession.member_id == member.id)).all():
        if row.revoked_at is None:
            row.revoked_at = utcnow()
    session.commit()
    dolt_commit(session, f"Reset password for {member.email}")
    return member


def change_password(session: Session, member: Member, *, current_password: str, new_password: str) -> None:
    if not verify_password(current_password, member.password_hash):
        raise AuthError("Current password is incorrect.", 401)
    if not valid_password(new_password):
        raise AuthError("Password must be at least 10 characters and include a letter and a number.")
    member.password_hash = hash_password(new_password)
    member.updated_at = utcnow()
    session.commit()
    dolt_commit(session, f"Change password for {member.email}")


def update_profile(session: Session, member: Member, *, display_name: str) -> Member:
    display_name = display_name.strip()
    if not display_name or len(display_name) > 120:
        raise AuthError("Display name is required.")
    member.display_name = display_name
    member.updated_at = utcnow()
    session.commit()
    dolt_commit(session, f"Update profile for {member.email}")
    return member


def create_auth_code(
    session: Session,
    *,
    client: OAuthClient,
    member: Member,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str,
) -> str:
    raw = random_token(32)
    now = utcnow()
    row = OAuthAuthCode(
        id=new_id(),
        code_hash=sha256_hex(raw),
        client_id=client.id,
        member_id=member.id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        expires_at=now + timedelta(minutes=10),
        consumed_at=None,
        created_at=now,
    )
    session.add(row)
    session.commit()
    dolt_commit(session, f"Issue authorization code for {member.email}")
    return raw


def consume_auth_code(session: Session, *, code: str, client_id: str, redirect_uri: str) -> OAuthAuthCode:
    row = session.scalar(select(OAuthAuthCode).where(OAuthAuthCode.code_hash == sha256_hex(code)))
    now = utcnow()
    if (
        row is None
        or row.client_id != client_id
        or row.redirect_uri != redirect_uri
        or row.consumed_at is not None
        or row.expires_at < now
    ):
        raise AuthError("Invalid authorization code.", 400)
    row.consumed_at = now
    session.commit()
    return row


def create_refresh_token(session: Session, *, client_id: str, member_id: str, days: int) -> str:
    raw = random_token(32)
    now = utcnow()
    row = OAuthRefreshToken(
        id=new_id(),
        token_hash=sha256_hex(raw),
        client_id=client_id,
        member_id=member_id,
        expires_at=now + timedelta(days=days),
        revoked_at=None,
        created_at=now,
    )
    session.add(row)
    session.commit()
    dolt_commit(session, "Issue refresh token")
    return raw


def rotate_refresh_token(session: Session, *, refresh_token: str, client_id: str, days: int) -> tuple[Member, str]:
    row = session.scalar(
        select(OAuthRefreshToken).where(OAuthRefreshToken.token_hash == sha256_hex(refresh_token))
    )
    now = utcnow()
    if (
        row is None
        or row.client_id != client_id
        or row.revoked_at is not None
        or row.expires_at < now
    ):
        raise AuthError("Invalid refresh token.", 400)
    row.revoked_at = now
    member = session.get(Member, row.member_id)
    if member is None or not member.is_active:
        raise AuthError("Invalid refresh token.", 400)
    session.commit()
    new_raw = create_refresh_token(session, client_id=client_id, member_id=member.id, days=days)
    return member, new_raw


def client_redirects(client: OAuthClient) -> list[str]:
    return json.loads(client.redirect_uris)


def get_oauth_client(session: Session, client_id: str) -> OAuthClient | None:
    return session.get(OAuthClient, client_id)


def seed_if_needed(session: Session, settings: Settings) -> None:
    client = session.get(OAuthClient, settings.oauth_first_party_client_id)
    if client is None:
        redirects = [
            f"{settings.public_base_url.rstrip('/')}/oauth/callback",
            "http://127.0.0.1:8000/oauth/callback",
            "http://localhost:8000/oauth/callback",
        ]
        session.add(
            OAuthClient(
                id=settings.oauth_first_party_client_id,
                name="Workers Club",
                secret_hash=None,
                redirect_uris=json.dumps(list(dict.fromkeys(redirects))),
                is_confidential=False,
                created_at=utcnow(),
            )
        )

    if session.scalar(select(Resource.id).limit(1)) is None:
        now = utcnow()
        session.add_all(
            [
                Resource(
                    id=new_id(),
                    slug="house-rules",
                    title="House rules",
                    summary="How members use the club, the Python backend, and the Dolt ledger.",
                    body=(
                        "Workers Club is members-only. Every page and API route checks an OpenAuth "
                        "session or access token before it returns club data. Passwords are stored "
                        "with scrypt. Authorization codes require PKCE (S256). Writes land in Dolt "
                        "and are committed so you can audit membership history."
                    ),
                    created_at=now,
                ),
                Resource(
                    id=new_id(),
                    slug="openauth-guide",
                    title="OpenAuth sign-in",
                    summary="Email + password, verification codes, and the OAuth 2.0 code flow.",
                    body=(
                        "Register with email and password, enter the verification code, then sign in. "
                        "The club issuer speaks OAuth 2.0 / OpenID discovery so an OpenAuth.js client "
                        "can call /oauth/authorize, /oauth/token, and /oauth/userinfo. Access tokens "
                        "are RS256 JWTs; refresh tokens are opaque and stored hashed in Dolt."
                    ),
                    created_at=now,
                ),
                Resource(
                    id=new_id(),
                    slug="dolt-ledger",
                    title="Dolt membership ledger",
                    summary="SQL with git-style commits for every membership change.",
                    body=(
                        "Dolt is a MySQL-compatible database that versions every table. Registering, "
                        "verifying, signing in, and updating a profile each create a Dolt commit. "
                        "Open History to read dolt_log — the same ledger the Python API uses."
                    ),
                    created_at=now,
                ),
            ]
        )

    if settings.seed_demo and settings.app_env != "test":
        if get_member_by_email(session, settings.demo_email) is None:
            now = utcnow()
            session.add(
                Member(
                    id=new_id(),
                    email=normalize_email(settings.demo_email),
                    display_name="Club Demo",
                    password_hash=hash_password(settings.demo_password),
                    role="member",
                    email_verified=True,
                    is_active=True,
                    created_at=now,
                    updated_at=now,
                )
            )

    session.commit()
    dolt_commit(session, "Seed OpenAuth client, library, and demo member")
