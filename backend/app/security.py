from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from jwt import InvalidTokenError, decode as jwt_decode, encode as jwt_encode
from jwt.algorithms import RSAAlgorithm

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PASSWORD_RE = re.compile(r"^(?=.*[A-Za-z])(?=.*\d).{10,}$")


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def new_id() -> str:
    return secrets.token_hex(16)


def normalize_email(email: str) -> str:
    return email.strip().lower()


def valid_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email)) and len(email) <= 255


def valid_password(password: str) -> bool:
    return bool(PASSWORD_RE.match(password))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    n, r, p, dklen = 2**14, 8, 1, 32
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dklen)
    return (
        f"scrypt${n}${r}${p}$"
        f"{base64.b64encode(salt).decode()}$"
        f"{base64.b64encode(digest).decode()}"
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n_s, r_s, p_s, salt_b64, hash_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n_s),
            r=int(r_s),
            p=int(p_s),
            dklen=len(expected),
        )
        return hmac.compare_digest(digest, expected)
    except (ValueError, TypeError):
        return False


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def random_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def numeric_code(digits: int = 6) -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(digits))


def safe_next_path(value: str | None) -> str:
    if not value:
        return "/dashboard"
    if not value.startswith("/") or value.startswith("//") or "://" in value:
        return "/dashboard"
    return value


def pkce_challenge_s256(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def generate_rsa_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def private_key_from_pem(pem: str) -> RSAPrivateKey:
    key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    if not isinstance(key, RSAPrivateKey):
        raise ValueError("JWT_PRIVATE_KEY_PEM must be an RSA private key")
    return key


def private_key_pem(key: RSAPrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def public_jwk(key: RSAPrivateKey, kid: str) -> dict[str, Any]:
    public = key.public_key()
    jwk = RSAAlgorithm.to_jwk(public, as_dict=True)
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return jwk


def issue_access_token(
    *,
    key: RSAPrivateKey,
    kid: str,
    issuer: str,
    audience: str,
    member_id: str,
    email: str,
    name: str,
    role: str,
    minutes: int,
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": issuer,
        "sub": member_id,
        "aud": audience,
        "email": email,
        "name": name,
        "role": role,
        "token_use": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=minutes)).timestamp()),
    }
    return jwt_encode(payload, key, algorithm="RS256", headers={"kid": kid})


def verify_access_token(token: str, key: RSAPrivateKey, issuer: str) -> dict[str, Any]:
    public = key.public_key()
    return jwt_decode(
        token,
        key=public,
        algorithms=["RS256"],
        issuer=issuer,
        options={"require": ["exp", "iat", "sub", "iss"], "verify_aud": False},
    )


def token_error_message(exc: InvalidTokenError) -> str:
    return str(exc) or "Invalid access token"
