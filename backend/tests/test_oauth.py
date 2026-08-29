import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlparse

from tests.conftest import register_verify_login


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
    return verifier, challenge


def test_oauth_authorization_code_pkce_and_userinfo(client):
    register_verify_login(client, "oauth@example.com", "OAuth Member")
    verifier, challenge = _pkce()
    redirect_uri = "http://testserver/oauth/callback"
    authorize = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "workers-club",
            "redirect_uri": redirect_uri,
            "state": "club-state",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert authorize.status_code == 302, authorize.text
    location = authorize.headers["location"]
    assert location.startswith(redirect_uri)
    params = parse_qs(urlparse(location).query)
    code = params["code"][0]
    assert params["state"][0] == "club-state"

    token = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "workers-club",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
    )
    assert token.status_code == 200, token.text
    body = token.json()
    assert body["token_type"] == "Bearer"
    access = body["access_token"]
    refresh = body["refresh_token"]

    client.cookies.clear()
    gated = client.get("/api/me")
    assert gated.status_code == 401

    me = client.get("/api/me", headers={"Authorization": f"Bearer {access}"})
    assert me.status_code == 200
    assert me.json()["email"] == "oauth@example.com"

    userinfo = client.get("/oauth/userinfo", headers={"Authorization": f"Bearer {access}"})
    assert userinfo.status_code == 200
    assert userinfo.json()["name"] == "OAuth Member"

    rotated = client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "client_id": "workers-club",
            "refresh_token": refresh,
        },
    )
    assert rotated.status_code == 200
    assert rotated.json()["access_token"]

    replay = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "workers-club",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
    )
    assert replay.status_code == 400


def test_authorize_rejects_missing_pkce(client):
    register_verify_login(client, "pkce@example.com", "Pkce")
    response = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "workers-club",
            "redirect_uri": "http://testserver/oauth/callback",
        },
    )
    assert response.status_code == 400
