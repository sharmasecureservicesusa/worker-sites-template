MEMBER_SECTIONS = [
    "/",
    "/dashboard",
    "/directory",
    "/library",
    "/library/house-rules",
    "/history",
    "/profile",
    "/oauth/callback",
]

MEMBER_APIS = ["/api/me", "/api/members", "/api/resources", "/api/history"]


def test_health_and_static_are_public(client):
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["ok"] is True
    css = client.get("/static/app.css")
    assert css.status_code == 200
    assert "--accent" in css.text
    robots = client.get("/robots.txt")
    assert robots.status_code == 200
    assert "Disallow: /" in robots.text


def test_login_page_is_public(client):
    page = client.get("/login")
    assert page.status_code == 200
    assert "Sign in" in page.text
    assert "Enter the club" in page.text


def test_every_section_requires_membership(client):
    for path in MEMBER_SECTIONS:
        response = client.get(path)
        assert response.status_code == 303, path
        assert response.headers["location"].startswith("/login")
    for path in MEMBER_APIS:
        response = client.get(path)
        assert response.status_code == 401, path


def test_discovery_is_public(client):
    doc = client.get("/.well-known/openid-configuration")
    assert doc.status_code == 200
    body = doc.json()
    assert body["issuer"] == "http://testserver"
    assert body["authorization_endpoint"].endswith("/oauth/authorize")
    jwks = client.get("/.well-known/jwks.json")
    assert jwks.status_code == 200
    assert jwks.json()["keys"][0]["alg"] == "RS256"
