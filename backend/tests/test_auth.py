from tests.conftest import PASSWORD, register_verify_login


def test_register_rejects_weak_password(client):
    response = client.post(
        "/api/auth/register",
        data={"email": "weak@example.com", "display_name": "Weak", "password": "short"},
    )
    assert response.status_code == 400


def test_duplicate_email_conflict(client):
    register_verify_login(client, "dup@example.com", "Dup")
    client.post("/api/auth/logout")
    again = client.post(
        "/api/auth/register",
        data={"email": "dup@example.com", "display_name": "Other", "password": PASSWORD},
    )
    assert again.status_code == 409


def test_unverified_member_cannot_sign_in(client):
    created = client.post(
        "/api/auth/register",
        data={"email": "pending@example.com", "display_name": "Pending", "password": PASSWORD},
    )
    assert created.status_code == 201
    login = client.post(
        "/api/auth/login",
        data={"email": "pending@example.com", "password": PASSWORD, "next": "/dashboard"},
    )
    assert login.status_code == 403


def test_full_membership_flow_opens_every_section(client):
    register_verify_login(client, "member@example.com", "Club Member")
    dashboard = client.get("/dashboard")
    assert dashboard.status_code == 200
    assert "Welcome back, Club Member" in dashboard.text
    directory = client.get("/directory")
    assert directory.status_code == 200
    assert "member@example.com" in directory.text
    library = client.get("/library")
    assert library.status_code == 200
    assert "OpenAuth" in library.text or "House rules" in library.text
    article = client.get("/library/house-rules")
    assert article.status_code == 200
    history = client.get("/history")
    assert history.status_code == 200
    assert "dolt_log" in history.text or "Register member" in history.text
    profile = client.get("/profile")
    assert profile.status_code == 200
    me = client.get("/api/me")
    assert me.status_code == 200
    assert me.json()["email"] == "member@example.com"


def test_logout_revokes_access(client):
    register_verify_login(client, "leave@example.com", "Leave")
    out = client.post("/api/auth/logout")
    assert out.status_code == 200
    blocked = client.get("/dashboard")
    assert blocked.status_code == 303


def test_password_reset_and_profile_update(client):
    register_verify_login(client, "resetme@example.com", "Reset Me")
    forgot = client.post("/api/auth/forgot", data={"email": "resetme@example.com"})
    assert forgot.status_code == 200
    code = forgot.json()["debug_code"]
    client.post("/api/auth/logout")
    reset = client.post(
        "/api/auth/reset",
        data={"email": "resetme@example.com", "code": code, "password": "BrandNewPass1"},
    )
    assert reset.status_code == 200
    old = client.post(
        "/api/auth/login",
        data={"email": "resetme@example.com", "password": PASSWORD, "next": "/dashboard"},
    )
    assert old.status_code == 401
    new = client.post(
        "/api/auth/login",
        data={"email": "resetme@example.com", "password": "BrandNewPass1", "next": "/dashboard"},
    )
    assert new.status_code == 200
    saved = client.post("/profile", data={"display_name": "Reset Member"})
    assert saved.status_code == 303
    page = client.get("/profile")
    assert "Reset Member" in page.text


def test_html_login_sets_cookie_and_lands_on_dashboard(client):
    register_verify_login(client, "html@example.com", "Html Path")
    client.post("/logout")
    login = client.post(
        "/login",
        data={"email": "html@example.com", "password": PASSWORD, "next": "/directory"},
    )
    assert login.status_code == 303
    assert login.headers["location"] == "/directory"
