import os
import socket
import subprocess
import time
from pathlib import Path

import pytest
import pymysql
from fastapi.testclient import TestClient

PASSWORD = "MembersOnly1"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_mysql(port: int, database: str | None = None, timeout: float = 45.0) -> None:
    deadline = time.time() + timeout
    last: Exception | None = None
    while time.time() < deadline:
        try:
            kwargs: dict = {
                "host": "127.0.0.1",
                "port": port,
                "user": "root",
                "password": "",
                "connect_timeout": 1,
            }
            if database:
                kwargs["database"] = database
            conn = pymysql.connect(**kwargs)
            conn.close()
            return
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(0.2)
    raise RuntimeError(f"Dolt SQL server did not become ready: {last}")


@pytest.fixture(scope="session")
def dolt_server(tmp_path_factory):
    datadir = tmp_path_factory.mktemp("dolt") / "members"
    datadir.mkdir()
    env = os.environ.copy()
    env["PATH"] = str(Path.home() / "bin") + os.pathsep + env.get("PATH", "")
    subprocess.run(["dolt", "init"], cwd=datadir, check=True, env=env)
    subprocess.run(
        ["dolt", "config", "--local", "--add", "user.name", "Workers Club"],
        cwd=datadir,
        check=True,
        env=env,
    )
    subprocess.run(
        ["dolt", "config", "--local", "--add", "user.email", "club@localhost"],
        cwd=datadir,
        check=True,
        env=env,
    )
    port = _free_port()
    proc = subprocess.Popen(
        ["dolt", "sql-server", "--host", "127.0.0.1", "--port", str(port)],
        cwd=datadir,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        _wait_mysql(port, "members")
        os.environ["DATABASE_URL"] = f"mysql+pymysql://root@127.0.0.1:{port}/members"
        os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"
        os.environ["APP_ENV"] = "test"
        os.environ["DEBUG"] = "true"
        os.environ["SEED_DEMO"] = "false"
        os.environ["PUBLIC_BASE_URL"] = "http://testserver"
        os.environ["COOKIE_SECURE"] = "false"
        yield {"port": port, "datadir": datadir}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture(scope="session")
def app(dolt_server):
    from app.config import clear_settings_cache
    from app.db import reset_engine

    clear_settings_cache()
    reset_engine()
    from app.main import app as fastapi_app

    return fastapi_app


@pytest.fixture()
def client(app):
    with TestClient(app, base_url="http://testserver", follow_redirects=False) as test_client:
        yield test_client


def register_verify_login(client: TestClient, email: str, name: str = "Ada Lovelace") -> None:
    created = client.post(
        "/api/auth/register",
        data={"email": email, "display_name": name, "password": PASSWORD},
    )
    assert created.status_code == 201, created.text
    code = created.json()["debug_code"]
    verified = client.post("/api/auth/verify", data={"email": email, "code": code})
    assert verified.status_code == 200, verified.text
    login = client.post(
        "/api/auth/login",
        data={"email": email, "password": PASSWORD, "next": "/dashboard"},
    )
    assert login.status_code == 200, login.text
    assert client.cookies.get("members_session")
