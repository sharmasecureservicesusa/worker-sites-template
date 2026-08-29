from sqlalchemy import create_engine, text

from tests.conftest import register_verify_login


def test_membership_writes_are_dolt_commits(client, dolt_server):
    register_verify_login(client, "ledger@example.com", "Ledger")
    engine = create_engine(f"mysql+pymysql://root@127.0.0.1:{dolt_server['port']}/members")
    with engine.connect() as conn:
        messages = [row[0] for row in conn.execute(text("SELECT message FROM dolt_log")).all()]
    joined = "\n".join(messages)
    assert "Register member ledger@example.com" in joined
    assert "Verify email for ledger@example.com" in joined
    history = client.get("/api/history")
    assert history.status_code == 200
    assert any("Register member" in item["message"] for item in history.json())
