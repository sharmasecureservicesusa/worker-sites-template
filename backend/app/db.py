from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings

_engine: Engine | None = None
SessionLocal: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    global _engine, SessionLocal
    if _engine is None:
        settings = get_settings()
        _engine = create_engine(
            settings.database_url,
            pool_pre_ping=True,
            pool_recycle=280,
            future=True,
        )
        SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False, future=True)
    return _engine


def get_session() -> Generator[Session, None, None]:
    if SessionLocal is None:
        get_engine()
    assert SessionLocal is not None
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def reset_engine() -> None:
    global _engine, SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    SessionLocal = None


def dolt_commit(session: Session, message: str) -> None:
    """Snapshot the working set in Dolt when there are staged/unstaged table changes."""
    status = session.execute(text("SELECT table_name FROM dolt_status")).all()
    if not status:
        return
    try:
        session.execute(text("CALL DOLT_COMMIT('-Am', :message)"), {"message": message})
        session.commit()
    except Exception as exc:  # noqa: BLE001 — Dolt raises when the working set is clean
        session.rollback()
        if "nothing to commit" not in str(exc).lower():
            raise
