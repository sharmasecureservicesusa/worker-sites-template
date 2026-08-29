from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_engine
from app.models import Base
from app.services import seed_if_needed


def bootstrap() -> None:
    engine = get_engine()
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        seed_if_needed(session, get_settings())
