from collections.abc import Generator
from functools import lru_cache
from uuid import UUID

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker


@lru_cache(maxsize=4)
def get_engine(database_url: str) -> Engine:
    if not database_url.startswith("postgresql+psycopg://"):
        raise ValueError("Database URLs must use the PostgreSQL psycopg driver")
    return create_engine(
        database_url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        pool_recycle=1800,
        hide_parameters=True,
    )


def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def scoped_session(engine: Engine, org_id: UUID | None) -> Generator[Session, None, None]:
    """Open one transaction and set tenant context locally so it cannot leak through the pool."""
    factory = session_factory(engine)
    with factory.begin() as session:
        if org_id is not None:
            session.execute(
                text("SELECT set_config('app.org_id', :org_id, true)"),
                {"org_id": str(org_id)},
            )
        yield session
