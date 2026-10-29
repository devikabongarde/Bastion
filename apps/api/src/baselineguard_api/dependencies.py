from collections.abc import Generator

from baselineguard_persistence.database import get_engine, scoped_session
from fastapi import Depends, Request
from sqlalchemy.orm import Session

from baselineguard_api.config import get_settings
from baselineguard_api.security import Principal, require_principal


def get_db(request: Request) -> Generator[Session, None, None]:
    # Readiness has no organization scope and only performs SELECT 1.
    yield from scoped_session(get_engine(get_settings().database_url), None)


def get_org_db(
    request: Request,
    principal: Principal = Depends(require_principal),
) -> Generator[Session, None, None]:
    yield from scoped_session(get_engine(get_settings().database_url), principal.org_id)
