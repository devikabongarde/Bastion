import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

pytestmark = pytest.mark.integration


def test_runtime_role_cannot_read_or_write_another_tenant() -> None:
    api_url = os.getenv("BG_DATABASE_URL")
    migration_url = os.getenv("BG_MIGRATION_DATABASE_URL")
    if not api_url or not migration_url:
        pytest.skip("set BG_DATABASE_URL and BG_MIGRATION_DATABASE_URL for PostgreSQL RLS tests")

    org_a, org_b = uuid4(), uuid4()
    site_a, site_b = uuid4(), uuid4()
    with create_engine(migration_url).begin() as connection:
        for org_id in (org_a, org_b):
            connection.execute(
                text("INSERT INTO organizations (id, slug, name) VALUES (:id, :slug, :name)"),
                {"id": org_id, "slug": f"rls-test-{org_id}", "name": "RLS test"},
            )
            connection.execute(
                text("SELECT set_config('app.org_id', :org_id, true)"),
                {"org_id": str(org_id)},
            )
            connection.execute(
                text("""
                    INSERT INTO sites (id, org_id, name, timezone, scope)
                    VALUES (:id, :org_id, 'RLS test site', 'UTC', '{}'::jsonb)
                """),
                {"id": site_a if org_id == org_a else site_b, "org_id": org_id},
            )

    try:
        with create_engine(api_url).begin() as connection:
            connection.execute(
                text("SELECT set_config('app.org_id', :org_id, true)"),
                {"org_id": str(org_b)},
            )
            assert (
                connection.execute(
                    text("SELECT id FROM sites WHERE id = :site_id"), {"site_id": site_a}
                ).first()
                is None
            )
            assert (
                connection.execute(
                    text("SELECT id FROM sites WHERE id = :site_id"), {"site_id": site_b}
                ).scalar_one()
                == site_b
            )
            with pytest.raises(DBAPIError):
                with connection.begin_nested():
                    connection.execute(
                        text("""
                            INSERT INTO sites (id, org_id, name, timezone, scope)
                            VALUES (:id, :org_id, 'Cross-tenant write', 'UTC', '{}'::jsonb)
                        """),
                        {"id": uuid4(), "org_id": org_a},
                    )
    finally:
        with create_engine(migration_url).begin() as connection:
            for org_id in (org_a, org_b):
                connection.execute(
                    text("SELECT set_config('app.org_id', :org_id, true)"),
                    {"org_id": str(org_id)},
                )
                connection.execute(
                    text("DELETE FROM sites WHERE org_id = :org_id"), {"org_id": org_id}
                )
            connection.execute(
                text("DELETE FROM organizations WHERE id IN (:org_a, :org_b)"),
                {"org_a": org_a, "org_b": org_b},
            )
