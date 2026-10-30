from __future__ import annotations

import os
from uuid import uuid4

import pytest
from baselineguard_persistence.models import Organization, Site
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from baselineguard_api.routes.v1.inventory import (
    AssetCsvCommitRequest,
    AssetCsvCommitRow,
    AssetCsvImportPreviewRequest,
    commit_asset_csv,
    list_assets,
    preview_asset_csv,
)
from baselineguard_api.security import Principal

pytestmark = [pytest.mark.integration]


def test_csv_preview_commit_and_list_round_trip() -> None:
    database_url = os.getenv("BG_MIGRATION_DATABASE_URL")
    if not database_url:
        pytest.skip("set BG_MIGRATION_DATABASE_URL for PostgreSQL CSV import tests")

    org_id, site_id = uuid4(), uuid4()
    engine = create_engine(database_url)
    try:
        with Session(engine) as session:
            session.execute(
                text("SELECT set_config('app.org_id', :org_id, true)"), {"org_id": str(org_id)}
            )
            session.add(Organization(id=org_id, slug=f"csv-{org_id}", name="CSV test"))
            session.flush()
            session.add(
                Site(
                    id=site_id,
                    org_id=org_id,
                    name="CSV site",
                    timezone="UTC",
                    scope={"allowed_cidrs": ["10.30.0.0/16"], "allowed_ports": [22]},
                )
            )
            session.flush()
            principal = Principal(
                user_id=uuid4(),
                org_id=org_id,
                roles=frozenset({"platform_admin"}),
                site_ids=frozenset({site_id}),
            )
            csv_text = (
                "name,address,port,category,criticality,role\n"
                "app-01,10.30.1.1,22,linux,high,server\n"
                "fw-01,10.30.0.1,22,firewall,critical,firewall\n"
                "sw-01,10.30.0.2,22,switch,high,switch\n"
                "rtr-01,10.30.0.3,22,router,high,router\n"
                "legacy-01,10.30.0.4,22,network,normal,switch\n"
                "bad-cat,10.30.0.5,22,mainframe,normal,server\n"
            )
            preview = preview_asset_csv(
                AssetCsvImportPreviewRequest(csv_text=csv_text, default_site_id=site_id),
                principal,
                session,
            )
            rows = {row.name: row for row in preview.rows}
            assert preview.valid_rows == 5
            assert not rows["bad-cat"].valid
            assert rows["fw-01"].adapter_id == "fortigate-ssh"
            assert rows["sw-01"].adapter_id == "cisco-iosxe"
            assert rows["legacy-01"].category == "switch"

            committed = commit_asset_csv(
                AssetCsvCommitRequest(
                    rows=[
                        AssetCsvCommitRow(
                            name=row.name,
                            address=row.address,
                            port=row.port,
                            category=row.category,
                            criticality=row.criticality,
                            declared_role=row.declared_role,
                            adapter_id=row.adapter_id,
                            site_id=site_id,
                        )
                        for row in preview.rows
                        if row.valid
                    ]
                ),
                principal,
                session,
            )
            assert committed.created_count == 5
            # Imported assets must be readable: a list-typed `tags` once broke this call.
            listed = list_assets(principal, session, limit=50, cursor=None, category=None)
            assert {asset.name for asset in listed.items} >= {"app-01", "fw-01", "legacy-01"}
            assert all(asset.tags == {} for asset in listed.items)
            session.rollback()
    finally:
        engine.dispose()
