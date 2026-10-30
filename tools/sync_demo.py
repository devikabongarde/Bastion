"""Bring an existing demo organization up to the full multi-platform scope.

Idempotent: safe to run repeatedly. Users, passwords and MFA secrets are untouched.

    python tools/sync_demo.py            # database: packs, policy, sites, assets, lab trust
    python tools/sync_demo.py --load     # also import sample evidence and run live scans

`--load` needs the API running (with BG_DEMO_LOGIN, BG_LAB_TARGETS and embedded workers)
and, for live scans, the mock device: python tools/mock_targets.py
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
ORG_SLUG = "northwind"
POLICY_NAME = "Enterprise Hardening Baseline (Multi-Platform)"
PACK_FILES = ["phase1-linux.yaml", "windows-server-2019.yaml", "cisco-iosxe-hardening.yaml", "fortigate-fortios.yaml"]
MOCK_KEY = DATA / "mock_ssh_host_rsa.key"
LAB_ADDRESS, LAB_PORT = "127.0.0.1", 2222
MOCK_USER, MOCK_PASSWORD = "audituser", "auditpass"

# name, category, role, criticality, address, port, adapter, identity(family, version), sample profile
IMPORT_ASSETS = [
    ("win-dc-01", "windows", "domain_controller", "critical", "10.20.1.101", 5986, "windows-fixture",
     ("microsoft", "windows_server", "2019"), "hardened"),
    ("win-app-02", "windows", "member_server", "high", "10.20.1.102", 5986, "windows-fixture",
     ("microsoft", "windows_server", "2022"), "mixed"),
    ("branch-rtr-01", "router", "router", "high", "10.20.10.1", 22, "cisco-iosxe-fixture",
     ("cisco", "cisco_ios_xe", "17.9"), "weak"),
    ("dmz-fw-02", "firewall", "firewall", "critical", "10.20.0.3", 443, "fortigate-fixture",
     ("fortinet", "fortigate", "7.2"), "mixed"),
]
LIVE_SSH_ASSETS = [
    ("core-sw-01", "switch", "switch", "critical", "cisco-iosxe", ("cisco", "cisco_ios_xe", "17.12")),
    ("edge-fw-01", "firewall", "firewall", "critical", "fortigate-ssh", ("fortinet", "fortigate", "7.4")),
    ("lab-ubuntu-01", "linux", "server", "high", "linux-ssh", ("canonical", "ubuntu", "22.04")),
]


def load_env() -> None:
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env", override=False)


def superuser_url() -> str:
    return f"postgresql+psycopg://postgres:{os.environ['POSTGRES_SUPERUSER_PASSWORD']}@127.0.0.1:55432/baselineguard"


def fingerprint(key) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def sync_database() -> None:
    import paramiko
    from baselineguard_credentials.envelope import seal_credential
    from baselineguard_persistence.models import (
        Asset,
        AssetCredential,
        AssetTrust,
        Credential,
        Organization,
        Policy,
        PolicyPack,
        RulePack,
        Site,
        User,
    )
    from baselineguard_rule_engine.canonical import semantic_digest
    from baselineguard_rule_engine.packs import load_rule_pack
    from sqlalchemy import create_engine, func, select, text
    from sqlalchemy.orm import Session

    master_key = os.environ.get("BG_MASTER_KEY_FILE", str(DATA / "keys" / "master.key"))
    known_hosts = Path(os.environ.get("BG_KNOWN_HOSTS_FILE", str(DATA / "known_hosts")))
    engine = create_engine(superuser_url(), hide_parameters=True)
    with Session(engine) as db, db.begin():
        org = db.execute(select(Organization).where(Organization.slug == ORG_SLUG)).scalar_one_or_none()
        if org is None:
            raise SystemExit(f"Organization '{ORG_SLUG}' not found. Run tools/seed_demo.py first.")
        db.execute(text("SELECT set_config('app.org_id', :id, true)"), {"id": str(org.id)})
        users = {u.subject: u for u in db.execute(select(User).where(User.org_id == org.id)).scalars()}
        ava, rowan = users["ava"], users["rowan"]

        # 1. Rule packs (current versions)
        packs: list[RulePack] = []
        for file in PACK_FILES:
            manifest = load_rule_pack((ROOT / "content" / "original" / file).read_bytes())
            digest = semantic_digest(manifest)
            row = db.execute(select(RulePack).where(
                RulePack.org_id == org.id, RulePack.pack_key == manifest["pack_id"],
                RulePack.version == manifest["version"],
            )).scalar_one_or_none()
            if row is not None and row.digest != digest:
                raise SystemExit(f"{manifest['pack_id']} {manifest['version']} changed content; bump its version.")
            if row is None:
                row = RulePack(
                    id=uuid4(), org_id=org.id, pack_key=manifest["pack_id"], version=manifest["version"],
                    digest=digest, manifest=manifest, state="approved",
                    rights_metadata={"publisher": manifest["publisher"], "license": manifest["license"],
                                     "rights_reference": manifest.get("rights_reference", "")},
                )
                db.add(row)
                print(f"  + rule pack {manifest['pack_id']} {manifest['version']} ({len(manifest['controls'])} controls)")
            packs.append(row)
        db.flush()

        # 2. Published multi-platform policy over exactly these packs
        spec = {"schema_version": "1.0", "site_ids": [], "overrides": {}, "exclusions": {}}
        policy_digest = semantic_digest({"spec": spec, "packs": sorted(p.digest for p in packs)})
        policy = db.execute(select(Policy).where(
            Policy.org_id == org.id, Policy.digest == policy_digest, Policy.state == "published",
        )).scalar_one_or_none()
        if policy is None:
            revision = (db.execute(select(func.max(Policy.revision)).where(
                Policy.org_id == org.id, Policy.name == POLICY_NAME)).scalar() or 0) + 1
            policy = Policy(
                id=uuid4(), org_id=org.id, name=POLICY_NAME, revision=revision, spec=spec, digest=policy_digest,
                state="published", author_id=ava.id, approver_id=rowan.id, published_at=datetime.now(UTC),
            )
            db.add(policy)
            db.flush()
            for p in packs:
                db.add(PolicyPack(org_id=org.id, policy_id=policy.id, rule_pack_id=p.id, pack_digest=p.digest))
            print(f"  + policy '{POLICY_NAME}' rev {revision} (all platforms)")

        # 3. Sites
        primary = db.execute(select(Site).where(Site.org_id == org.id).order_by(Site.created_at)).scalars().first()
        lab = db.execute(select(Site).where(Site.org_id == org.id, Site.name == "Security Lab")).scalar_one_or_none()
        if lab is None:
            lab = Site(id=uuid4(), org_id=org.id, name="Security Lab", timezone="UTC", scope={
                "allowed_cidrs": ["127.0.0.0/8"], "allowed_dns_suffixes": [], "allowed_ports": [LAB_PORT],
            })
            db.add(lab)
            db.flush()
            print("  + site 'Security Lab' (scope 127.0.0.0/8 port 2222)")

        existing = {a.name: a for a in db.execute(
            select(Asset).where(Asset.org_id == org.id, Asset.archived_at.is_(None))).scalars()}

        def add_asset(name, category, role, criticality, address, port, adapter, ident, site):
            if name in existing:
                return existing[name]
            vendor, family, version = ident
            asset = Asset(
                id=uuid4(), org_id=org.id, site_id=site.id, category=category, name=name, address=address,
                port=port, adapter_id=adapter, declared_role=role, criticality=criticality, owner_id=ava.id,
                identity={"vendor": vendor, "family": family, "version": version, "role": role, "stable_device_id": name},
                tags={"env": "lab" if site is lab else "production"},
            )
            db.add(asset)
            existing[name] = asset
            print(f"  + asset {name} ({adapter})")
            return asset

        for name, cat, role, crit, addr, port, adapter, ident, _profile in IMPORT_ASSETS:
            add_asset(name, cat, role, crit, addr, port, adapter, ident, primary)
        for name, cat, role, crit, adapter, ident in LIVE_SSH_ASSETS:
            add_asset(name, cat, role, crit, LAB_ADDRESS, LAB_PORT, adapter, ident, lab)
        if sys.platform == "win32":
            host = socket.gethostname().lower()[:60]
            add_asset(host, "windows", "workstation", "high", LAB_ADDRESS, LAB_PORT, "windows-local",
                      ("microsoft", "windows", "11"), lab)
        db.flush()

        # 4. Pin the mock device host key and bind its read-only audit credential
        if MOCK_KEY.exists():
            key = paramiko.RSAKey(filename=str(MOCK_KEY))
            fp = fingerprint(key)
            known_hosts.parent.mkdir(parents=True, exist_ok=True)
            known_hosts.touch(exist_ok=True)
            hosts = paramiko.HostKeys(str(known_hosts))
            hosts.add(f"[{LAB_ADDRESS}]:{LAB_PORT}", key.get_name(), key)
            hosts.save(str(known_hosts))
            for name, *_ in LIVE_SSH_ASSETS:
                asset = existing[name]
                has_trust = db.execute(select(AssetTrust.id).where(
                    AssetTrust.org_id == org.id, AssetTrust.asset_id == asset.id,
                    AssetTrust.revoked_at.is_(None))).first()
                if not has_trust:
                    db.add(AssetTrust(id=uuid4(), org_id=org.id, asset_id=asset.id, trust_type="ssh_host_key",
                                      fingerprint=fp, verified_by=ava.id, verified_at=datetime.now(UTC)))
                bound = db.execute(select(AssetCredential.asset_id).where(
                    AssetCredential.org_id == org.id, AssetCredential.asset_id == asset.id,
                    AssetCredential.purpose == "audit_collect")).first()
                if not bound:
                    cid = uuid4()
                    db.add(Credential(
                        id=cid, org_id=org.id, name=f"{name}-audit-{cid.hex[:8]}", kind="ssh_password",
                        encrypted_secret=seal_credential(
                            json.dumps({"username": MOCK_USER, "password": MOCK_PASSWORD}).encode(),
                            org_id=str(org.id), credential_id=str(cid), master_key_file=master_key),
                        key_version="local-v1", credential_metadata={"username": MOCK_USER}, created_by=ava.id,
                    ))
                    db.flush()
                    db.add(AssetCredential(org_id=org.id, asset_id=asset.id, credential_id=cid, purpose="audit_collect"))
            print(f"  = lab host key pinned ({fp}) and audit credentials bound")
        else:
            print("  ! data/mock_ssh_host_rsa.key missing: start tools/mock_targets.py once, then re-run")
    print("Database is in sync.")


def load(base: str) -> None:
    import httpx

    creds = json.loads((DATA / "demo-credentials.json").read_text())
    client = httpx.Client(base_url=base, timeout=60)
    r = client.post("/api/v1/auth/demo-login", json={
        "organization": ORG_SLUG, "username": "ava", "password": creds["password"]})
    if r.status_code != 200:
        raise SystemExit(f"Demo sign-in failed ({r.status_code}). Is BG_DEMO_LOGIN=true and the API restarted?")
    # The session cookie is Secure (__Host-), so pass it explicitly over local HTTP.
    headers = {"X-CSRF-Token": r.json()["csrf_token"], "Cookie": r.headers["set-cookie"].split(";", 1)[0]}

    def send(method, path, body=None):
        response = client.request(method, path, json=body, headers={**headers, "Idempotency-Key": uuid4().hex * 2})
        if response.status_code >= 400:
            raise SystemExit(f"{method} {path} -> {response.status_code}: {response.text}")
        return response.json() if response.content else None

    policies = client.get("/api/v1/policies", headers=headers).json()["items"]
    policy = max((p for p in policies if p["name"] == POLICY_NAME and p["state"] == "published"),
                 key=lambda p: p["revision"])
    assets = {a["name"]: a for a in client.get("/api/v1/assets?limit=200", headers=headers).json()["items"]}
    assessed = {row["asset_id"] for row in client.get("/api/v1/overview", headers=headers).json()["posture"]
                if row["observed_at"]}

    for name, _c, role, _cr, _a, _p, _ad, ident, profile in IMPORT_ASSETS:
        asset = assets[name]
        if asset["id"] in assessed:
            continue
        query = f"profile={profile}&family={ident[1]}" + (f"&role={role}" if role in ("router", "switch") else "")
        bundle = client.get(f"/api/v1/imports/sample?{query}", headers=headers).json()
        bundle.update({"asset_id": asset["id"], "policy_revision_id": policy["id"]})
        send("POST", "/api/v1/imports", bundle)
        print(f"  imported sample evidence for {name} ({profile})")

    live = [assets[n]["id"] for n in [*(a[0] for a in LIVE_SSH_ASSETS)] if n in assets]
    live += [a["id"] for a in assets.values() if a["adapter_id"] == "windows-local"]
    run = send("POST", "/api/v1/scans", {"asset_ids": live, "policy_revision_id": policy["id"],
                                         "reason": "Live audit of lab devices and this workstation"})
    print(f"  live scan queued for {len(live)} assets (run {run['scan_id'][:8]})")
    for _ in range(90):
        state = client.get(f"/api/v1/scans/{run['scan_id']}", headers=headers).json()
        if state["status"] in {"COMPLETED", "PARTIAL", "FAILED", "CANCELED"}:
            print(f"  live scan finished: {state['status']}")
            break
        time.sleep(1)
    else:
        print("  live scan still running; check the Assessments page")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--load", action="store_true")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    load_env()
    sync_database()
    if args.load:
        load(args.base_url)


if __name__ == "__main__":
    main()
