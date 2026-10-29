"""Create a local demo organization, users, site, assets, rule packs and published policy.

Development only. Uses the PostgreSQL superuser from .env (it bypasses row-level
security) and writes demo credentials to data/demo-credentials.json.

    python tools/seed_demo.py            # database objects
    python tools/seed_demo.py --load     # also drive the running API to import sample evidence
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
CREDENTIALS = DATA / "demo-credentials.json"
ORG_SLUG = "northwind"
PASSWORD = secrets.token_urlsafe(24)

ADMIN_ROLES = ["platform_admin", "analyst", "scan_operator", "auditor", "policy_author",
               "inventory_editor", "viewer", "manual_assessor"]
APPROVER_ROLES = ["risk_approver", "policy_approver", "analyst", "viewer"]

# name, category, role, criticality, address, port, adapter_id, identity, profile, variant, family
ASSETS = [
    ("web-01", "linux", "server", "critical", "10.20.1.11", 22, "linux-ssh-fixture",
     {"vendor": "canonical", "family": "ubuntu", "version": "22.04", "role": "server", "stable_device_id": "web-01"},
     "hardened", 0, "ubuntu"),
    ("db-01", "linux", "server", "critical", "10.20.2.21", 22, "linux-ssh-fixture",
     {"vendor": "canonical", "family": "ubuntu", "version": "22.04", "role": "server", "stable_device_id": "db-01"},
     "mixed", 1, "ubuntu"),
    ("win-dc-01", "windows", "domain_controller", "critical", "10.20.1.101", 5986, "windows-fixture",
     {"vendor": "microsoft", "family": "windows_server", "version": "2019", "role": "domain_controller", "stable_device_id": "win-dc-01"},
     "hardened", 0, "windows_server"),
    ("win-app-02", "windows", "member_server", "high", "10.20.1.102", 5986, "windows-fixture",
     {"vendor": "microsoft", "family": "windows_server", "version": "2019", "role": "member_server", "stable_device_id": "win-app-02"},
     "mixed", 1, "windows_server"),
    ("edge-fw-01", "firewall", "firewall", "critical", "10.20.0.1", 443, "fortigate-fixture",
     {"vendor": "fortinet", "family": "fortigate", "version": "7.4", "role": "firewall", "stable_device_id": "edge-fw-01"},
     "mixed", 0, "fortigate"),
    ("core-sw-01", "network", "switch", "critical", "10.20.0.2", 22, "cisco-iosxe-fixture",
     {"vendor": "cisco", "family": "cisco_ios_xe", "version": "17.12", "role": "switch", "stable_device_id": "core-sw-01"},
     "hardened", 0, "cisco_ios_xe"),
    ("branch-rtr-01", "network", "router", "high", "10.20.10.1", 22, "cisco-iosxe-fixture",
     {"vendor": "cisco", "family": "cisco_ios_xe", "version": "17.12", "role": "router", "stable_device_id": "branch-rtr-01"},
     "weak", 0, "cisco_ios_xe"),
]

RULE_PACK_FILES = [
    "phase1-linux.yaml",
    "windows-server-2019.yaml",
    "cisco-iosxe-hardening.yaml",
    "fortigate-fortios.yaml",
]


def load_env() -> None:
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env", override=False)


def superuser_url() -> str:
    password = os.environ["POSTGRES_SUPERUSER_PASSWORD"]
    return f"postgresql+psycopg://postgres:{password}@127.0.0.1:55432/baselineguard"


def migrate() -> None:
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=ROOT, check=True)


def ensure_key() -> Path:
    key = DATA / "keys" / "master.key"
    key.parent.mkdir(parents=True, exist_ok=True)
    if not key.exists():
        key.write_bytes(secrets.token_bytes(32))
    return key


def seed_database() -> dict:
    from baselineguard_persistence.models import (
        Asset,
        Organization,
        Policy,
        PolicyPack,
        RoleBinding,
        RulePack,
        Site,
        User,
    )
    from baselineguard_rule_engine.canonical import semantic_digest
    from baselineguard_rule_engine.packs import load_rule_pack
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session

    from baselineguard_api.crypto import seal
    from baselineguard_api.identity import encoded_totp_secret, hash_password, new_totp_secret

    key = ensure_key()
    engine = create_engine(superuser_url(), hide_parameters=True)
    creds: dict = {"organization": ORG_SLUG, "password": PASSWORD, "users": []}
    with Session(engine) as db, db.begin():
        org = db.execute(select(Organization).where(Organization.slug == ORG_SLUG)).scalar_one_or_none()
        if org is not None and CREDENTIALS.exists():
            print(f"Organization '{ORG_SLUG}' already seeded.")
            return json.loads(CREDENTIALS.read_text())
        if org is not None:
            raise SystemExit("Organization exists but data/demo-credentials.json is missing; "
                             "reset the database volume or remove the organization first.")
        org = Organization(id=uuid4(), slug=ORG_SLUG, name="Northwind Enterprise")
        db.add(org)
        db.flush()
        users: dict[str, User] = {}
        for username, email, roles in (
            ("ava", "ava.chen@northwind.example", ADMIN_ROLES),
            ("rowan", "rowan.diaz@northwind.example", APPROVER_ROLES),
        ):
            secret = new_totp_secret()
            user_id = uuid4()
            user = User(
                id=user_id, org_id=org.id, subject=username, email=email, auth_provider="local",
                password_hash=hash_password(PASSWORD, None),
                totp_ciphertext=seal(secret, binding=f"{org.id}/{user_id}/totp",
                                     master_key_file=str(key)),
                last_totp_step=-1, recovery_hashes=[],
            )
            db.add(user)
            db.flush()
            for role in roles:
                db.add(RoleBinding(id=uuid4(), org_id=org.id, user_id=user_id, role=role))
            users[username] = user
            creds["users"].append({"username": username, "email": email, "roles": roles,
                                   "totp_secret_base32": encoded_totp_secret(secret)})

        site = Site(
            id=uuid4(),
            org_id=org.id,
            name="Primary Datacenter",
            timezone="UTC",
            scope={
                "allowed_cidrs": ["10.20.0.0/16"],
                "allowed_dns_suffixes": [],
                "allowed_ports": [22, 443, 5986],
            },
        )
        db.add(site)
        db.flush()

        for name, category, role, criticality, address, port, adapter_id, identity, _prof, _var, _fam in ASSETS:
            db.add(Asset(
                id=uuid4(), org_id=org.id, site_id=site.id, category=category, name=name,
                address=address, port=port, adapter_id=adapter_id, declared_role=role,
                identity=identity, criticality=criticality, owner_id=users["ava"].id,
                tags={"env": "production"},
            ))

        # Seed all 4 rule packs
        created_packs: list[RulePack] = []
        for pack_file in RULE_PACK_FILES:
            pack_path = ROOT / "content" / "original" / pack_file
            if not pack_path.exists():
                continue
            manifest = load_rule_pack(pack_path.read_bytes())
            pack = RulePack(
                id=uuid4(),
                org_id=org.id,
                pack_key=manifest["pack_id"],
                version=manifest["version"],
                digest=semantic_digest(manifest),
                manifest=manifest,
                rights_metadata={
                    "publisher": manifest["publisher"],
                    "license": manifest["license"],
                    "rights_reference": manifest.get("rights_reference", ""),
                },
                state="approved",
            )
            db.add(pack)
            created_packs.append(pack)
        db.flush()

        spec = {"schema_version": "1.0", "site_ids": [], "overrides": {}, "exclusions": {}}
        policy = Policy(
            id=uuid4(),
            org_id=org.id,
            name="Enterprise Hardening Baseline (Multi-Platform)",
            revision=1,
            spec=spec,
            digest=semantic_digest({"spec": spec, "packs": [p.digest for p in created_packs]}),
            state="published",
            author_id=users["ava"].id,
            approver_id=users["rowan"].id,
            published_at=datetime.now(UTC),
        )
        db.add(policy)
        db.flush()

        for p in created_packs:
            db.add(PolicyPack(org_id=org.id, policy_id=policy.id, rule_pack_id=p.id, pack_digest=p.digest))

        creds["policy_id"] = str(policy.id)
    DATA.mkdir(exist_ok=True)
    CREDENTIALS.write_text(json.dumps(creds, indent=2))
    return creds


def write_worker_env() -> None:
    """Append dev-only worker settings to .env if absent."""
    env = ROOT / ".env"
    text = env.read_text()
    additions = []
    if "BG_EMBEDDED_WORKERS" not in text:
        additions.append("BG_EMBEDDED_WORKERS=true")
    if "BG_WORKER_DATABASE_URL" not in text:
        additions.append(f"BG_WORKER_DATABASE_URL={superuser_url()}")
    if additions:
        env.write_text(text.rstrip("\n") + "\n" + "\n".join(additions) + "\n")
        print("Added development worker settings to .env")


# ------------------------------------------------------------------ API loading


class ApiSession:
    def __init__(self, base: str, creds: dict, username: str):
        import httpx

        from baselineguard_api.identity import totp_code

        self.client = httpx.Client(base_url=base, timeout=30)
        user = next(u for u in creds["users"] if u["username"] == username)
        raw = user["totp_secret_base32"]
        secret = base64.b32decode(raw + "=" * (-len(raw) % 8))
        login = self.client.post("/api/v1/auth/login", json={
            "organization": creds["organization"], "username": username,
            "password": creds["password"]})
        login.raise_for_status()
        challenge = login.json()["challenge"]
        verify = None
        for offset in (0, 1):
            step = int(time.time() // 30) + offset
            verify = self.client.post("/api/v1/auth/mfa/verify",
                                      json={"challenge": challenge, "code": totp_code(secret, step)})
            if verify.status_code == 200:
                break
        assert verify is not None
        verify.raise_for_status()
        cookie = verify.headers["set-cookie"].split(";", 1)[0]
        self.headers = {"Cookie": cookie, "X-CSRF-Token": verify.json()["csrf_token"]}

    def get(self, path: str):
        response = self.client.get(path, headers=self.headers)
        response.raise_for_status()
        return response.json()

    def send(self, method: str, path: str, body=None):
        headers = {**self.headers, "Idempotency-Key": uuid4().hex + uuid4().hex}
        response = self.client.request(method, path, json=body, headers=headers)
        if response.status_code >= 400:
            raise SystemExit(f"{method} {path} -> {response.status_code}: {response.text}")
        return response.json() if response.content else None


def load_demo_data(base: str, creds: dict) -> None:
    ava = ApiSession(base, creds, "ava")
    if ava.get("/api/v1/assessments")["items"]:
        print("Assessments already exist; skipping sample import.")
        return
    assets = {a["name"]: a for a in ava.get("/api/v1/assets?limit=50")["items"]}
    for name, _cat, _role, _crit, _addr, _port, _adapt, _ident, profile, variant, family in ASSETS:
        bundle = ava.get(f"/api/v1/imports/sample?profile={profile}&variant={variant}&family={family}")
        bundle.update({"asset_id": assets[name]["id"], "policy_revision_id": creds["policy_id"]})
        ava.send("POST", "/api/v1/imports", bundle)
        print(f"  imported {name} ({family} - {profile})")
    for _ in range(60):
        runs = ava.get("/api/v1/assessments")["items"]
        if runs and all(r["status"] in {"COMPLETED", "PARTIAL"} for r in runs):
            break
        time.sleep(1)
    else:
        raise SystemExit("Workers did not finish. Is the API running with BG_EMBEDDED_WORKERS=true?")
    findings = ava.get("/api/v1/findings?state=OPEN&limit=200")["items"]
    users = {u["email"]: u["id"] for u in ava.get("/api/v1/users")["items"]}
    ava_id, rowan_id = users["ava.chen@northwind.example"], users["rowan.diaz@northwind.example"]
    for index, finding in enumerate(findings[:12]):
        ava.send("PATCH", f"/api/v1/findings/{finding['id']}", {
            "owner_id": ava_id if index % 2 == 0 else rowan_id,
            "due_at": (datetime.now(UTC) + timedelta(days=7 + index * 3)).isoformat()})
    target = next((f for f in findings if "ip_forward" in f["control_key"] or "pwd" in f["control_key"]), None)
    if target:
        exc = ava.send("POST", "/api/v1/exceptions", {
            "asset_id": target["asset_id"], "control_key": target["control_key"],
            "reason": "Host requires legacy configuration pending enterprise controller migration.",
            "compensating_controls": "Perimeter network access control list limits access to jump hosts.",
            "expires_at": (datetime.now(UTC) + timedelta(days=60)).isoformat()})
        ApiSession(base, creds, "rowan").send("POST", f"/api/v1/exceptions/{exc['id']}/approve")
        print("  created and approved a sample exception")
    print("Multi-platform enterprise sample evidence loaded.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--load", action="store_true", help="import sample evidence via the running API")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    load_env()
    migrate()
    creds = seed_database()
    write_worker_env()
    print(f"\nOrganization: {ORG_SLUG}")
    print("Users: ava (administrator), rowan (risk approver)")
    print("Demo password is stored in the ignored local file data/demo-credentials.json.")
    print("Authenticator codes: python tools/totp.py")
    if args.load:
        load_demo_data(args.base_url, creds)


if __name__ == "__main__":
    main()
