"""Interactive local account enrollment. Run on the trusted control-plane host."""

import argparse
import os
import re
import secrets
from datetime import UTC, datetime
from getpass import getpass
from pathlib import Path
from urllib.parse import quote, urlencode
from uuid import uuid4

from baselineguard_persistence.database import get_engine
from baselineguard_persistence.models import Organization, RoleBinding, User
from dotenv import load_dotenv
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from baselineguard_api.audit import append_audit_event
from baselineguard_api.config import get_settings
from baselineguard_api.crypto import seal
from baselineguard_api.identity import (
    encoded_totp_secret,
    hash_password,
    new_recovery_codes,
    new_totp_secret,
    verify_totp,
)
from baselineguard_api.security import Principal

ROLES = {
    "viewer",
    "analyst",
    "scan_operator",
    "auditor",
    "manual_assessor",
    "policy_author",
    "policy_approver",
    "risk_approver",
    "credential_admin",
    "platform_admin",
    "inventory_editor",
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Enroll a local user with mandatory TOTP MFA.")
    parser.add_argument("--organization", required=True, help="Organization slug")
    parser.add_argument("--name", required=True, help="Organization display name if creating it")
    parser.add_argument("--username", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument(
        "--roles", required=True, help="Explicit comma-separated organization-wide roles"
    )
    args = parser.parse_args()
    roles = set(args.roles.split(","))
    if not roles or not roles <= ROLES:
        parser.error("Unknown role. Valid roles: " + ", ".join(sorted(ROLES)))
    if not re.fullmatch(r"[a-z0-9-]{1,100}", args.organization):
        parser.error("Use a lowercase organization slug with letters, digits and hyphens")
    if not 1 <= len(args.username.strip()) <= 255 or not 1 <= len(args.email) <= 320:
        parser.error("Invalid username or email length")
    load_dotenv(".env", override=False)
    url = os.environ.get("BG_MIGRATION_DATABASE_URL")
    if not url:
        parser.error("Set BG_MIGRATION_DATABASE_URL for host-admin enrollment")
    settings = get_settings()
    password = getpass("Password (at least 14 characters): ")
    if password != getpass("Confirm password: "):
        parser.error("Passwords do not match")
    try:
        password_digest = hash_password(password, settings.password_blocklist_file)
    except ValueError as exc:
        parser.error(str(exc))
    del password
    key_path = Path(settings.master_key_file)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if not key_path.exists():
        descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(secrets.token_bytes(32))
        print(
            "Created local master key. Restrict its filesystem permissions "
            "and back it up separately."
        )
    secret = new_totp_secret()
    params = urlencode(
        {
            "secret": encoded_totp_secret(secret),
            "issuer": "BaselineGuard",
            "algorithm": "SHA1",
            "digits": "6",
            "period": "30",
        }
    )
    print("Enroll this URI in your authenticator (keep this terminal private):")
    print(f"otpauth://totp/{quote('BaselineGuard:' + args.username, safe='')}?{params}")
    step = verify_totp(
        secret,
        getpass("Authenticator code: "),
        timestamp=datetime.now(UTC).timestamp(),
        last_step=-1,
    )
    if step is None:
        parser.error("Authenticator verification failed; no account was created")
    recovery_codes, recovery_hashes = new_recovery_codes()
    with Session(get_engine(url)) as db, db.begin():
        org = db.execute(
            select(Organization).where(Organization.slug == args.organization)
        ).scalar_one_or_none()
        if org is None:
            org = Organization(id=uuid4(), slug=args.organization, name=args.name)
            db.add(org)
            db.flush()
        if org.status != "active":
            parser.error("The organization is not active")
        db.execute(text("SELECT set_config('app.org_id', :id, true)"), {"id": str(org.id)})
        username = args.username.strip().casefold()
        if db.execute(
            select(User.id).where(User.subject == username, User.auth_provider == "local")
        ).first():
            parser.error("That account already exists; enrollment never overwrites credentials")
        user_id = uuid4()
        db.add(
            User(
                id=user_id,
                org_id=org.id,
                subject=username,
                email=args.email,
                auth_provider="local",
                password_hash=password_digest,
                totp_ciphertext=seal(
                    secret,
                    binding=f"{org.id}/{user_id}/totp",
                    master_key_file=settings.master_key_file,
                ),
                last_totp_step=step,
                recovery_hashes=recovery_hashes,
            )
        )
        db.flush()
        for role in sorted(roles):
            db.add(RoleBinding(id=uuid4(), org_id=org.id, user_id=user_id, role=role))
        append_audit_event(
            db,
            Principal(user_id, org.id, frozenset(roles), frozenset()),
            action="user.enrolled_by_host_admin",
            object_type="user",
            object_id=user_id,
            details={"roles": sorted(roles)},
        )
    print("Account enrolled. Save these one-use recovery codes privately:")
    print("\n".join(recovery_codes))
    print(
        "Wait for the next authenticator code, then sign in using "
        "your organization slug and username."
    )


if __name__ == "__main__":
    main()
