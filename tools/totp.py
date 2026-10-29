"""Print the current demo authenticator codes (development only)."""

import base64
import json
import time
from pathlib import Path

from baselineguard_api.identity import totp_code

creds = json.loads(
    (Path(__file__).resolve().parents[1] / "data" / "demo-credentials.json").read_text()
)
step = int(time.time() // 30)
remaining = 30 - int(time.time() % 30)
for user in creds["users"]:
    raw = user["totp_secret_base32"]
    secret = base64.b32decode(raw + "=" * (-len(raw) % 8))
    print(f"{user['username']:8s} {totp_code(secret, step)}   (valid ~{remaining}s)")
