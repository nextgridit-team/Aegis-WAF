#!/usr/bin/env python3
"""Create deployment bootstrap secrets once; never overwrite existing material."""
import base64
import os
from pathlib import Path
import secrets

root = Path(__file__).resolve().parents[1] / "secrets"
root.mkdir(mode=0o700, exist_ok=True)
if any(root.iterdir()):
    raise SystemExit("Refusing to overwrite a nonempty secrets directory.")
root.chmod(0o700)
password = secrets.token_hex(32)
values = {
    "postgres_password": password,
    "database_url": f"postgres://aegis_waf:{password}@db:5432/aegis_waf?sslmode=disable",
    "encryption_key": base64.b64encode(secrets.token_bytes(32)).decode(),
    "bootstrap_secret": secrets.token_urlsafe(48),
}
for name, value in values.items():
    fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    with os.fdopen(fd, "w") as handle:
        handle.write(value + "\n")
    (root / name).chmod(0o444)
print("Created bootstrap files in secrets/ (directory 0700; mounted files 0444).")
print("Open http://localhost:9090 and use secrets/bootstrap_secret for first-run setup.")
