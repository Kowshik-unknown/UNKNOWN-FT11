"""Seed 50 synthetic Firebase Auth/Firestore members in a new sandbox project.

Requires Application Default Credentials or GOOGLE_APPLICATION_CREDENTIALS. Run
only against a dedicated test Firebase project. The generated credentials file
is local, ignored by Git, and never served by FastAPI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Any

import firebase_admin
from firebase_admin import auth, firestore

HERE = Path(__file__).resolve().parent
ROSTER_PATH = HERE / "member_roster.json"
CREDENTIALS_PATH = HERE / "firebase_seed_credentials.json"
PBKDF2_ITERATIONS = 240_000


def password_hash(pin: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32).hex()


def write_credentials(items: list[dict[str, Any]]) -> None:
    CREDENTIALS_PATH.write_text(
        json.dumps(
            {
                "notice": "Synthetic sandbox credentials. Keep this file private, do not commit it, and rotate passwords/PINs before any real pilot.",
                "users": items,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    try:
        CREDENTIALS_PATH.chmod(0o600)
    except OSError:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Offlinerupee member accounts into a Firebase sandbox.")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Reset passwords, transfer PINs, and sandbox balances for matching existing users. Use only in a test project.",
    )
    args = parser.parse_args()

    project_id = os.environ.get("FIREBASE_PROJECT_ID") or os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not firebase_admin._apps:
        options = {"projectId": project_id} if project_id else None
        firebase_admin.initialize_app(options=options)

    db = firestore.client()
    roster = json.loads(ROSTER_PATH.read_text(encoding="utf-8"))["members"]
    credentials: list[dict[str, Any]] = []

    for profile in roster:
        email = profile["email"].lower()
        try:
            existing = auth.get_user_by_email(email)
        except auth.UserNotFoundError:
            existing = None

        if existing is not None and not args.overwrite:
            raise SystemExit(
                f"{email} already exists. Use a fresh Firebase sandbox or rerun with --overwrite "
                "(which rotates credentials and resets sandbox balances)."
            )

        password = secrets.token_urlsafe(18)
        pin = f"{secrets.randbelow(900_000) + 100_000:06d}"
        if existing is None:
            user = auth.create_user(email=email, password=password, display_name=profile["displayName"], disabled=False)
        else:
            user = auth.update_user(existing.uid, password=password, display_name=profile["displayName"], disabled=False)

        pin_salt = secrets.token_bytes(16)
        member_data = {
            "email": email,
            "displayName": profile["displayName"],
            "bankId": profile["bankId"],
            "bankName": profile["bankName"],
            "walletId": profile["walletId"],
            "balancePaise": int(profile["initialBalancePaise"]),
            "counter": 0,
            "isActive": True,
            "isSandbox": True,
            "createdAt": firestore.SERVER_TIMESTAMP,
        }
        secret_data = {
            "pinSalt": pin_salt.hex(),
            "pinHash": password_hash(pin, pin_salt),
            "pinIterations": PBKDF2_ITERATIONS,
            "pinFailures": 0,
            "pinBlockedUntil": 0,
            "updatedAt": firestore.SERVER_TIMESTAMP,
        }
        db.collection("members").document(user.uid).set(member_data)
        db.collection("memberSecrets").document(user.uid).set(secret_data)
        credentials.append(
            {
                "email": email,
                "password": password,
                "pin": pin,
                "displayName": profile["displayName"],
                "bankName": profile["bankName"],
                "walletId": profile["walletId"],
                "sandboxBalancePaise": int(profile["initialBalancePaise"]),
            }
        )
        print(f"Seeded {email} ({profile['displayName']}, {profile['bankName']})")

    write_credentials(credentials)
    print(f"Created {len(credentials)} member accounts.")
    print(f"Private one-time credentials: {CREDENTIALS_PATH}")
    print("Do not upload that file, and never use these sandbox balances for real value.")


if __name__ == "__main__":
    main()
