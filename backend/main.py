"""Offlinerupee local gateway for a fixed, pre-enrolled wallet roster.

Local mode is a sandbox: it seeds 50 synthetic users once, stores password/PIN
verifiers (never plaintext), and writes one-time local credentials to an ignored,
non-served file. Production Firebase transfers are implemented in ../functions.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import Cookie, FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

ROOT_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = ROOT_DIR / "frontend"
BANK_CATALOG_PATH = Path(__file__).with_name("bank_catalog.json")
ROSTER_PATH = Path(__file__).with_name("member_roster.json")
DB_PATH = Path(os.environ.get("OFFLINERUPEE_DB_PATH", Path(__file__).with_name("offlinerupee.sqlite3")))
LOCAL_CREDENTIALS_PATH = Path(os.environ.get("OFFLINERUPEE_LOCAL_CREDENTIALS_PATH", Path(__file__).with_name("local_seed_credentials.json")))
SESSION_COOKIE = "offlinerupee_session"
SESSION_TTL_SECONDS = 60 * 60 * 12
PBKDF2_ITERATIONS = 240_000
MAX_TRANSFER_PAISE = 2_500_000  # ₹25,000 per transfer in this prototype.

# Public browser HMAC key only for the original offline-settlement exercise.
# For real value, use a key controlled by a smartcard/secure element instead.
PROTOTYPE_HMAC_KEY = b"offlinerupee-prototype-only-key-v1"
_db_lock = threading.RLock()

_BANK_CATALOG: dict[str, Any] = json.loads(BANK_CATALOG_PATH.read_text(encoding="utf-8"))
_BANK_CATEGORIES = {item["id"]: item for item in _BANK_CATALOG["categories"]}
_ROSTER: dict[str, Any] = json.loads(ROSTER_PATH.read_text(encoding="utf-8"))


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-") or "bank"


BANKS: list[dict[str, str]] = [
    {
        "id": f"{bank['category']}:{_slug(bank['name'])}",
        "name": bank["name"],
        "category": bank["category"],
        "categoryName": _BANK_CATEGORIES[bank["category"]]["name"],
    }
    for bank in _BANK_CATALOG["banks"]
]
BANKS_BY_ID = {bank["id"]: bank for bank in BANKS}
BANKS_BY_NAME = {bank["name"].casefold(): bank for bank in BANKS}


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)


class TransferRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    recipientId: str = Field(min_length=1, max_length=80)
    amountPaise: int = Field(gt=0, le=MAX_TRANSFER_PAISE, strict=True)
    pin: str = Field(pattern=r"^\d{6}$")
    idempotencyKey: str = Field(min_length=16, max_length=128)


class OfflineTransaction(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    cardId: str = Field(min_length=1, max_length=100)
    merchantId: str = Field(min_length=1, max_length=120)
    # amount/newBalance are paise integers; the field names remain concise in the signed payload.
    amount: int = Field(gt=0, strict=True)
    newBalance: int = Field(ge=0, strict=True)
    counter: int = Field(gt=0, strict=True)
    payload: str = Field(min_length=1, max_length=2_000)
    signature: str = Field(min_length=1, max_length=256)


app = FastAPI(
    title="Offlinerupee Gateway",
    description="Local sandbox for pre-enrolled member sign-in, peer transfers, and offline counter settlement.",
    version="0.3.0",
)


def connect_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _derive_hash(value: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32)


def _write_local_credentials(credentials: list[dict[str, Any]]) -> None:
    LOCAL_CREDENTIALS_PATH.write_text(
        json.dumps(
            {
                "notice": "Synthetic local-sandbox credentials. This file is not served by FastAPI and is git-ignored. Rotate/delete it before any shared deployment.",
                "users": credentials,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    try:
        LOCAL_CREDENTIALS_PATH.chmod(0o600)
    except OSError:
        pass


def initialize_database() -> None:
    """Create tables and seed the 50 local-only accounts on a fresh database."""
    with _db_lock:
        connection = connect_db()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS members (
                    member_id TEXT PRIMARY KEY,
                    wallet_id TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    display_name TEXT NOT NULL,
                    bank_id TEXT NOT NULL,
                    password_salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    pin_salt BLOB NOT NULL,
                    pin_hash BLOB NOT NULL,
                    balance_paise INTEGER NOT NULL CHECK (balance_paise >= 0),
                    counter INTEGER NOT NULL DEFAULT 0 CHECK (counter >= 0),
                    active INTEGER NOT NULL DEFAULT 1,
                    pin_failures INTEGER NOT NULL DEFAULT 0,
                    pin_blocked_until INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS local_sessions (
                    token_hash TEXT PRIMARY KEY,
                    member_id TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY (member_id) REFERENCES members(member_id)
                );

                CREATE TABLE IF NOT EXISTS transfers (
                    transfer_id TEXT PRIMARY KEY,
                    sender_id TEXT NOT NULL,
                    recipient_id TEXT NOT NULL,
                    amount_paise INTEGER NOT NULL CHECK (amount_paise > 0),
                    idempotency_key TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    UNIQUE (sender_id, idempotency_key),
                    FOREIGN KEY (sender_id) REFERENCES members(member_id),
                    FOREIGN KEY (recipient_id) REFERENCES members(member_id)
                );

                CREATE TABLE IF NOT EXISTS ledger_entries (
                    entry_id TEXT PRIMARY KEY,
                    transfer_id TEXT NOT NULL,
                    member_id TEXT NOT NULL,
                    delta_paise INTEGER NOT NULL,
                    balance_after_paise INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY (transfer_id) REFERENCES transfers(transfer_id),
                    FOREIGN KEY (member_id) REFERENCES members(member_id)
                );

                CREATE TABLE IF NOT EXISTS offline_settlements (
                    receipt_id TEXT PRIMARY KEY,
                    member_id TEXT NOT NULL,
                    wallet_id TEXT NOT NULL,
                    counter INTEGER NOT NULL,
                    merchant_id TEXT NOT NULL,
                    amount_paise INTEGER NOT NULL,
                    new_balance_paise INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    settled_at INTEGER NOT NULL,
                    UNIQUE (member_id, counter),
                    FOREIGN KEY (member_id) REFERENCES members(member_id)
                );
                """
            )

            # Remove abandoned prototype card tables from earlier iterations; the current
            # wallet balance/counter live with the enrolled member row.
            connection.execute("DROP TABLE IF EXISTS settled_transactions")
            connection.execute("DROP TABLE IF EXISTS card_state")

            existing = connection.execute("SELECT COUNT(*) AS count FROM members").fetchone()["count"]
            if existing == 0:
                generated: list[dict[str, Any]] = []
                now = int(time.time())
                for profile in _ROSTER["members"]:
                    bank = BANKS_BY_ID.get(profile["bankId"])
                    if bank is None:
                        bank = BANKS_BY_NAME.get(profile["bankName"].casefold())
                    if bank is None:
                        raise RuntimeError(f"Unknown bank in member roster: {profile['bankName']}")

                    password = secrets.token_urlsafe(15)
                    pin = f"{secrets.randbelow(900_000) + 100_000:06d}"
                    password_salt = secrets.token_bytes(16)
                    pin_salt = secrets.token_bytes(16)
                    connection.execute(
                        """
                        INSERT INTO members (
                            member_id, wallet_id, email, display_name, bank_id,
                            password_salt, password_hash, pin_salt, pin_hash,
                            balance_paise, counter, active, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1, ?)
                        """,
                        (
                            profile["memberId"],
                            profile["walletId"],
                            profile["email"].lower(),
                            profile["displayName"],
                            bank["id"],
                            password_salt,
                            _derive_hash(password, password_salt),
                            pin_salt,
                            _derive_hash(pin, pin_salt),
                            int(profile["initialBalancePaise"]),
                            now,
                        ),
                    )
                    generated.append(
                        {
                            "memberId": profile["memberId"],
                            "email": profile["email"],
                            "password": password,
                            "pin": pin,
                            "displayName": profile["displayName"],
                            "bankName": bank["name"],
                            "walletId": profile["walletId"],
                            "sandboxBalancePaise": int(profile["initialBalancePaise"]),
                        }
                    )
                _write_local_credentials(generated)
            connection.commit()
        finally:
            connection.close()


def _member_response(row: sqlite3.Row) -> dict[str, Any]:
    bank = BANKS_BY_ID.get(row["bank_id"])
    return {
        "memberId": row["member_id"],
        "walletId": row["wallet_id"],
        "email": row["email"],
        "displayName": row["display_name"],
        "bankId": row["bank_id"],
        "bankName": bank["name"] if bank else "Bank unavailable",
        "balancePaise": row["balance_paise"],
        "counter": row["counter"],
        "active": bool(row["active"]),
    }


def _find_member_by_session(connection: sqlite3.Connection, raw_token: str | None) -> sqlite3.Row:
    if not raw_token:
        raise HTTPException(status_code=401, detail="Sign in with an existing member account.")
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    row = connection.execute(
        """
        SELECT m.* FROM local_sessions s
        JOIN members m ON m.member_id = s.member_id
        WHERE s.token_hash = ? AND s.expires_at > ? AND m.active = 1
        """,
        (token_hash, int(time.time())),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Session expired or member account is unavailable.")
    return row


def canonical_payload(transaction: OfflineTransaction) -> str:
    fields = {
        "cardId": transaction.cardId,
        "merchantId": transaction.merchantId,
        "amount": transaction.amount,
        "newBalance": transaction.newBalance,
        "counter": transaction.counter,
    }
    return json.dumps(fields, ensure_ascii=False, separators=(",", ":"))


def sign_payload(payload: str) -> str:
    return hmac.new(PROTOTYPE_HMAC_KEY, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_transaction_signature(transaction: OfflineTransaction) -> bool:
    expected = canonical_payload(transaction)
    if not hmac.compare_digest(transaction.payload, expected):
        return False
    if not re.fullmatch(r"[0-9a-f]{64}", transaction.signature):
        return False
    return hmac.compare_digest(sign_payload(expected), transaction.signature)


initialize_database()


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "mode": "local-sandbox",
        "service": "offlinerupee-gateway",
        "eligibleMembers": len(_ROSTER["members"]),
    }


@app.get("/api/roster-summary")
def roster_summary() -> dict[str, int]:
    return {"memberCount": len(_ROSTER["members"])}


@app.get("/api/banks")
def get_banks() -> dict[str, Any]:
    return {
        "checkedOn": _BANK_CATALOG["checkedOn"],
        "sourceNote": _BANK_CATALOG["sourceNote"],
        "categories": _BANK_CATALOG["categories"],
        "banks": BANKS,
    }


@app.post("/api/auth/login")
def login(request: LoginRequest, response: Response, http_request: Request) -> dict[str, Any]:
    email = request.email.strip().lower()
    with _db_lock:
        connection = connect_db()
        try:
            member = connection.execute("SELECT * FROM members WHERE email = ?", (email,)).fetchone()
            # Run a dummy KDF on unknown addresses so the error path is less distinguishable.
            if member is None:
                _derive_hash(request.password, b"offlinerupee-dummy-salt")
                raise HTTPException(status_code=401, detail="No bank account was found for these credentials.")
            computed = _derive_hash(request.password, member["password_salt"])
            if not hmac.compare_digest(computed, member["password_hash"]):
                raise HTTPException(status_code=401, detail="No bank account was found for these credentials.")

            raw_token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
            now = int(time.time())
            connection.execute(
                "INSERT INTO local_sessions (token_hash, member_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
                (token_hash, member["member_id"], now + SESSION_TTL_SECONDS, now),
            )
            connection.commit()
            forwarded_proto = http_request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower()
            secure_cookie = http_request.url.scheme == "https" or forwarded_proto == "https"
            response.set_cookie(
                SESSION_COOKIE,
                raw_token,
                max_age=SESSION_TTL_SECONDS,
                httponly=True,
                secure=secure_cookie,
                samesite="lax",
                path="/",
            )
            return _member_response(member)
        finally:
            connection.close()


@app.post("/api/auth/logout")
def logout(response: Response, raw_token: str | None = Cookie(default=None, alias=SESSION_COOKIE)) -> dict[str, str]:
    if raw_token:
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        with _db_lock:
            connection = connect_db()
            try:
                connection.execute("DELETE FROM local_sessions WHERE token_hash = ?", (token_hash,))
                connection.commit()
            finally:
                connection.close()
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, samesite="lax")
    return {"status": "signed-out"}


@app.get("/api/me")
def get_me(raw_token: str | None = Cookie(default=None, alias=SESSION_COOKIE)) -> dict[str, Any]:
    with _db_lock:
        connection = connect_db()
        try:
            member = _find_member_by_session(connection, raw_token)
            return _member_response(member)
        finally:
            connection.close()


@app.get("/api/members")
def list_members(raw_token: str | None = Cookie(default=None, alias=SESSION_COOKIE)) -> dict[str, Any]:
    with _db_lock:
        connection = connect_db()
        try:
            current = _find_member_by_session(connection, raw_token)
            rows = connection.execute(
                "SELECT member_id, display_name, bank_id FROM members WHERE active = 1 ORDER BY display_name COLLATE NOCASE",
            ).fetchall()
            recipients = []
            for row in rows:
                bank = BANKS_BY_ID.get(row["bank_id"])
                recipients.append(
                    {
                        "memberId": row["member_id"],
                        "displayName": row["display_name"],
                        "bankName": bank["name"] if bank else "Bank unavailable",
                        "isSelf": row["member_id"] == current["member_id"],
                    }
                )
            return {"recipients": recipients}
        finally:
            connection.close()


@app.get("/api/transfers")
def list_transfers(raw_token: str | None = Cookie(default=None, alias=SESSION_COOKIE)) -> dict[str, Any]:
    with _db_lock:
        connection = connect_db()
        try:
            member = _find_member_by_session(connection, raw_token)
            rows = connection.execute(
                """
                SELECT t.transfer_id, t.sender_id, t.recipient_id, t.amount_paise, t.created_at,
                       s.display_name AS sender_name, s.bank_id AS sender_bank_id,
                       r.display_name AS recipient_name, r.bank_id AS recipient_bank_id
                FROM transfers t
                JOIN members s ON s.member_id = t.sender_id
                JOIN members r ON r.member_id = t.recipient_id
                WHERE t.sender_id = ? OR t.recipient_id = ?
                ORDER BY t.created_at DESC LIMIT 25
                """,
                (member["member_id"], member["member_id"]),
            ).fetchall()
            transfers = []
            for row in rows:
                as_sender = row["sender_id"] == member["member_id"]
                bank_id = row["recipient_bank_id"] if as_sender else row["sender_bank_id"]
                bank = BANKS_BY_ID.get(bank_id)
                transfers.append(
                    {
                        "transferId": row["transfer_id"],
                        "direction": "sent" if as_sender else "received",
                        "counterpartyName": row["recipient_name"] if as_sender else row["sender_name"],
                        "counterpartyBankName": bank["name"] if bank else "Bank unavailable",
                        "amountPaise": row["amount_paise"],
                        "createdAt": row["created_at"],
                    }
                )
            return {"transfers": transfers}
        finally:
            connection.close()


@app.post("/api/transfers")
def send_transfer(
    request: TransferRequest,
    raw_token: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict[str, Any]:
    result: dict[str, Any] | None = None
    error: tuple[int, str] | None = None
    with _db_lock:
        connection = connect_db()
        try:
            connection.execute("BEGIN IMMEDIATE")
            sender = _find_member_by_session(connection, raw_token)
            existing = connection.execute(
                "SELECT * FROM transfers WHERE sender_id = ? AND idempotency_key = ?",
                (sender["member_id"], request.idempotencyKey),
            ).fetchone()
            if existing:
                if existing["recipient_id"] != request.recipientId or existing["amount_paise"] != request.amountPaise:
                    error = (409, "This transfer request key was already used for different details.")
                else:
                    sender_now = connection.execute("SELECT balance_paise FROM members WHERE member_id = ?", (sender["member_id"],)).fetchone()
                    recipient = connection.execute("SELECT display_name, bank_id FROM members WHERE member_id = ?", (existing["recipient_id"],)).fetchone()
                    bank = BANKS_BY_ID.get(recipient["bank_id"]) if recipient else None
                    result = {
                        "transferId": existing["transfer_id"],
                        "recipientName": recipient["display_name"] if recipient else "Recipient",
                        "recipientBankName": bank["name"] if bank else "Bank unavailable",
                        "amountPaise": existing["amount_paise"],
                        "senderBalancePaise": sender_now["balance_paise"],
                        "status": "settled",
                        "idempotentReplay": True,
                    }
            else:
                recipient = connection.execute(
                    "SELECT * FROM members WHERE member_id = ? AND active = 1",
                    (request.recipientId,),
                ).fetchone()
                if recipient is None:
                    error = (404, "Recipient account was not found.")
                elif recipient["member_id"] == sender["member_id"]:
                    error = (400, "You cannot transfer funds to your own account.")
                else:
                    now = int(time.time())
                    if sender["pin_blocked_until"] > now:
                        error = (429, "Transfer PIN locked temporarily after failed attempts. Try again later.")
                    else:
                        pin_hash = _derive_hash(request.pin, sender["pin_salt"])
                        if not hmac.compare_digest(pin_hash, sender["pin_hash"]):
                            failures = int(sender["pin_failures"]) + 1
                            blocked_until = now + 900 if failures >= 5 else 0
                            connection.execute(
                                "UPDATE members SET pin_failures = ?, pin_blocked_until = ? WHERE member_id = ?",
                                (failures, blocked_until, sender["member_id"]),
                            )
                            error = (401, "The six-digit transfer PIN is incorrect.")
                        elif sender["balance_paise"] < request.amountPaise:
                            error = (400, "Insufficient wallet balance.")
                        else:
                            sender_balance = int(sender["balance_paise"]) - request.amountPaise
                            recipient_balance = int(recipient["balance_paise"]) + request.amountPaise
                            transfer_id = f"TR-{uuid.uuid4().hex[:16].upper()}"
                            connection.execute(
                                "UPDATE members SET balance_paise = ?, pin_failures = 0, pin_blocked_until = 0 WHERE member_id = ?",
                                (sender_balance, sender["member_id"]),
                            )
                            connection.execute(
                                "UPDATE members SET balance_paise = ? WHERE member_id = ?",
                                (recipient_balance, recipient["member_id"]),
                            )
                            connection.execute(
                                "INSERT INTO transfers (transfer_id, sender_id, recipient_id, amount_paise, idempotency_key, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                                (transfer_id, sender["member_id"], recipient["member_id"], request.amountPaise, request.idempotencyKey, now),
                            )
                            connection.execute(
                                "INSERT INTO ledger_entries (entry_id, transfer_id, member_id, delta_paise, balance_after_paise, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                                (uuid.uuid4().hex, transfer_id, sender["member_id"], -request.amountPaise, sender_balance, now),
                            )
                            connection.execute(
                                "INSERT INTO ledger_entries (entry_id, transfer_id, member_id, delta_paise, balance_after_paise, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                                (uuid.uuid4().hex, transfer_id, recipient["member_id"], request.amountPaise, recipient_balance, now),
                            )
                            bank = BANKS_BY_ID.get(recipient["bank_id"])
                            result = {
                                "transferId": transfer_id,
                                "recipientName": recipient["display_name"],
                                "recipientBankName": bank["name"] if bank else "Bank unavailable",
                                "amountPaise": request.amountPaise,
                                "senderBalancePaise": sender_balance,
                                "status": "settled",
                                "idempotentReplay": False,
                            }
            connection.commit()
        except HTTPException:
            connection.rollback()
            raise
        except sqlite3.IntegrityError:
            connection.rollback()
            raise HTTPException(status_code=409, detail="This transfer request could not be applied twice.")
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    if error:
        raise HTTPException(status_code=error[0], detail=error[1])
    if result is None:
        raise HTTPException(status_code=500, detail="Transfer was not completed.")
    return result


@app.post("/api/sync-batch")
def sync_batch(
    transactions: list[OfflineTransaction],
    raw_token: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict[str, Any]:
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    wallet_ids = list(dict.fromkeys(item.cardId for item in transactions))

    with _db_lock:
        connection = connect_db()
        try:
            connection.execute("BEGIN IMMEDIATE")
            _find_member_by_session(connection, raw_token)
            for item in transactions:
                member = connection.execute(
                    "SELECT member_id, wallet_id, balance_paise, counter FROM members WHERE wallet_id = ? AND active = 1",
                    (item.cardId,),
                ).fetchone()
                if member is None:
                    rejected.append({"cardId": item.cardId, "counter": item.counter, "signature": item.signature, "reason": "Unknown wallet identifier."})
                    continue
                last_counter = int(member["counter"])
                balance_paise = int(member["balance_paise"])
                if item.counter <= last_counter:
                    rejected.append({"cardId": item.cardId, "counter": item.counter, "signature": item.signature, "reason": "Double-Spend Fraud Attack! Counter is not newer than the last settled counter."})
                    continue
                if not verify_transaction_signature(item):
                    rejected.append({"cardId": item.cardId, "counter": item.counter, "signature": item.signature, "reason": "Invalid payload or HMAC-SHA-256 signature."})
                    continue
                if item.counter != last_counter + 1:
                    rejected.append({"cardId": item.cardId, "counter": item.counter, "signature": item.signature, "reason": f"Counter gap: expected {last_counter + 1}, received {item.counter}."})
                    continue
                expected_balance = balance_paise - item.amount
                if expected_balance < 0 or item.newBalance != expected_balance:
                    rejected.append({"cardId": item.cardId, "counter": item.counter, "signature": item.signature, "reason": "Balance chain mismatch."})
                    continue

                receipt_id = f"SET-{uuid.uuid4().hex[:12].upper()}"
                now = int(time.time())
                connection.execute(
                    "INSERT INTO offline_settlements (receipt_id, member_id, wallet_id, counter, merchant_id, amount_paise, new_balance_paise, payload, signature, settled_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (receipt_id, member["member_id"], item.cardId, item.counter, item.merchantId, item.amount, item.newBalance, item.payload, item.signature, now),
                )
                connection.execute(
                    "UPDATE members SET balance_paise = ?, counter = ? WHERE member_id = ?",
                    (item.newBalance, item.counter, member["member_id"]),
                )
                accepted.append({"cardId": item.cardId, "counter": item.counter, "signature": item.signature, "newBalance": item.newBalance, "settlementId": receipt_id})

            states = []
            for wallet_id in wallet_ids:
                row = connection.execute("SELECT wallet_id, balance_paise, counter FROM members WHERE wallet_id = ?", (wallet_id,)).fetchone()
                if row:
                    states.append({"cardId": row["wallet_id"], "lastCounter": row["counter"], "balance": row["balance_paise"]})
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    return {
        "status": "settled" if not rejected else "partial",
        "settledCount": len(accepted),
        "rejectedCount": len(rejected),
        "accepted": accepted,
        "rejected": rejected,
        "cardStates": states,
    }


@app.get("/api/bank-catalog")
def get_bank_catalog() -> dict[str, Any]:
    """Public name-only bank catalogue; no member credentials or account numbers."""
    return {
        "checkedOn": _BANK_CATALOG["checkedOn"],
        "categories": _BANK_CATALOG["categories"],
        "banks": BANKS,
    }


# Same-origin serving keeps the browser on relative /api URLs in local and preview use.
app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
