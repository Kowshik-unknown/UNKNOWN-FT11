"""Tests for the enrolled roster, PIN-confirmed transfers, and offline replay guard."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path

_TEST_DIR = tempfile.TemporaryDirectory(prefix="offlinerupee-test-")
os.environ["OFFLINERUPEE_DB_PATH"] = str(Path(_TEST_DIR.name) / "test.sqlite3")
os.environ["OFFLINERUPEE_LOCAL_CREDENTIALS_PATH"] = str(Path(_TEST_DIR.name) / "local-credentials.json")

from backend.main import (  # noqa: E402
    BANKS,
    OfflineTransaction,
    TransferRequest,
    connect_db,
    list_members,
    send_transfer,
    sign_payload,
    sync_batch,
)

TEST_MEMBER_ID = "member-050"
TEST_BALANCE_PAISE = 20_000_000


def signed_transaction(wallet_id: str, counter: int, amount: int, balance_before: int) -> OfflineTransaction:
    fields = {
        "cardId": wallet_id,
        "merchantId": "TEST-MERCHANT",
        "amount": amount,
        "newBalance": balance_before - amount,
        "counter": counter,
    }
    payload = json.dumps(fields, ensure_ascii=False, separators=(",", ":"))
    return OfflineTransaction(**fields, payload=payload, signature=sign_payload(payload))


def create_session(member_id: str) -> str:
    raw_token = f"test-session-{uuid.uuid4().hex}"
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    connection = connect_db()
    try:
        connection.execute(
            "INSERT INTO local_sessions (token_hash, member_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
            (token_hash, member_id, 4_102_444_800, 1_700_000_000),
        )
        connection.commit()
    finally:
        connection.close()
    return raw_token


class OfflinerupeeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.credentials = json.loads(Path(os.environ["OFFLINERUPEE_LOCAL_CREDENTIALS_PATH"]).read_text(encoding="utf-8"))["users"]
        cls.credentials_by_email = {item["email"]: item for item in cls.credentials}

    def setUp(self) -> None:
        self.wallet_id = "OW-MEMBER-050"
        connection = connect_db()
        try:
            connection.execute(
                "UPDATE members SET balance_paise = ?, counter = 0 WHERE member_id = ?",
                (TEST_BALANCE_PAISE, TEST_MEMBER_ID),
            )
            connection.execute("DELETE FROM offline_settlements WHERE member_id = ?", (TEST_MEMBER_ID,))
            connection.commit()
        finally:
            connection.close()
        self.session = create_session(TEST_MEMBER_ID)

    def test_catalog_and_roster_contain_50_public_names_without_credentials(self) -> None:
        self.assertEqual(len(BANKS), 123)
        connection = connect_db()
        try:
            member_count = connection.execute("SELECT COUNT(*) FROM members").fetchone()[0]
            recipients = list_members(self.session)["recipients"]
        finally:
            connection.close()
        self.assertEqual(member_count, 50)
        self.assertEqual(len(recipients), 50)
        self.assertTrue(any(item["isSelf"] for item in recipients))
        self.assertTrue(all("accountNumber" not in item and "email" not in item for item in recipients))

        roster = json.loads(Path("backend/member_roster.json").read_text(encoding="utf-8"))
        self.assertEqual(len(roster["members"]), 50)
        for member in roster["members"]:
            self.assertNotIn("password", member)
            self.assertNotIn("pin", member)
            self.assertNotIn("cvv", member)

    def test_valid_signed_offline_payment_settles_and_replay_is_flagged(self) -> None:
        transaction = signed_transaction(self.wallet_id, 1, 10_000, TEST_BALANCE_PAISE)
        first = sync_batch([transaction], self.session)
        self.assertEqual(first["settledCount"], 1)
        self.assertEqual(first["cardStates"][0]["lastCounter"], 1)
        self.assertEqual(first["cardStates"][0]["balance"], TEST_BALANCE_PAISE - 10_000)

        replay = sync_batch([transaction], self.session)
        self.assertEqual(replay["settledCount"], 0)
        self.assertIn("Double-Spend Fraud Attack!", replay["rejected"][0]["reason"])

    def test_counter_must_be_exactly_next(self) -> None:
        gap = signed_transaction(self.wallet_id, 2, 10_000, TEST_BALANCE_PAISE)
        result = sync_batch([gap], self.session)
        self.assertEqual(result["settledCount"], 0)
        self.assertIn("Counter gap", result["rejected"][0]["reason"])
        self.assertEqual(result["cardStates"][0]["lastCounter"], 0)

    def test_invalid_hmac_is_rejected_without_advancing_state(self) -> None:
        transaction = signed_transaction(self.wallet_id, 1, 10_000, TEST_BALANCE_PAISE)
        transaction.signature = "0" * 64
        result = sync_batch([transaction], self.session)
        self.assertEqual(result["settledCount"], 0)
        self.assertIn("Invalid payload or HMAC", result["rejected"][0]["reason"])
        self.assertEqual(result["cardStates"][0]["lastCounter"], 0)

    def test_ordered_batch_advances_counter_and_paise_balance(self) -> None:
        first_amount, second_amount = 12_500, 25_000
        first = signed_transaction(self.wallet_id, 1, first_amount, TEST_BALANCE_PAISE)
        second = signed_transaction(self.wallet_id, 2, second_amount, TEST_BALANCE_PAISE - first_amount)
        result = sync_batch([first, second], self.session)
        self.assertEqual(result["settledCount"], 2)
        self.assertEqual(result["cardStates"][0]["lastCounter"], 2)
        self.assertEqual(result["cardStates"][0]["balance"], TEST_BALANCE_PAISE - first_amount - second_amount)

    def test_transfer_debits_and_credits_atomically_after_pin_check(self) -> None:
        sender = self.credentials_by_email["member001@example.com"]
        sender_id = "member-001"
        recipient_id = "member-002"
        amount = 123_450
        connection = connect_db()
        try:
            connection.execute("UPDATE members SET balance_paise = 5000000, pin_failures = 0, pin_blocked_until = 0 WHERE member_id = ?", (sender_id,))
            connection.execute("UPDATE members SET balance_paise = 2000000 WHERE member_id = ?", (recipient_id,))
            connection.commit()
        finally:
            connection.close()
        session = create_session(sender_id)

        result = send_transfer(
            TransferRequest(
                recipientId=recipient_id,
                amountPaise=amount,
                pin=sender["pin"],
                idempotencyKey=f"unit-test-{uuid.uuid4().hex}",
            ),
            session,
        )
        self.assertEqual(result["senderBalancePaise"], 5_000_000 - amount)
        connection = connect_db()
        try:
            sender_balance = connection.execute("SELECT balance_paise FROM members WHERE member_id = ?", (sender_id,)).fetchone()[0]
            receiver_balance = connection.execute("SELECT balance_paise FROM members WHERE member_id = ?", (recipient_id,)).fetchone()[0]
            ledger_count = connection.execute("SELECT COUNT(*) FROM ledger_entries WHERE transfer_id = ?", (result["transferId"],)).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(sender_balance, 5_000_000 - amount)
        self.assertEqual(receiver_balance, 2_000_000 + amount)
        self.assertEqual(ledger_count, 2)

    def test_wrong_pin_does_not_move_balance(self) -> None:
        connection = connect_db()
        try:
            connection.execute("UPDATE members SET balance_paise = 5000000, pin_failures = 0, pin_blocked_until = 0 WHERE member_id = 'member-001'")
            connection.commit()
        finally:
            connection.close()
        session = create_session("member-001")
        try:
            send_transfer(
                TransferRequest(
                    recipientId="member-002",
                    amountPaise=10_000,
                    pin="000000",
                    idempotencyKey=f"bad-pin-{uuid.uuid4().hex}",
                ),
                session,
            )
        except Exception as error:
            self.assertIn("incorrect", str(error).lower())
        else:
            self.fail("Incorrect transfer PIN should have been rejected")

        connection = connect_db()
        try:
            sender = connection.execute("SELECT balance_paise, pin_failures FROM members WHERE member_id = 'member-001'").fetchone()
            self.assertEqual(sender["balance_paise"], 5_000_000)
            self.assertGreaterEqual(sender["pin_failures"], 1)
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
