"use strict";

const crypto = require("node:crypto");
const admin = require("firebase-admin");
const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { setGlobalOptions } = require("firebase-functions/v2");

admin.initializeApp();
setGlobalOptions({ region: "asia-south1", maxInstances: 10 });

const db = admin.firestore();
const MAX_TRANSFER_PAISE = 2_500_000; // ₹25,000 per transfer; review with issuer/compliance.
const PIN_FAILURE_LIMIT = 5;
const PIN_LOCK_MS = 15 * 60 * 1000;
const EXPECTED_PIN_ITERATIONS = 240_000;

function requireAuth(request) {
  if (!request.auth || !request.auth.uid) {
    throw new HttpsError("unauthenticated", "Sign in with an enrolled member account.");
  }
  return request.auth.uid;
}

function requiredMemberData(snapshot) {
  if (!snapshot.exists || snapshot.get("isActive") !== true) {
    throw new HttpsError("not-found", "No bank account was found for this signed-in user.");
  }
  return snapshot.data();
}

function publicMember(uid, data) {
  return {
    memberId: uid,
    walletId: data.walletId || uid,
    email: data.email || "",
    displayName: data.displayName || "Member",
    bankId: data.bankId || "",
    bankName: data.bankName || "Bank",
    balancePaise: Number(data.balancePaise || 0),
    counter: Number(data.counter || 0),
    active: data.isActive === true,
  };
}

function validPin(pin) {
  return typeof pin === "string" && /^\d{6}$/.test(pin);
}

function verifyPin(pin, secret) {
  if (!validPin(pin) || !secret || !secret.pinSalt || !secret.pinHash) return false;
  const iterations = Number(secret.pinIterations || EXPECTED_PIN_ITERATIONS);
  if (iterations !== EXPECTED_PIN_ITERATIONS) return false;
  const salt = Buffer.from(secret.pinSalt, "hex");
  const expected = Buffer.from(secret.pinHash, "hex");
  const actual = crypto.pbkdf2Sync(pin, salt, iterations, expected.length, "sha256");
  return expected.length === actual.length && crypto.timingSafeEqual(actual, expected);
}

exports.getMemberProfile = onCall(async (request) => {
  const uid = requireAuth(request);
  const snapshot = await db.collection("members").doc(uid).get();
  return { profile: publicMember(uid, requiredMemberData(snapshot)) };
});

exports.listRecipients = onCall(async (request) => {
  const uid = requireAuth(request);
  const snapshot = await db.collection("members").where("isActive", "==", true).get();
  const recipients = snapshot.docs.map((document) => {
    const data = document.data();
    return {
      memberId: document.id,
      displayName: data.displayName || "Member",
      bankName: data.bankName || "Bank",
      isSelf: document.id === uid,
    };
  }).sort((left, right) => left.displayName.localeCompare(right.displayName, "en-IN"));
  return { recipients };
});

exports.transferFunds = onCall(async (request) => {
  const senderUid = requireAuth(request);
  const { recipientId, amountPaise, pin, idempotencyKey } = request.data || {};
  if (typeof recipientId !== "string" || recipientId.length < 1 || recipientId.length > 128) {
    throw new HttpsError("invalid-argument", "Choose a valid enrolled recipient.");
  }
  if (!Number.isSafeInteger(amountPaise) || amountPaise < 1 || amountPaise > MAX_TRANSFER_PAISE) {
    throw new HttpsError("invalid-argument", "Enter a valid amount up to ₹25,000.00.");
  }
  if (!validPin(pin)) {
    throw new HttpsError("invalid-argument", "Enter the six-digit transfer PIN.");
  }
  if (typeof idempotencyKey !== "string" || !/^[a-zA-Z0-9_-]{16,128}$/.test(idempotencyKey)) {
    throw new HttpsError("invalid-argument", "A valid transfer request key is required.");
  }
  if (senderUid === recipientId) {
    throw new HttpsError("invalid-argument", "You cannot send money to your own account.");
  }

  const senderRef = db.collection("members").doc(senderUid);
  const recipientRef = db.collection("members").doc(recipientId);
  const secretRef = db.collection("memberSecrets").doc(senderUid);
  const transferRef = db.collection("transfers").doc(`${senderUid}_${idempotencyKey}`);
  const now = Date.now();

  const outcome = await db.runTransaction(async (transaction) => {
    const [senderSnapshot, recipientSnapshot, secretSnapshot, priorTransfer] = await Promise.all([
      transaction.get(senderRef),
      transaction.get(recipientRef),
      transaction.get(secretRef),
      transaction.get(transferRef),
    ]);

    const sender = requiredMemberData(senderSnapshot);
    const recipient = requiredMemberData(recipientSnapshot);
    const secret = secretSnapshot.exists ? secretSnapshot.data() : null;

    if (priorTransfer.exists) {
      const prior = priorTransfer.data();
      if (prior.recipientId !== recipientId || prior.amountPaise !== amountPaise) {
        return { error: "idempotency-conflict" };
      }
      return {
        transferId: transferRef.id,
        recipientName: recipient.displayName,
        recipientBankName: recipient.bankName,
        amountPaise: prior.amountPaise,
        senderBalancePaise: Number(sender.balancePaise || 0),
        status: "settled",
        idempotentReplay: true,
      };
    }

    if (!secret || Number(secret.pinBlockedUntil || 0) > now) {
      return { error: "pin-locked" };
    }
    if (!verifyPin(pin, secret)) {
      const failures = Number(secret.pinFailures || 0) + 1;
      const pinBlockedUntil = failures >= PIN_FAILURE_LIMIT ? now + PIN_LOCK_MS : 0;
      transaction.set(secretRef, {
        ...secret,
        pinFailures: failures,
        pinBlockedUntil,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }, { merge: true });
      return { error: failures >= PIN_FAILURE_LIMIT ? "pin-locked" : "pin-invalid" };
    }

    const senderBalance = Number(sender.balancePaise || 0);
    const recipientBalance = Number(recipient.balancePaise || 0);
    if (senderBalance < amountPaise) return { error: "insufficient-funds" };

    const nextSenderBalance = senderBalance - amountPaise;
    const nextRecipientBalance = recipientBalance + amountPaise;
    const transferData = {
      senderId: senderUid,
      recipientId,
      senderName: sender.displayName || "Member",
      recipientName: recipient.displayName || "Member",
      senderBankName: sender.bankName || "Bank",
      recipientBankName: recipient.bankName || "Bank",
      amountPaise,
      idempotencyKey,
      createdAt: now,
      status: "settled",
    };

    transaction.update(senderRef, {
      balancePaise: nextSenderBalance,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    transaction.update(recipientRef, {
      balancePaise: nextRecipientBalance,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    transaction.set(transferRef, transferData);
    transaction.set(secretRef, {
      ...secret,
      pinFailures: 0,
      pinBlockedUntil: 0,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });

    return {
      transferId: transferRef.id,
      recipientName: transferData.recipientName,
      recipientBankName: transferData.recipientBankName,
      amountPaise,
      senderBalancePaise: nextSenderBalance,
      status: "settled",
      idempotentReplay: false,
    };
  });

  if (outcome.error === "pin-invalid") throw new HttpsError("permission-denied", "The six-digit transfer PIN is incorrect.");
  if (outcome.error === "pin-locked") throw new HttpsError("resource-exhausted", "Transfer PIN locked temporarily after failed attempts.");
  if (outcome.error === "insufficient-funds") throw new HttpsError("failed-precondition", "Insufficient wallet balance.");
  if (outcome.error === "idempotency-conflict") throw new HttpsError("already-exists", "This transfer request key was already used for different details.");
  return outcome;
});

exports.listTransfers = onCall(async (request) => {
  const uid = requireAuth(request);
  const [sentSnapshot, receivedSnapshot] = await Promise.all([
    db.collection("transfers").where("senderId", "==", uid).limit(25).get(),
    db.collection("transfers").where("recipientId", "==", uid).limit(25).get(),
  ]);
  const transfers = [];
  for (const document of [...sentSnapshot.docs, ...receivedSnapshot.docs]) {
    const data = document.data();
    const sent = data.senderId === uid;
    transfers.push({
      transferId: document.id,
      direction: sent ? "sent" : "received",
      counterpartyName: sent ? data.recipientName : data.senderName,
      counterpartyBankName: sent ? data.recipientBankName : data.senderBankName,
      amountPaise: Number(data.amountPaise || 0),
      createdAt: Number(data.createdAt || 0),
    });
  }
  transfers.sort((left, right) => right.createdAt - left.createdAt);
  return { transfers: transfers.slice(0, 25) };
});
