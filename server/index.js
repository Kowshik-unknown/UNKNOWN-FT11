"use strict";

/*
 * Standalone replacement for the callable Cloud Functions in ../functions.
 * Runs on any Node host (Render, Railway, a VM) so the Firebase project can stay
 * on the free Spark plan: Auth + Firestore are used through the Admin SDK and
 * every request must carry a Firebase ID token of an active enrolled member.
 */

const crypto = require("node:crypto");
const { promisify } = require("node:util");
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");

const pbkdf2 = promisify(crypto.pbkdf2);
const FIREBASE_CERTS_URL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";

// FIREBASE_SERVICE_ACCOUNT holds the service-account JSON as a string (set it as a
// secret env var on the host). Without it, Application Default Credentials are used.
const serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT
  ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)
  : null;
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID
  || process.env.GCLOUD_PROJECT
  || serviceAccount?.project_id;
admin.initializeApp(serviceAccount
  ? { credential: admin.credential.cert(serviceAccount), projectId: serviceAccount.project_id }
  : { projectId: FIREBASE_PROJECT_ID });

const db = admin.firestore();
const MAX_TRANSFER_PAISE = 2_500_000; // ₹25,000 per transfer; review with issuer/compliance.
const DEMO_STARTING_BALANCE_PAISE = 500_000;
const PIN_FAILURE_LIMIT = 5;
const PIN_LOCK_MS = 15 * 60 * 1000;
const EXPECTED_PIN_ITERATIONS = 240_000;
let firebaseCertCache = null;
let firebaseCertCacheExpiresAt = 0;

const HTTP_STATUS = {
  "invalid-argument": 400,
  "failed-precondition": 400,
  unauthenticated: 401,
  "permission-denied": 403,
  "not-found": 404,
  "already-exists": 409,
  "resource-exhausted": 429,
  internal: 500,
};

class ApiError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

async function requireAuth(req) {
  const match = /^Bearer (.+)$/.exec(req.get("Authorization") || "");
  if (!match) throw new ApiError("unauthenticated", "Sign in with an enrolled member account.");
  try {
    const segments = match[1].split(".");
    if (segments.length !== 3) throw new Error("Malformed Firebase ID token.");
    const header = JSON.parse(Buffer.from(segments[0], "base64url").toString("utf8"));
    const claims = JSON.parse(Buffer.from(segments[1], "base64url").toString("utf8"));
    if (header.alg !== "RS256" || typeof header.kid !== "string") {
      throw new Error("Unsupported Firebase ID token signing key.");
    }
    if (!FIREBASE_PROJECT_ID) throw new Error("Firebase project ID is not configured.");

    const now = Math.floor(Date.now() / 1000);
    if (claims.aud !== FIREBASE_PROJECT_ID
        || claims.iss !== `https://securetoken.google.com/${FIREBASE_PROJECT_ID}`
        || typeof claims.sub !== "string" || !claims.sub || claims.sub.length > 128
        || typeof claims.exp !== "number" || claims.exp <= now
        || typeof claims.iat !== "number" || claims.iat > now + 300) {
      throw new Error("Firebase ID token claims are invalid for this project.");
    }

    const publicKeys = await getFirebasePublicKeys();
    const certificate = publicKeys[header.kid];
    if (!certificate) throw new Error("Firebase ID token signing key is not recognized.");
    const signedContent = Buffer.from(`${segments[0]}.${segments[1]}`);
    const signature = Buffer.from(segments[2], "base64url");
    if (!crypto.verify("RSA-SHA256", signedContent, certificate, signature)) {
      throw new Error("Firebase ID token signature is invalid.");
    }
    return claims.sub;
  } catch (error) {
    console.error("Firebase ID token verification failed", {
      code: error.code || error.name || "unknown",
      message: error.message || "No error message",
    });
    throw new ApiError("unauthenticated", "Your session has expired. Sign in again.");
  }
}

async function getFirebasePublicKeys() {
  if (firebaseCertCache && Date.now() < firebaseCertCacheExpiresAt) return firebaseCertCache;

  const response = await fetch(FIREBASE_CERTS_URL);
  if (!response.ok) throw new Error(`Could not fetch Firebase public keys (${response.status}).`);
  const certificates = await response.json();
  const cacheControl = response.headers.get("cache-control") || "";
  const maxAge = Number(/max-age=(\d+)/i.exec(cacheControl)?.[1] || 3600);

  firebaseCertCache = Object.fromEntries(
    Object.entries(certificates).map(([keyId, certificate]) => [
      keyId,
      crypto.createPublicKey(certificate),
    ]),
  );
  firebaseCertCacheExpiresAt = Date.now() + maxAge * 1000;
  return firebaseCertCache;
}

function requiredMemberData(snapshot) {
  if (!snapshot.exists || snapshot.get("isActive") !== true) {
    throw new ApiError("not-found", "No bank account was found for this signed-in user.");
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

async function verifyPin(pin, secret) {
  if (!validPin(pin) || !secret || !secret.pinSalt || !secret.pinHash) return false;
  const iterations = Number(secret.pinIterations || EXPECTED_PIN_ITERATIONS);
  if (iterations !== EXPECTED_PIN_ITERATIONS) return false;
  const salt = Buffer.from(secret.pinSalt, "hex");
  const expected = Buffer.from(secret.pinHash, "hex");
  const actual = await pbkdf2(pin, salt, iterations, expected.length, "sha256");
  return expected.length === actual.length && crypto.timingSafeEqual(actual, expected);
}

async function getMemberProfile(uid) {
  const snapshot = await db.collection("members").doc(uid).get();
  return { profile: publicMember(uid, requiredMemberData(snapshot)) };
}

async function registerMember(uid, data) {
  const { displayName, pin, email } = data || {};
  if (typeof displayName !== "string" || displayName.trim().length < 2 || displayName.trim().length > 60) {
    throw new ApiError("invalid-argument", "Enter a name between 2 and 60 characters.");
  }
  if (!validPin(pin)) throw new ApiError("invalid-argument", "Choose a six-digit transfer PIN.");

  const memberRef = db.collection("members").doc(uid);
  const secretRef = db.collection("memberSecrets").doc(uid);
  const pinSalt = crypto.randomBytes(16);
  const pinHash = await pbkdf2(pin, pinSalt, EXPECTED_PIN_ITERATIONS, 32, "sha256");

  await db.runTransaction(async (transaction) => {
    const [memberSnapshot, secretSnapshot] = await Promise.all([
      transaction.get(memberRef),
      transaction.get(secretRef),
    ]);
    if (memberSnapshot.exists || secretSnapshot.exists) {
      throw new ApiError("already-exists", "A wallet is already registered for this account.");
    }
    transaction.create(memberRef, {
      email: typeof email === "string" ? email.trim().toLowerCase() : "",
      displayName: displayName.trim(),
      bankId: "sandbox-demo",
      bankName: "Sandbox Bank",
      walletId: uid,
      balancePaise: DEMO_STARTING_BALANCE_PAISE,
      counter: 0,
      isActive: true,
      isSandbox: true,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    transaction.create(secretRef, {
      pinSalt: pinSalt.toString("hex"),
      pinHash: pinHash.toString("hex"),
      pinIterations: EXPECTED_PIN_ITERATIONS,
      pinFailures: 0,
      pinBlockedUntil: 0,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  });

  const snapshot = await memberRef.get();
  return { profile: publicMember(uid, requiredMemberData(snapshot)) };
}

async function listRecipients(uid) {
  // Only enrolled members may see the directory.
  requiredMemberData(await db.collection("members").doc(uid).get());
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
}

async function transferFunds(senderUid, data) {
  const { recipientId, amountPaise, pin, idempotencyKey } = data || {};
  if (typeof recipientId !== "string" || recipientId.length < 1 || recipientId.length > 128) {
    throw new ApiError("invalid-argument", "Choose a valid enrolled recipient.");
  }
  if (!Number.isSafeInteger(amountPaise) || amountPaise < 1 || amountPaise > MAX_TRANSFER_PAISE) {
    throw new ApiError("invalid-argument", "Enter a valid amount up to ₹25,000.00.");
  }
  if (!validPin(pin)) {
    throw new ApiError("invalid-argument", "Enter the six-digit transfer PIN.");
  }
  if (typeof idempotencyKey !== "string" || !/^[a-zA-Z0-9_-]{16,128}$/.test(idempotencyKey)) {
    throw new ApiError("invalid-argument", "A valid transfer request key is required.");
  }
  if (senderUid === recipientId) {
    throw new ApiError("invalid-argument", "You cannot send money to your own account.");
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
    if (!(await verifyPin(pin, secret))) {
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

  if (outcome.error === "pin-invalid") throw new ApiError("permission-denied", "The six-digit transfer PIN is incorrect.");
  if (outcome.error === "pin-locked") throw new ApiError("resource-exhausted", "Transfer PIN locked temporarily after failed attempts.");
  if (outcome.error === "insufficient-funds") throw new ApiError("failed-precondition", "Insufficient wallet balance.");
  if (outcome.error === "idempotency-conflict") throw new ApiError("already-exists", "This transfer request key was already used for different details.");
  return outcome;
}

async function listTransfers(uid) {
  requiredMemberData(await db.collection("members").doc(uid).get());
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
}

const handlers = { getMemberProfile, registerMember, listRecipients, transferFunds, listTransfers };

const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",").map((origin) => origin.trim()).filter(Boolean);

const app = express();
app.disable("x-powered-by");
app.use(cors({
  origin: (origin, callback) => callback(null, !origin || allowedOrigins.includes(origin)),
  methods: ["POST"],
  allowedHeaders: ["Authorization", "Content-Type"],
}));
app.use(express.json({ limit: "16kb" }));

app.get("/health", (_req, res) => res.json({ status: "ok" }));

app.post("/:name", async (req, res) => {
  const handler = Object.hasOwn(handlers, req.params.name) ? handlers[req.params.name] : null;
  if (!handler) return res.status(404).json({ error: { status: "not-found", message: "Unknown endpoint." } });
  try {
    const uid = await requireAuth(req);
    res.json(await handler(uid, req.body));
  } catch (error) {
    const code = error instanceof ApiError ? error.code : "internal";
    if (code === "internal") console.error(error);
    res.status(HTTP_STATUS[code] || 500).json({
      error: { status: code, message: code === "internal" ? "Internal server error." : error.message },
    });
  }
});

const port = Number(process.env.PORT || 8080);
app.listen(port, () => console.log(`Offlinerupee API listening on :${port}`));
