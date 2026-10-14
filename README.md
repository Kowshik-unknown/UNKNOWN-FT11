# Offlinerupee — enrolled-member wallet prototype

A local-first wallet prototype with a 50-member roster, bank-name assignments, peer transfers, and a signed offline payment queue. The hosted demo uses Firebase Authentication, Firestore, and Hosting on the Spark plan; local FastAPI mode remains available for development.

> **No real bank connection or money:** the 50 members and balances are synthetic sandbox data. Bank names are reference labels only. The app does not collect bank account numbers, card numbers, CVVs, OTPs, or bank passwords. CVV is deliberately not stored or used; it is not a wallet login credential and must not be retained.

## Run the local prototype

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
python -m pip install -r backend/requirements.txt
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Open <http://127.0.0.1:8000>. On the first start, FastAPI seeds **50 pre-enrolled members** into SQLite. There is no signup endpoint, and an email/password not in that member dataset receives “No bank account was found for these credentials.”

The local seed creates a random password and six-digit PIN per member. It stores only PBKDF2 password/PIN verifiers in SQLite and writes the one-time sandbox credentials to `backend/local_seed_credentials.json`. That file is **git-ignored, not served by the web server, and contains sensitive test credentials**—keep it private. The login page does not show credentials. The roster itself is `backend/member_roster.json` and contains names, fixed test emails, bank-name assignments, wallet IDs, and synthetic starting balances, but no passwords, PINs, CVVs, or account numbers.

Firebase Hosting serves only the static frontend; it does not run FastAPI. For the hosted Firebase mode, deploy the callable functions and provision Firebase Auth/Firestore members using the Firebase setup below. Their one-time passwords and PINs are written to `backend/firebase_seed_credentials.json`. The local and Firebase credential files are separate; neither is created just by deploying Hosting.

After sign-in, the wallet displays the member's assigned bank and balance. **Send money** loads the 50-member recipient directory; each row shows only the recipient's name and bank. The current member is visible but disabled as a recipient. Select another member, enter an amount and the assigned six-digit transfer PIN, then confirm. Local transfers update sender and recipient balances in one SQLite transaction. Five incorrect PIN attempts trigger a 15-minute lock. The transfer limit is ₹25,000 per transaction in this prototype.

All local balances are sandbox amounts, not bank balances. The offline merchant-payment section remains available in local mode; signed pending payments are kept in browser `localStorage` and synchronized through `POST /api/sync-batch`. Do not use it for real funds.

## Firebase setup

When Firebase is configured, the frontend uses Firebase Email/Password authentication and Firestore directly; it does not call Render, FastAPI, or Cloud Functions. Visitors can register a demo account and receive ₹5,000 in simulated funds. Firestore rules restrict profile creation to the signed-in user, make profiles private, publish only a separate name/bank directory, and allow balance changes only when a matching transfer atomically debits one wallet and credits another. The six-digit PIN remains part of local FastAPI mode only: Spark has no trusted server to verify it, so the Firebase demo does not request or claim to verify a transfer PIN.

1. Use a **dedicated Firebase sandbox project**. Enable Email/Password in Firebase Authentication and create Firestore in production mode.
2. Confirm the public web-app values (`apiKey`, `authDomain`, `projectId`, `appId`) in `frontend/firebase-config.js`. Never put a service-account key there.
3. Install the Firebase CLI, sign in, and select the project:
   ```bash
   npm install -g firebase-tools
   firebase login
   firebase use --add
   ```
4. Deploy the Firestore security rules and static frontend:
   ```bash
   firebase deploy --only firestore:rules,hosting
   ```

Once deployed, open the Hosting URL and select **New here? Create a demo account**. Existing seeded members may continue signing in; their public name/bank listing is added when they next sign in. This setup requires no Firebase service-account key, Blaze upgrade, or Render service.

For local development, deploy Hosting separately only when you want to update the live site:
   ```bash
   firebase deploy --only hosting
   ```

The seeder uses reserved `example.com` test addresses and synthetic initial balances. Replace the roster with real, consented enrollment data and a legitimate funds-provisioning process before any pilot. Do not seed real account numbers, CVVs, or passwords into Firestore.

## Firebase data model and rules

- `members/{uid}` — display name, email, bank label, wallet ID, sandbox balance in paise, counter, and `isActive`.
- `publicMembers/{uid}` — only display name, bank label, and active status; readable to signed-in demo users.
- `memberSecrets/{uid}` — legacy server-only PIN verifier data; never readable or writable by the client.
- `transfers/{senderUid_idempotencyKey}` — transfer record created in the same Firestore transaction that updates both balances.

`firestore.rules` allows a signed-in user to read only their own private member document. New Firebase demo accounts receive exactly 500,000 paise at creation; clients cannot update balances except through a matched transfer that reduces the sender balance and increases the recipient balance by the same amount. Transfer documents are visible only to their two participants. This is a demo integrity boundary, not a real-money banking system; demo users can create multiple accounts and there is no server-verified PIN or fraud-control service.

## Bank catalogue

`backend/bank_catalog.json` contains 123 public institution names across public-sector banks, domestic private-sector banks, small-finance banks, payments banks, regional rural banks, local-area banks, and foreign banks operating in India. The UI shows assigned bank names but never displays a bank account number. The names were compiled from RBI's [Banks in India](https://www.rbi.org.in/commonman/english/scripts/BanksInIndia.aspx) and [Bank Links](https://www.rbi.org.in/scripts/banklinks.aspx) pages; the foreign-bank names use RBI's [branch/WOS presence list](https://rbidocs.rbi.org.in/rdocs/Content/pdfs/71207.pdf), dated 15 November 2025. This is a broad catalogue, not an exhaustive directory of every cooperative bank, and inclusion does not imply account-linking support.

## API and tests

Local API routes:

- `GET /api/health`, `GET /api/roster-summary`
- `GET /api/banks` — public bank names only
- `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/me` — existing-roster-only local session
- `GET /api/members` — authenticated name/bank recipient list, no account numbers
- `POST /api/transfers`, `GET /api/transfers` — PIN-checked local peer transfers and history
- `POST /api/sync-batch` — signed offline settlement with a strict counter and balance-chain check

Money is represented internally as integer paise. Tests:

```bash
python -m unittest discover -s backend/tests -v
```

## Security limits and next steps

This remains a hackathon prototype, not an authorized payment product. The local generated credentials file contains plaintext **test** passwords/PINs and must be kept private. The offline browser HMAC key is intentionally public, so it is not a production security control. SQLite local sessions are for preview use only.

Before real funds:

- Replace browser HMAC with per-card hardware-backed signing and a secure key-provisioning/rotation/revocation ceremony.
- Authenticate every API request with Firebase ID tokens or another trusted identity token; bind every wallet/transfer to a verified owner and reject inactive/revoked members.
- Provision balances only from an issuer/sponsor/regulated Account Aggregator flow; never accept client-supplied balances or public top-up requests.
- Set issuer-approved offline limits, per-day velocity limits, device binding, transaction expiry, conflict/rollback recovery, lost-device revocation, dispute/reversal rules, and double-entry reconciliation.
- Add key management/HSM, audit retention, encrypted transport/storage, monitoring, rate limiting, backups, incident response, penetration testing, and payment/privacy legal review.

Materials needed for the real integration include smartcard/secure-element model and APDU/SDK docs; issuer/sponsor sandbox and settlement/reversal specifications; merchant onboarding and identity requirements; Firebase project details; offline-risk policy; data-retention/privacy policy; and a threat model. Never share service-account credentials in chat or commit them to the repository.
