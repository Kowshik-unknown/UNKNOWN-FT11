const PROTOTYPE_HMAC_KEY = "offlinerupee-prototype-only-key-v1"; // Local-only exercise key; never use for live value.
const FIREBASE_SDK_VERSION = "11.6.0";
const LOCAL_QUEUE_PREFIX = "offlinerupee.pending.v3.";
const LOCAL_WALLET_PREFIX = "offlinerupee.local-wallet.v3.";
const OFFLINE_MODE_STORAGE_KEY = "offlinerupee.offline-mode.v1";

const $ = (selector) => document.querySelector(selector);

const state = {
  authMode: "local",
  auth: null,
  authSdk: null,
  functionsSdk: null,
  functions: null,
  user: null,
  profile: null,
  recipients: [],
  selectedRecipient: null,
  queue: [],
  lastRejected: new Map(),
  lastServerStates: new Map(),
  offline: readJson(OFFLINE_MODE_STORAGE_KEY, true) !== false,
  loadingRecipients: false,
  submittingTransfer: false,
  creatingPayment: false,
  syncing: false,
};

function readJson(key, fallback) {
  try {
    const value = JSON.parse(localStorage.getItem(key));
    return value === null ? fallback : value;
  } catch {
    return fallback;
  }
}

function userSuffix(email = state.user?.email || "local") {
  return encodeURIComponent(String(email).trim().toLowerCase());
}

function queueKey(email = state.user?.email) {
  return `${LOCAL_QUEUE_PREFIX}${userSuffix(email)}`;
}

function walletCacheKey(email = state.user?.email) {
  return `${LOCAL_WALLET_PREFIX}${userSuffix(email)}`;
}

function persistQueue() {
  localStorage.setItem(queueKey(), JSON.stringify(state.queue));
}

function saveLocalWallet() {
  if (!state.profile) return;
  localStorage.setItem(walletCacheKey(), JSON.stringify({
    balancePaise: state.profile.balancePaise,
    counter: state.profile.counter,
  }));
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
}

function formatRupees(paise) {
  return new Intl.NumberFormat("en-IN", {
    style: "currency", currency: "INR", minimumFractionDigits: 2, maximumFractionDigits: 2,
  }).format((Number(paise) || 0) / 100);
}

function parseRupeesToPaise(value) {
  const match = String(value ?? "").trim().match(/^(\d+)(?:\.(\d{1,2}))?$/);
  if (!match) return null;
  const whole = BigInt(match[1]);
  const fractional = BigInt((match[2] || "").padEnd(2, "0") || "0");
  const paise = whole * 100n + fractional;
  return paise <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(paise) : null;
}

function txKey(transaction) {
  return `${transaction.cardId}:${transaction.counter}:${transaction.signature}`;
}

function setError(id, message) {
  const element = $(id);
  element.textContent = message;
  element.classList.toggle("hidden", !message);
}

let toastTimer = null;
function toast(message) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.add("toast-show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => element.classList.remove("toast-show"), 3200);
}

async function apiRequest(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(path, { ...options, headers, credentials: "same-origin" });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = body.detail || body.message || `Request failed (${response.status})`;
    throw new Error(Array.isArray(detail) ? detail.map((item) => item.msg).join("; ") : detail);
  }
  return body;
}

function setApiStatus(connected, message = "") {
  const badge = $("#apiBadge");
  if (connected) {
    badge.innerHTML = '<span class="h-2 w-2 rounded-full bg-emerald-600"></span><span>GATEWAY READY</span>';
    $("#apiWarning").classList.add("hidden");
  } else {
    badge.innerHTML = '<span class="h-2 w-2 rounded-full bg-red-500"></span><span>GATEWAY UNAVAILABLE</span>';
    const warning = $("#apiWarning");
    warning.textContent = message || "Could not connect to the local gateway. Start FastAPI and refresh.";
    warning.classList.remove("hidden");
  }
}

function setNetworkState() {
  const badge = $("#networkBadge");
  const dot = $("#networkDot");
  const label = $("#networkLabel");
  if (state.offline) {
    badge.classList.remove("border-[#cde4d3]", "bg-[#eff8ef]", "text-[#326a4c]");
    badge.classList.add("border-[#eadfcf]", "bg-[#faf5ec]", "text-[#8b5e2b]");
    dot.classList.remove("online");
    label.textContent = "OFFLINE MODE";
  } else {
    badge.classList.remove("border-[#eadfcf]", "bg-[#faf5ec]", "text-[#8b5e2b]");
    badge.classList.add("border-[#cde4d3]", "bg-[#eff8ef]", "text-[#326a4c]");
    dot.classList.add("online");
    label.textContent = "CONNECTED";
  }
  $("#modeToggle").textContent = state.offline ? "Go online" : "Go offline";
}

function toggleNetworkMode() {
  state.offline = !state.offline;
  localStorage.setItem(OFFLINE_MODE_STORAGE_KEY, JSON.stringify(state.offline));
  setNetworkState();
  toast(state.offline ? "Offline mode enabled." : "Connected mode enabled. Sync pending payments when ready.");
}

function showLogin() {
  $("#walletView").classList.add("hidden");
  $("#loginView").classList.remove("hidden");
  $("#sessionBar").classList.add("hidden");
  $("#sessionBar").classList.remove("flex");
}

function activateSession(profile, user, authMode) {
  state.profile = profile;
  state.user = user || { email: profile.email };
  state.authMode = authMode;
  state.queue = readJson(queueKey(profile.email), []);
  if (!Array.isArray(state.queue)) state.queue = [];

  const cached = readJson(walletCacheKey(profile.email), null);
  if (authMode === "local" && state.queue.some((transaction) => transaction.cardId === profile.walletId)
      && cached && Number.isSafeInteger(cached.balancePaise) && Number.isSafeInteger(cached.counter)) {
    state.profile.balancePaise = cached.balancePaise;
    state.profile.counter = cached.counter;
  }
  $("#headerUser").textContent = profile.displayName;
  $("#headerBank").textContent = profile.bankName;
  $("#sessionBar").classList.remove("hidden");
  $("#sessionBar").classList.add("flex");
  $("#loginView").classList.add("hidden");
  $("#walletView").classList.remove("hidden");
  $("#memberCount").textContent = "50";
  $("#offlineUnavailable").classList.toggle("hidden", authMode !== "firebase");
  $("#offlineLocalTools").classList.toggle("hidden", authMode === "firebase");
  setNetworkState();
  renderWallet();
  refreshHistory();
}

function buildFirebaseProfile(data, user) {
  return {
    memberId: data.memberId || data.uid || user.uid,
    walletId: data.walletId || data.memberId || user.uid,
    email: data.email || user.email,
    displayName: data.displayName || data.name || user.displayName || user.email,
    bankName: data.bankName || "Bank",
    balancePaise: Number(data.balancePaise || 0),
    counter: Number(data.counter || 0),
    active: data.active !== false,
  };
}

async function callFirebaseFunction(name, payload = {}) {
  if (!state.functionsSdk || !state.functions) throw new Error("Firebase Cloud Functions are not configured.");
  const callable = state.functionsSdk.httpsCallable(state.functions, name);
  const response = await callable(payload);
  return response.data;
}

async function acceptFirebaseUser(user) {
  try {
    const result = await callFirebaseFunction("getMemberProfile");
    const profileData = result.profile || result;
    activateSession(buildFirebaseProfile(profileData, user), user, "firebase");
    setError("#authError", "");
  } catch (error) {
    await state.authSdk.signOut(state.auth).catch(() => {});
    showLogin();
    const message = error.code === "functions/not-found" || error.code === "functions/failed-precondition"
      ? "No bank account was found for this signed-in user. Access is limited to the 50 enrolled members."
      : `Could not verify this member account. ${error.message}`;
    setError("#authError", message);
  }
}

async function initializeFirebase() {
  const config = window.OFFLINERUPEE_FIREBASE_CONFIG || {};
  const configured = Boolean(config.apiKey && config.authDomain && config.projectId && config.appId);
  if (!configured) {
    state.authMode = "local";
    $("#authModeNote").textContent = "Local member mode is active. Only the 50 pre-enrolled sandbox accounts can sign in. Their one-time passwords and six-digit PINs are kept in backend/local_seed_credentials.json on this machine, not served to browsers. Firebase Auth and Firestore functions can be enabled with your project config.";
    try {
      const profile = await apiRequest("/api/me");
      activateSession(profile, { email: profile.email }, "local");
    } catch {
      showLogin();
    }
    return;
  }

  state.authMode = "firebase";
  $("#authModeNote").textContent = "Firebase email/password is active. Sign-in is followed by a server-side enrolled-member check. Transfers are authorized by the callable backend; new account creation is disabled here.";
  try {
    const appUrl = `https://www.gstatic.com/firebasejs/${FIREBASE_SDK_VERSION}/firebase-app.js`;
    const authUrl = `https://www.gstatic.com/firebasejs/${FIREBASE_SDK_VERSION}/firebase-auth.js`;
    const functionsUrl = `https://www.gstatic.com/firebasejs/${FIREBASE_SDK_VERSION}/firebase-functions.js`;
    const [appSdk, authSdk, functionsSdk] = await Promise.all([import(appUrl), import(authUrl), import(functionsUrl)]);
    const firebaseApp = appSdk.getApps().find((app) => app.name === "offlinerupee")
      || appSdk.initializeApp(config, "offlinerupee");
    state.authSdk = authSdk;
    state.auth = authSdk.getAuth(firebaseApp);
    state.functionsSdk = functionsSdk;
    state.functions = functionsSdk.getFunctions(firebaseApp, config.region || "asia-south1");

    const user = await new Promise((resolve, reject) => {
      let unsubscribe = () => {};
      unsubscribe = authSdk.onAuthStateChanged(state.auth, (currentUser) => {
        unsubscribe();
        resolve(currentUser);
      }, reject);
    });
    if (user) await acceptFirebaseUser(user);
    else showLogin();
  } catch (error) {
    $("#authModeNote").textContent = `Firebase could not initialize: ${error.message}. Check the web config and deploy the callable functions.`;
    $("#authModeNote").classList.add("border-red-200", "text-red-800");
    $("#loginSubmit").disabled = true;
    showLogin();
  }
}

async function handleLogin(event) {
  event.preventDefault();
  setError("#authError", "");
  const email = $("#emailInput").value.trim();
  const password = $("#passwordInput").value;
  const button = $("#loginSubmit");
  button.disabled = true;
  button.textContent = "Verifying member…";
  try {
    if (state.authMode === "firebase") {
      const credentials = await state.authSdk.signInWithEmailAndPassword(state.auth, email, password);
      await acceptFirebaseUser(credentials.user);
    } else {
      const profile = await apiRequest("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });
      activateSession(profile, { email: profile.email }, "local");
      setError("#authError", "");
    }
  } catch (error) {
    const isFirebaseCredentialError = /^auth\/(user-not-found|invalid-credential|wrong-password|invalid-email)/.test(error.code || "");
    setError("#authError", isFirebaseCredentialError
      ? "No bank account was found for this email and password. Only enrolled members can sign in."
      : error.message || "Sign-in failed.");
  } finally {
    button.disabled = false;
    button.innerHTML = 'Sign in securely <span aria-hidden="true">↗</span>';
  }
}

async function signOut() {
  try {
    if (state.authMode === "firebase" && state.auth) {
      await state.authSdk.signOut(state.auth);
    } else {
      await apiRequest("/api/auth/logout", { method: "POST" });
    }
  } catch {
    // Clear the local view even if a stale session cannot be reached.
  }
  state.profile = null;
  state.user = null;
  state.queue = [];
  state.recipients = [];
  state.selectedRecipient = null;
  closeTransferModal();
  showLogin();
  toast("Signed out.");
}

function renderWallet() {
  if (!state.profile) return;
  const profile = state.profile;
  $("#memberNameHeading").textContent = profile.displayName;
  $("#memberBank").textContent = profile.bankName;
  $("#memberWalletId").textContent = profile.walletId;
  $("#accountBankName").textContent = profile.bankName;
  $("#accountWalletId").textContent = profile.walletId;
  $("#balanceValue").textContent = formatRupees(profile.balancePaise);
  $("#counterValue").textContent = String(profile.counter || 0).padStart(6, "0");
  $("#memberIdValue").textContent = profile.memberId;
  const blockedByQueue = state.queue.some((transaction) => transaction.cardId === profile.walletId);
  $("#sendMoneyButton").disabled = state.authMode === "local" && blockedByQueue;
  $("#sendMoneyButton").title = blockedByQueue ? "Sync pending offline payments before making a peer transfer." : "Send money to an enrolled member";
  $("#offlinePaymentSubmit").disabled = state.creatingPayment || state.authMode === "firebase" || profile.balancePaise <= 0;
  renderQueue();
}

function renderRecipientList() {
  const term = $("#recipientSearch").value.trim().toLocaleLowerCase();
  const matches = state.recipients.filter((recipient) =>
    recipient.displayName.toLocaleLowerCase().includes(term) || recipient.bankName.toLocaleLowerCase().includes(term),
  );
  $("#recipientList").innerHTML = matches.map((recipient) => {
    const self = recipient.isSelf || recipient.memberId === state.profile?.memberId;
    return `
      <button type="button" data-recipient-id="${escapeHtml(recipient.memberId)}" ${self ? "disabled" : ""} class="recipient-option rounded-xl border border-[#e4eae2] bg-[#fbfcfa] p-3 text-left transition hover:border-[#9bbda2] hover:bg-[#f5faf3] disabled:cursor-not-allowed disabled:opacity-55">
        <span class="flex items-center justify-between gap-2"><span class="min-w-0"><span class="block truncate text-sm font-bold text-[#294b3b]">${escapeHtml(recipient.displayName)}${self ? ' <span class="ml-1 text-[9px] font-extrabold uppercase tracking-wide text-[#87948c]">You</span>' : ""}</span><span class="mt-1 block truncate text-[10px] font-semibold text-[#87948c]">${escapeHtml(recipient.bankName)}</span></span><span class="shrink-0 text-[#8ba192]" aria-hidden="true">→</span></span>
      </button>`;
  }).join("");
  if (!matches.length && !state.loadingRecipients) {
    $("#recipientList").innerHTML = '<p class="col-span-full rounded-xl border border-dashed border-[#dbe4d9] px-4 py-8 text-center text-sm text-[#718178]">No enrolled members match that search.</p>';
  }
}

async function openTransferModal() {
  if (!state.profile) return;
  if (state.authMode === "local" && state.queue.some((transaction) => transaction.cardId === state.profile.walletId)) {
    toast("Sync your offline payments before sending money.");
    return;
  }
  state.selectedRecipient = null;
  $("#recipientStep").classList.remove("hidden");
  $("#transferForm").classList.add("hidden");
  $("#transferSuccess").classList.add("hidden");
  $("#transferTitle").textContent = "Send money";
  $("#transferSubtitle").textContent = "Choose one of the enrolled members. Account numbers are not shown.";
  $("#recipientSearch").value = "";
  setError("#recipientError", "");
  setError("#transferError", "");
  $("#transferModal").classList.remove("hidden");
  $("#transferModal").classList.add("flex");
  $("#recipientLoading").classList.remove("hidden");
  $("#recipientList").innerHTML = "";
  try {
    const data = state.authMode === "firebase"
      ? await callFirebaseFunction("listRecipients")
      : await apiRequest("/api/members");
    state.recipients = data.recipients || [];
    state.loadingRecipients = false;
    $("#recipientLoading").classList.add("hidden");
    renderRecipientList();
    $("#recipientSearch").focus();
  } catch (error) {
    state.loadingRecipients = false;
    $("#recipientLoading").classList.add("hidden");
    setError("#recipientError", `Could not load the enrolled member list. ${error.message}`);
  }
}

function selectRecipient(memberId) {
  const recipient = state.recipients.find((item) => item.memberId === memberId && !item.isSelf);
  if (!recipient) return;
  state.selectedRecipient = recipient;
  $("#recipientStep").classList.add("hidden");
  $("#transferForm").classList.remove("hidden");
  $("#selectedRecipientCard").innerHTML = `<div class="text-[10px] font-extrabold uppercase tracking-[.13em] text-[#87948c]">Recipient</div><div class="mt-2 text-base font-bold text-[#294b3b]">${escapeHtml(recipient.displayName)}</div><div class="mt-1 text-xs font-semibold text-[#718178]">${escapeHtml(recipient.bankName)}</div>`;
  $("#transferAmountInput").value = "";
  $("#transferPinInput").value = "";
  setError("#transferError", "");
  $("#transferAmountInput").focus();
}

function closeTransferModal() {
  const modal = $("#transferModal");
  if (!modal) return;
  modal.classList.add("hidden");
  modal.classList.remove("flex");
  $("#transferAmountInput").value = "";
  $("#transferPinInput").value = "";
  setError("#transferError", "");
  setError("#recipientError", "");
  state.selectedRecipient = null;
}

function makeIdempotencyKey() {
  if (window.crypto?.randomUUID) return window.crypto.randomUUID();
  const bytes = window.crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

async function submitTransfer(event) {
  event.preventDefault();
  setError("#transferError", "");
  if (!state.selectedRecipient) return;
  const amountPaise = parseRupeesToPaise($("#transferAmountInput").value);
  const pin = $("#transferPinInput").value.trim();
  if (!Number.isSafeInteger(amountPaise) || amountPaise <= 0) {
    setError("#transferError", "Enter a valid amount with up to two decimal places.");
    return;
  }
  if (!/^\d{6}$/.test(pin)) {
    setError("#transferError", "Enter your assigned six-digit transfer PIN.");
    return;
  }
  if (amountPaise > 2_500_000) {
    setError("#transferError", "The maximum transfer for this prototype is ₹25,000.00.");
    return;
  }
  if (amountPaise > state.profile.balancePaise) {
    setError("#transferError", "Insufficient available balance.");
    return;
  }

  state.submittingTransfer = true;
  $("#confirmTransferButton").disabled = true;
  $("#confirmTransferButton").textContent = "Verifying PIN and transferring…";
  try {
    const payload = {
      recipientId: state.selectedRecipient.memberId,
      amountPaise,
      pin,
      idempotencyKey: makeIdempotencyKey(),
    };
    const result = state.authMode === "firebase"
      ? await callFirebaseFunction("transferFunds", payload)
      : await apiRequest("/api/transfers", { method: "POST", body: JSON.stringify(payload) });

    state.profile.balancePaise = result.senderBalancePaise;
    if (state.authMode === "local") saveLocalWallet();
    $("#transferForm").classList.add("hidden");
    $("#transferSuccess").classList.remove("hidden");
    $("#transferTitle").textContent = "Transfer complete";
    $("#transferSubtitle").textContent = result.transferId;
    $("#transferSuccessText").textContent = `${formatRupees(result.amountPaise)} sent to ${result.recipientName} · ${result.recipientBankName}. Transfer reference ${result.transferId}.`;
    renderWallet();
    await refreshHistory();
  } catch (error) {
    setError("#transferError", error.message || "Transfer could not be completed.");
  } finally {
    state.submittingTransfer = false;
    $("#confirmTransferButton").disabled = false;
    $("#confirmTransferButton").innerHTML = 'Confirm transfer <span aria-hidden="true">→</span>';
    $("#transferPinInput").value = "";
  }
}

function renderHistory(transfers) {
  const history = $("#historyList");
  if (!transfers.length) {
    history.innerHTML = '<div class="rounded-xl border border-dashed border-[#dbe4d9] px-4 py-7 text-center text-xs text-[#87948c]">No transfers yet.</div>';
    return;
  }
  history.innerHTML = transfers.slice(0, 12).map((item) => {
    const received = item.direction === "received";
    const date = item.createdAt ? new Date(typeof item.createdAt === "number" && item.createdAt < 1e12 ? item.createdAt * 1000 : item.createdAt).toLocaleString("en-IN", { dateStyle: "medium", timeStyle: "short" }) : "Just now";
    return `<div class="flex items-center justify-between gap-3 rounded-xl border border-[#e6ebe4] bg-[#fbfcfa] px-3 py-3"><div class="flex min-w-0 items-center gap-3"><span class="grid h-9 w-9 shrink-0 place-items-center rounded-full ${received ? "bg-[#eaf4e8] text-[#2e7954]" : "bg-[#fbf1e2] text-[#a16b2c]"}">${received ? "↓" : "↑"}</span><span class="min-w-0"><span class="block truncate text-xs font-bold text-[#365447]">${received ? "From " : "To "}${escapeHtml(item.counterpartyName)}</span><span class="mt-1 block truncate text-[10px] text-[#87948c]">${escapeHtml(item.counterpartyBankName)} · ${escapeHtml(date)}</span></span></div><span class="shrink-0 text-xs font-extrabold ${received ? "text-[#2e7954]" : "text-[#a16b2c]"}">${received ? "+" : "−"}${formatRupees(item.amountPaise)}</span></div>`;
  }).join("");
}

async function refreshHistory() {
  if (!state.profile) return;
  try {
    const data = state.authMode === "firebase"
      ? await callFirebaseFunction("listTransfers")
      : await apiRequest("/api/transfers");
    renderHistory(data.transfers || []);
  } catch {
    renderHistory([]);
  }
}

async function signOfflinePayload(payload) {
  if (!window.crypto?.subtle) throw new Error("Web Crypto is unavailable in this browser.");
  const encoder = new TextEncoder();
  const key = await window.crypto.subtle.importKey("raw", encoder.encode(PROTOTYPE_HMAC_KEY), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await window.crypto.subtle.sign("HMAC", key, encoder.encode(payload));
  return Array.from(new Uint8Array(signature), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function renderQueue() {
  const list = $("#queueList");
  const currentPending = state.profile ? state.queue.filter((item) => item.cardId === state.profile.walletId) : [];
  $("#offlineSummary").textContent = `${currentPending.length} pending`;
  $("#queueSummary").textContent = currentPending.length ? `${currentPending.length} signed payment${currentPending.length === 1 ? "" : "s"} waiting to settle` : "No pending payments";
  $("#syncButton").disabled = state.syncing;
  $("#syncButton").textContent = state.syncing ? "Syncing…" : currentPending.length ? `Reconnect & settle ${currentPending.length}` : "Reconnect & sync";
  $("#discardRejectedButton").classList.toggle("hidden", state.lastRejected.size === 0);
  if (!currentPending.length) {
    list.innerHTML = '<div class="rounded-xl border border-dashed border-[#dbe4d9] px-4 py-5 text-center text-xs text-[#87948c]">No signed payments in the queue.</div>';
    return;
  }
  list.innerHTML = currentPending.slice().sort((a,b)=>a.counter-b.counter).map((item) => {
    const reason = state.lastRejected.get(txKey(item));
    return `<div class="rounded-xl border border-[#e6ebe4] bg-[#fbfcfa] px-3 py-3"><div class="flex items-center justify-between gap-3"><div><div class="text-xs font-bold text-[#365447]">${escapeHtml(item.merchantId)}</div><div class="mono mt-1 text-[10px] text-[#87948c]">counter ${escapeHtml(item.counter)}</div></div><div class="text-right"><div class="text-xs font-extrabold text-[#294b3b]">−${formatRupees(item.amount)}</div><div class="mt-1 text-[9px] font-black uppercase tracking-wide ${reason ? "text-red-700" : "text-[#a16b2c]"}">${reason ? "Rejected" : "Pending"}</div></div></div>${reason ? `<div class="mt-2 text-[10px] leading-4 text-red-800">${escapeHtml(reason)}</div>` : ""}</div>`;
  }).join("");
}

async function createOfflinePayment(event) {
  event.preventDefault();
  setError("#offlineError", "");
  if (state.authMode !== "local" || !state.profile) return;
  const merchantId = $("#merchantInput").value.trim();
  const amount = parseRupeesToPaise($("#offlineAmountInput").value);
  if (!merchantId || !Number.isSafeInteger(amount) || amount <= 0) {
    setError("#offlineError", "Enter a merchant reference and a positive amount.");
    return;
  }
  if (amount > state.profile.balancePaise) {
    setError("#offlineError", "Insufficient wallet balance.");
    return;
  }
  state.creatingPayment = true;
  $("#offlinePaymentSubmit").disabled = true;
  $("#offlinePaymentSubmit").textContent = "Signing locally…";
  try {
    const fields = {
      cardId: state.profile.walletId,
      merchantId,
      amount,
      newBalance: state.profile.balancePaise - amount,
      counter: state.profile.counter + 1,
    };
    const payload = JSON.stringify(fields);
    const signature = await signOfflinePayload(payload);
    state.queue.push({ ...fields, payload, signature });
    state.profile.balancePaise = fields.newBalance;
    state.profile.counter = fields.counter;
    persistQueue();
    saveLocalWallet();
    $("#offlineAmountInput").value = "";
    renderWallet();
    toast("Signed payment queued on this device.");
  } catch (error) {
    setError("#offlineError", error.message);
  } finally {
    state.creatingPayment = false;
    $("#offlinePaymentSubmit").disabled = state.profile.balancePaise <= 0;
    $("#offlinePaymentSubmit").textContent = "Create signed offline payment";
  }
}

async function syncQueue() {
  if (state.authMode !== "local") return;
  state.offline = false;
  localStorage.setItem(OFFLINE_MODE_STORAGE_KEY, JSON.stringify(false));
  setNetworkState();
  const batch = state.queue.filter((item) => item.cardId === state.profile.walletId);
  if (!batch.length) {
    showSyncResult("Connected. There are no pending payments to settle.");
    return;
  }
  state.syncing = true;
  renderQueue();
  try {
    const response = await apiRequest("/api/sync-batch", { method: "POST", body: JSON.stringify(batch) });
    const accepted = new Set((response.accepted || []).map(txKey));
    state.queue = state.queue.filter((item) => !accepted.has(txKey(item)));
    persistQueue();
    state.lastRejected = new Map((response.rejected || []).map((item) => [txKey(item), item.reason]));
    state.lastServerStates = new Map((response.cardStates || []).map((item) => [item.cardId, item]));
    const server = state.lastServerStates.get(state.profile.walletId);
    const stillPending = state.queue.some((item) => item.cardId === state.profile.walletId);
    if (server && !stillPending) {
      state.profile.balancePaise = server.balance;
      state.profile.counter = server.lastCounter;
      saveLocalWallet();
    }
    showSyncResult(response.rejectedCount
      ? `${response.settledCount} settled; ${response.rejectedCount} rejected. Review the rejection details.`
      : `${response.settledCount} offline payment${response.settledCount === 1 ? "" : "s"} settled successfully.`);
  } catch (error) {
    state.offline = true;
    localStorage.setItem(OFFLINE_MODE_STORAGE_KEY, JSON.stringify(true));
    showSyncResult(`Sync failed; the queue was preserved. ${error.message}`, true);
  } finally {
    state.syncing = false;
    setNetworkState();
    renderWallet();
  }
}

function showSyncResult(message, isError = false) {
  const box = $("#syncResult");
  box.textContent = message;
  box.classList.remove("hidden", "border-[#cde4d3]", "bg-[#eff8ef]", "text-[#326a4c]", "border-red-200", "bg-red-50", "text-red-800");
  box.classList.add(...(isError ? ["border-red-200", "bg-red-50", "text-red-800"] : ["border-[#cde4d3]", "bg-[#eff8ef]", "text-[#326a4c]"]));
  box.classList.remove("hidden");
}

function discardRejected() {
  if (!state.lastRejected.size) return;
  const keys = new Set(state.lastRejected.keys());
  state.queue = state.queue.filter((item) => !keys.has(txKey(item)));
  state.lastRejected.clear();
  persistQueue();
  const server = state.lastServerStates.get(state.profile.walletId);
  if (server && !state.queue.some((item) => item.cardId === state.profile.walletId)) {
    state.profile.balancePaise = server.balance;
    state.profile.counter = server.lastCounter;
    saveLocalWallet();
  }
  showSyncResult("Rejected payments discarded; local wallet reconciled to the latest server state.");
  renderWallet();
}

function bindEvents() {
  $("#loginForm").addEventListener("submit", handleLogin);
  $("#signOutButton").addEventListener("click", signOut);
  $("#modeToggle").addEventListener("click", toggleNetworkMode);
  $("#sendMoneyButton").addEventListener("click", openTransferModal);
  $("#closeTransferModal").addEventListener("click", closeTransferModal);
  $("#doneTransferButton").addEventListener("click", closeTransferModal);
  $("#transferModal").addEventListener("click", (event) => {
    if (event.target.closest("[data-close-modal='true']")) closeTransferModal();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeTransferModal();
  });
  $("#recipientSearch").addEventListener("input", renderRecipientList);
  $("#recipientList").addEventListener("click", (event) => {
    const option = event.target.closest("[data-recipient-id]");
    if (option && !option.disabled) selectRecipient(option.dataset.recipientId);
  });
  $("#backToRecipients").addEventListener("click", () => {
    $("#transferForm").classList.add("hidden");
    $("#recipientStep").classList.remove("hidden");
    $("#transferPinInput").value = "";
  });
  $("#transferForm").addEventListener("submit", submitTransfer);
  $("#refreshHistoryButton").addEventListener("click", refreshHistory);
  $("#offlinePaymentForm").addEventListener("submit", createOfflinePayment);
  $("#syncButton").addEventListener("click", syncQueue);
  $("#discardRejectedButton").addEventListener("click", discardRejected);
}

async function initialize() {
  bindEvents();
  setNetworkState();
  try {
    const [health, roster] = await Promise.all([apiRequest("/api/health"), apiRequest("/api/roster-summary")]);
    $("#memberCount").textContent = String(roster.memberCount || 50);
    setApiStatus(health.status === "ok");
  } catch (error) {
    setApiStatus(false, `Could not load the member service. Start FastAPI and refresh. ${error.message}`);
  }
  await initializeFirebase();
}

initialize();
