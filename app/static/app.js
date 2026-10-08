"use strict";
// Session lives only in memory (not localStorage) -> cleared on tab close; reduces token theft via XSS/persistence.
let S = null; let pending = null;
const $ = (s) => document.querySelector(s);
const inr = (p) => "₹" + (p / 100).toLocaleString("en-IN", { minimumFractionDigits: 2 });
const toPaise = (v) => Math.round(Number.parseFloat(v) * 100);


// Safe DOM builders (no innerHTML with data) - fixes Sonar "DOM XSS via unsanitized user input"
function el(tag, text, cls) { const n = document.createElement(tag); if (text !== undefined) n.textContent = String(text); if (cls) n.className = cls; return n; }
function row(cells) { const tr = document.createElement("tr"); cells.forEach((c) => tr.appendChild(c instanceof Node ? c : el("td", c))); return tr; }
function fill(tbody, rows, emptyText, cols) {
  tbody.replaceChildren();
  if (!rows.length) { const td = el("td", emptyText, "muted"); td.colSpan = cols; tbody.appendChild(row([td])); return; }
  rows.forEach((r) => tbody.appendChild(r));
}
function tdWith(child, cls) { const td = el("td", undefined, cls); td.appendChild(child); return td; }

function toast(msg, kind = "") { const t = $("#toast"); t.textContent = msg; t.className = kind; t.hidden = false; clearTimeout(t._h); t._h = setTimeout(() => (t.hidden = true), 4000); }

async function hmacHex(keyHex, msg) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(keyHex), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function sha256Hex(bytes) { const d = await crypto.subtle.digest("SHA-256", bytes); return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join(""); }
const nonce = () => [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");

async function api(path, { method = "GET", body, signed = false, headers = {} } = {}) {
  const h = { ...headers };
  let raw;
  if (S) h.Authorization = "Bearer " + S.token;
  if (body !== undefined || signed) { raw = new TextEncoder().encode(JSON.stringify(body ?? {})); h["Content-Type"] = "application/json"; }
  if (signed) {
    const ts = String(Math.floor(Date.now() / 1000)), n = nonce();
    const canon = [method, path, ts, n, await sha256Hex(raw)].join("|");
    Object.assign(h, { "X-Timestamp": ts, "X-Nonce": n, "X-Signature": await hmacHex(S.key, canon) });
  }
  const r = await fetch(path, { method, headers: h, body: raw });
  const data = await r.json().catch(() => ({}));
  if (r.status === 401 && S && !path.includes("/auth/")) { toast("Session expired – please sign in again", "err"); logout(); }
  if (!r.ok) throw new Error(data.error || data.detail || (data.fields ? "Invalid: " + data.fields.join(", ") : "Request failed"));
  return data;
}

// ---------- routing ----------
const HOME = { customer: "#wallet", merchant: "#merchant", admin: "#admin" };
const ROUTES = { "#wallet": ["customer"], "#pay": ["customer"], "#history": ["customer", "merchant"], "#merchant": ["merchant"], "#admin": ["admin"] };
function route() {
  let h = location.hash || "#login";
  if (!S) h = "#login"; else if (!ROUTES[h] || !ROUTES[h].includes(S.role)) h = HOME[S.role];
  document.querySelectorAll(".view").forEach((v) => (v.hidden = v.id !== "v-" + h.slice(1)));
  $("#nav").hidden = !S;
  document.querySelectorAll("#nav a").forEach((a) => { a.hidden = !S || !a.dataset.roles.split(" ").includes(S.role); a.classList.toggle("on", a.getAttribute("href") === h); });
  if (location.hash !== h) history.replaceState(null, "", h);
  // explicit allow-list instead of calling obj[userControlledKey]() (CodeQL js/unvalidated-dynamic-method-call)
  switch (h) {
    case "#wallet": void loadWallet(); break;
    case "#pay": void loadPay(); break;
    case "#history": void loadHistory(); break;
    case "#merchant": void loadMerchant(); break;
    case "#admin": void loadAudit(); break;
    default: break;
  }
}
window.addEventListener("hashchange", route);
function logout() {
  // DEF-03 fix: wipe every form, table and balance so the next user of a shared device sees nothing of the previous one
  S = null; pending = null;
  document.querySelectorAll("form").forEach((f) => f.reset());
  ["#txns", "#mpays", "#audit"].forEach((id) => $(id).replaceChildren());
  ["#bal", "#mbal", "#wid", "#who", "#mstatus"].forEach((id) => ($(id).textContent = ""));
  route();
}
$("#logout").onclick = logout;

// ---------- login / register ----------
document.querySelectorAll(".tab").forEach((b) => (b.onclick = () => {
  document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("on", x === b));
  $("#f-login").hidden = b.dataset.tab !== "login"; $("#f-register").hidden = b.dataset.tab !== "register";
}));
$("#f-login").onsubmit = async (e) => {
  e.preventDefault(); const f = Object.fromEntries(new FormData(e.target));
  try {
    const d = await api("/api/auth/login", { method: "POST", body: f });
    S = { token: d.access_token, key: d.signing_key, role: d.role, name: f.username };
    $("#who").textContent = f.username + " · " + d.role; e.target.reset(); location.hash = HOME[d.role]; route();
  } catch (err) { toast(err.message, "err"); }
};
$("#f-register").onsubmit = async (e) => {
  e.preventDefault(); const f = Object.fromEntries(new FormData(e.target));
  try { await api("/api/auth/register", { method: "POST", body: f }); toast("Account created – sign in now", "ok"); document.querySelector('[data-tab=login]').click(); $("#f-login").username.value = f.username; }
  catch (err) { toast(err.message, "err"); }
};

// ---------- wallet ----------
async function loadWallet() {
  try { const w = await api("/api/wallets/me"); $("#bal").textContent = inr(w.balance); $("#wid").textContent = "Wallet #" + w.wallet_id + " · " + w.currency; $("#mkwallet").hidden = true; $("#f-topup").hidden = false; }
  catch { $("#bal").textContent = "No wallet yet"; $("#wid").textContent = ""; $("#mkwallet").hidden = false; $("#f-topup").hidden = true; }
}
$("#mkwallet").onclick = async () => { try { await api("/api/wallets", { method: "POST" }); toast("Wallet created", "ok"); await loadWallet(); } catch (e) { toast(e.message, "err"); } };
$("#f-topup").onsubmit = async (e) => {
  e.preventDefault(); const btn = e.submitter; btn.disabled = true;
  try { const r = await api("/api/wallets/topup", { method: "POST", signed: true, body: { amount: toPaise(e.target.amount.value) } }); toast("Added. New balance " + inr(r.balance), "ok"); e.target.reset(); await loadWallet(); }
  catch (err) { toast(err.message, "err"); } finally { btn.disabled = false; }
};

// ---------- pay ----------
async function loadPay() {
  const ms = await api("/api/merchants").catch(() => []);
  const sel = $("#merchants"); sel.replaceChildren();
  if (!ms.length) { const o = el("option", "No merchants yet"); o.value = ""; sel.appendChild(o); }
  ms.forEach((m) => { const o = el("option", `${m.business_name} (${m.category})`); o.value = String(m.merchant_id); sel.appendChild(o); });
  showPending();
}
function showPending() {
  $("#pending").textContent = pending ? `Payment #${pending.id}: ${inr(pending.amount)} to ${pending.merchant}. Check the details, then confirm.` : "No pending payment.";
  $("#confirm").disabled = $("#cancel").disabled = !pending;
}
$("#f-pay").onsubmit = async (e) => {
  e.preventDefault(); const sel = $("#merchants");
  const body = { merchant_id: Number.parseInt(sel.value, 10), amount: toPaise(e.target.amount.value) };
  try {
    const r = await api("/api/payments", { method: "POST", signed: true, body, headers: { "Idempotency-Key": crypto.randomUUID() } });
    pending = { id: r.payment_id, amount: r.amount, merchant: sel.options[sel.selectedIndex].text }; showPending();
  } catch (err) { toast(err.message, "err"); }
};
$("#confirm").onclick = async () => {
  $("#confirm").disabled = true;               // prevents double-click double submit
  try { const r = await api(`/api/payments/${pending.id}/confirm`, { method: "POST", signed: true });
    toast(r.status === "CONFIRMED" ? "Payment successful" : "Payment failed: " + r.reason, r.status === "CONFIRMED" ? "ok" : "err"); pending = null; showPending(); }
  catch (err) { toast(err.message, "err"); $("#confirm").disabled = false; }
};
$("#cancel").onclick = () => { pending = null; showPending(); toast("Payment not confirmed – no money moved"); };

// ---------- history ----------
async function loadHistory() {
  try { const t = await api("/api/transactions");
    fill($("#txns"), t.map((x) => row([String(x.txn_id), tdWith(el("span", x.txn_type, "st")), String(x.payment_id ?? "—"),
      el("td", (/DEBIT/.test(x.txn_type) ? "−" : "+") + inr(x.amount), "r"), el("td", inr(x.balance_after), "r"), el("td", x.created_at, "mono")])), "No transactions yet", 6);
  } catch (e) { fill($("#txns"), [], e.message, 6); }
}

// ---------- merchant ----------
async function loadMerchant() {
  try { const w = await api("/api/wallets/me"); $("#mbal").textContent = inr(w.balance); $("#f-merchant").hidden = true; } catch { $("#mbal").textContent = "—"; $("#mstatus").textContent = "Register your business to receive payments."; $("#f-merchant").hidden = false; }
  const ps = await api("/api/merchant/payments").catch(() => []);
  fill($("#mpays"), ps.map((p) => {
    const action = el("td");
    if (p.status === "CONFIRMED") {
      const b = el("button", "Refund", "ghost"); b.dataset.refund = String(p.payment_id);
      b.onclick = () => { $("#rpid").textContent = "#" + p.payment_id; $("#refundDlg").dataset.pid = String(p.payment_id); $("#refundDlg").showModal(); };
      action.appendChild(b);
    }
    return row(["#" + p.payment_id, el("td", inr(p.amount), "r"), tdWith(el("span", p.status, "st " + p.status)), el("td", p.created_at, "mono"), action]);
  }), "No payments yet", 5);
}
$("#f-merchant").onsubmit = async (e) => {
  e.preventDefault();
  try { const r = await api("/api/merchants", { method: "POST", body: Object.fromEntries(new FormData(e.target)) }); toast("Merchant #" + r.merchant_id + " registered", "ok"); e.target.reset(); await loadMerchant(); }
  catch (err) { toast(err.message, "err"); }
};
$("#refundDlg").addEventListener("close", async () => {
  const d = $("#refundDlg"); if (d.returnValue !== "ok") return;
  try { await api(`/api/payments/${d.dataset.pid}/refund`, { method: "POST", signed: true, body: { reason: $("#f-refund").reason.value } }); toast("Refund issued", "ok"); $("#f-refund").reset(); await loadMerchant(); }
  catch (err) { toast(err.message, "err"); }
});

// ---------- admin ----------
async function loadAudit() {
  try { const a = await api("/api/admin/audit"); const v = a.verification;
    $("#chain").textContent = v.valid ? `hash chain valid · ${v.entries} entries` : `TAMPERED at #${v.broken_at}`; $("#chain").className = "pill " + (v.valid ? "ok" : "bad");
    fill($("#audit"), a.entries.slice().reverse().map((x) => row([String(x.audit_id), el("td", x.ts.slice(0, 19), "mono"), String(x.actor_id ?? "system"), x.action, x.entity, el("td", x.entry_hash.slice(0, 12) + "…", "mono")])), "No entries", 6);
  } catch (e) { toast(e.message, "err"); }
}
route();
