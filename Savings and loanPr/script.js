"use strict";
const $ = id => document.getElementById(id);
const enc = new TextEncoder(), dec = new TextDecoder();
const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")), c => c.charCodeAt(0));
const money = c => (c/100).toLocaleString("en-US",{style:"currency",currency:"USD"});

/* ---------- Mock backend (in a real app this is your server) ---------- */
const Server = (() => {
  const users = {}, pending = {}, fails = {};
  let jwtKey, dataKey;
  const ready = (async () => {
    jwtKey = await crypto.subtle.generateKey({name:"HMAC",hash:"SHA-256"}, false, ["sign","verify"]);
    dataKey = await crypto.subtle.generateKey({name:"AES-GCM",length:256}, false, ["encrypt","decrypt"]);
  })();
  const hash = async (pw, salt) => {
    const k = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
    return b64u(await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations:210000,hash:"SHA-256"}, k, 256));
  };
  const encrypt = async obj => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({name:"AES-GCM",iv}, dataKey, enc.encode(JSON.stringify(obj)));
    return b64u(iv) + "." + b64u(ct);
  };
  const decrypt = async s => {
    const [iv, ct] = s.split(".");
    return JSON.parse(dec.decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64u(iv)}, dataKey, unb64u(ct))));
  };
  const sign = async claims => {
    const h = b64u(enc.encode(JSON.stringify({alg:"HS256",typ:"JWT"}))), p = b64u(enc.encode(JSON.stringify(claims)));
    const s = b64u(await crypto.subtle.sign("HMAC", jwtKey, enc.encode(h + "." + p)));
    return h + "." + p + "." + s;
  };
  const verify = async token => {
    const [h, p, s] = String(token).split(".");
    if (!h || !p || !s || !(await crypto.subtle.verify("HMAC", jwtKey, unb64u(s), enc.encode(h + "." + p)))) throw new Error("Invalid session");
    const c = JSON.parse(dec.decode(unb64u(p)));
    if (c.exp * 1000 < Date.now()) throw new Error("Session expired");
    return c;
  };
  const checkLock = email => { const f = fails[email]; if (f && f.until > Date.now()) throw new Error("Too many attempts. Try again in a minute."); };
  const fail = email => { const f = fails[email] || (fails[email] = {n:0,until:0}); if (++f.n >= 5) { f.until = Date.now() + 60000; f.n = 0; } };

  return {
    ready,
    async register(email, pw) {
      await ready;
      if (users[email]) throw new Error("Could not create account. Try signing in.");
      const salt = crypto.getRandomValues(new Uint8Array(16));
      users[email] = {salt, hash: await hash(pw, salt), balance: 0, loans: []};
    },
    async login(email, pw) {
      await ready; checkLock(email);
      const u = users[email];
      const h = await hash(pw, u ? u.salt : new Uint8Array(16));   // same work either way
      if (!u || h !== u.hash) { fail(email); throw new Error("Invalid email or password."); }
      const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, "0");
      pending[email] = {code, exp: Date.now() + 300000, tries: 0};
      return code;   // real server: send by SMS/app, never return it
    },
    async verifyMfa(email, code) {
      const m = pending[email];
      if (!m || m.exp < Date.now()) throw new Error("Code expired. Sign in again.");
      if (++m.tries > 3) { delete pending[email]; throw new Error("Too many wrong codes. Sign in again."); }
      if (code !== m.code) throw new Error("That code is not correct.");
      delete pending[email];
      const now = Math.floor(Date.now() / 1000);
      return sign({sub: email, role: "member", iat: now, exp: now + 900});
    },
    async api(token, action, data) {
      const c = await verify(token), u = users[c.sub];
      if (action === "deposit") {
        const cents = Math.round(Number(data) * 100);
        if (!Number.isFinite(cents) || cents < 100 || cents > 100000000) throw new Error("Enter an amount from $1 to $1,000,000.");
        u.balance += cents;
      }
      if (action === "loan") {
        const {amt, term} = data;
        if (!Number.isInteger(amt) || amt < 500 || amt > 50000) throw new Error("Amount must be $500 to $50,000.");
        if (!Number.isInteger(term) || term < 6 || term > 60) throw new Error("Term must be 6 to 60 months.");
        u.loans.push(await encrypt({amt, term, payment: payment(amt, term), status: "Under review"}));
      }
      return {email: c.sub, exp: c.exp, balance: u.balance, loans: await Promise.all(u.loans.map(decrypt)), sample: u.loans[0] || ""};
    }
  };
})();

const payment = (amt, n) => { const r = 0.085 / 12; return Math.round(amt * r / (1 - Math.pow(1 + r, -n)) * 100) / 100; };

/* ---------- Password rules ---------- */
const RULES = [
  ["At least 12 characters", p => p.length >= 12],
  ["A lowercase letter", p => /[a-z]/.test(p)],
  ["An uppercase letter", p => /[A-Z]/.test(p)],
  ["A number", p => /\d/.test(p)],
  ["A symbol", p => /[^A-Za-z0-9]/.test(p)],
  ["No common words (password, 123456, qwerty)", p => !/password|123456|qwerty|letmein/i.test(p)]
];
const rulesEl = $("rules");
RULES.forEach(r => { const li = document.createElement("li"); li.textContent = r[0]; rulesEl.appendChild(li); });
const passwordOk = p => RULES.every(r => r[1](p));
$("pw").addEventListener("input", () => { [...rulesEl.children].forEach((li, i) => li.classList.toggle("ok", RULES[i][1]($("pw").value))); });

/* ---------- UI state ---------- */
let mode = "login", token = null, pendingEmail = "", lastActive = Date.now();
const say = (id, text, cls) => { const el = $(id); el.textContent = text; el.className = "msg " + (cls || ""); };
const emailOk = e => /^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/.test(e);

$("switchBtn").onclick = () => {
  mode = mode === "login" ? "register" : "login";
  $("authTitle").textContent = mode === "login" ? "Sign in" : "Create an account";
  $("authBtn").textContent = mode === "login" ? "Sign in" : "Create account";
  $("switchBtn").textContent = mode === "login" ? "Create an account" : "I have an account";
  $("pw").autocomplete = mode === "login" ? "current-password" : "new-password";
  rulesEl.hidden = mode === "login"; say("authMsg", "");
};

$("authBtn").onclick = async () => {
  const email = $("email").value.trim().toLowerCase(), pw = $("pw").value;
  if (!emailOk(email)) return say("authMsg", "Enter a valid email address.", "err");
  try {
    if (mode === "register") {
      if (!passwordOk(pw)) return say("authMsg", "Your password does not meet every rule below.", "err");
      await Server.register(email, pw);
      $("switchBtn").click(); $("pw").value = "";
      return say("authMsg", "Account created. Sign in to continue.", "ok");
    }
    say("authMsg", "Checking…");
    const code = await Server.login(email, pw);
    pendingEmail = email; $("pw").value = "";
    $("demoCode").textContent = "Demo only: your code is " + code + ". A real site sends it to your phone or authenticator app.";
    $("authView").hidden = true; $("mfaView").hidden = false; $("code").focus();
  } catch (e) { say("authMsg", e.message, "err"); }
};

$("mfaBtn").onclick = async () => {
  const code = $("code").value.trim();
  if (!/^\d{6}$/.test(code)) return say("mfaMsg", "Enter the 6-digit code.", "err");
  try {
    token = await Server.verifyMfa(pendingEmail, code);
    $("code").value = ""; say("mfaMsg", "");
    $("mfaView").hidden = true; $("dash").hidden = false;
    lastActive = Date.now(); await refresh();
  } catch (e) {
    say("mfaMsg", e.message, "err");
    if (/Sign in again/.test(e.message)) { $("mfaView").hidden = true; $("authView").hidden = false; }
  }
};

let tokenExp = 0;
async function refresh(action, data) {
  const r = await Server.api(token, action, data);
  tokenExp = r.exp;
  $("who").textContent = "Signed in as " + r.email;
  $("balance").textContent = money(r.balance);
  const box = $("loans"); box.textContent = "";
  r.loans.forEach(l => {
    const d = document.createElement("div"); d.className = "loan";
    d.textContent = "$" + l.amt.toLocaleString() + " over " + l.term + " months · about $" + l.payment.toFixed(2) + "/month · " + l.status;
    box.appendChild(d);
  });
  if (r.sample) { const m = document.createElement("div"); m.className = "mono"; m.textContent = "Stored encrypted (AES-GCM): " + r.sample.slice(0, 60) + "…"; box.appendChild(m); }
}

$("depBtn").onclick = async () => {
  try { await refresh("deposit", $("dep").value.trim()); $("dep").value = ""; say("depMsg", "Deposit received.", "ok"); }
  catch (e) { say("depMsg", e.message, "err"); endIfExpired(e); }
};
const calc = () => { const a = parseInt($("amt").value, 10), t = parseInt($("term").value, 10);
  $("est").textContent = a >= 500 && a <= 50000 && t >= 6 && t <= 60 ? "Estimated payment: $" + payment(a, t).toFixed(2) + " per month" : ""; };
$("amt").oninput = $("term").oninput = calc;
$("loanBtn").onclick = async () => {
  const amt = parseInt($("amt").value, 10), term = parseInt($("term").value, 10);
  try { await refresh("loan", {amt, term}); say("loanMsg", "Application submitted.", "ok"); $("amt").value = $("term").value = ""; calc(); }
  catch (e) { say("loanMsg", e.message, "err"); endIfExpired(e); }
};

function signOut(note) {
  token = null; $("dash").hidden = true; $("mfaView").hidden = true; $("authView").hidden = false;
  say("authMsg", note || "You have been signed out.", note ? "err" : "ok");
}
const endIfExpired = e => { if (/session/i.test(e.message)) signOut(e.message + ". Sign in again."); };
$("outBtn").onclick = () => signOut();

["click","keydown","touchstart"].forEach(ev => document.addEventListener(ev, () => { lastActive = Date.now(); }, {passive:true}));
setInterval(() => {
  if (!token) return;
  if (Date.now() - lastActive > 300000) return signOut("Signed out after 5 minutes of inactivity.");
  const left = tokenExp * 1000 - Date.now();
  if (left <= 0) return signOut("Your session expired. Sign in again.");
  $("timer").textContent = "Session ends in " + Math.floor(left / 60000) + ":" + String(Math.floor(left / 1000) % 60).padStart(2, "0");
}, 1000);
