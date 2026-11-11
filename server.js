'use strict';
const express = require('express'), helmet = require('helmet'), rl = require('express-rate-limit'),
  jwt = require('jsonwebtoken'), Database = require('better-sqlite3'), crypto = require('crypto'),
  scrypt = require('util').promisify(crypto.scrypt);

const { JWT_SECRET, ENC_KEY, NODE_ENV, PORT = 3000 } = process.env, PROD = NODE_ENV === 'production';
if (!JWT_SECRET || JWT_SECRET.length < 48 || !/^[0-9a-f]{64}$/i.test(ENC_KEY || '')) {
  console.error('Missing secrets. Run `npm run keygen` and put the output in .env'); process.exit(1);
}
const KEY = Buffer.from(ENC_KEY, 'hex'), ISS = 'harbor-sl', AUD = 'harbor-web';

/* ---------- Database: parameterized statements only (SQL injection) ---------- */
const db = new Database('harbor.db'); db.pragma('journal_mode=WAL'); db.pragma('foreign_keys=ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name_enc TEXT NOT NULL, pw TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'customer' CHECK(role IN('customer','officer')),
  balance INTEGER NOT NULL DEFAULT 0 CHECK(balance>=0), failed INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0, last_login INTEGER, prev_login INTEGER);
CREATE TABLE IF NOT EXISTS otps(user_id INTEGER PRIMARY KEY, code TEXT, expires INTEGER, tries INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS revoked(jti TEXT PRIMARY KEY, exp INTEGER);
CREATE TABLE IF NOT EXISTS txns(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), kind TEXT, amount INTEGER, ts INTEGER);
CREATE TABLE IF NOT EXISTS loans(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), amount INTEGER, term INTEGER,
  payment INTEGER, purpose_enc TEXT, status TEXT NOT NULL DEFAULT 'pending', ts INTEGER);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts INTEGER, user_id INTEGER, event TEXT, ip TEXT);`);
setInterval(() => db.prepare('DELETE FROM revoked WHERE exp<?').run(Date.now() / 1000 | 0), 36e5).unref();

/* ---------- Crypto helpers ---------- */
const now = () => Date.now(), sha = x => crypto.createHash('sha256').update(x).digest('hex');
const log = (u, e, ip) => db.prepare('INSERT INTO audit(ts,user_id,event,ip) VALUES(?,?,?,?)').run(now(), u, e, ip);
// AES-256-GCM for personal data at rest (name, loan purpose)
const enc = t => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', KEY, iv),
  d = Buffer.concat([c.update(t, 'utf8'), c.final()]); return Buffer.concat([iv, c.getAuthTag(), d]).toString('base64'); };
const dec = b => { const r = Buffer.from(b, 'base64'), d = crypto.createDecipheriv('aes-256-gcm', KEY, r.subarray(0, 12));
  d.setAuthTag(r.subarray(12, 28)); return Buffer.concat([d.update(r.subarray(28)), d.final()]).toString('utf8'); };
// scrypt (memory-hard, async so it never blocks the event loop) with a unique salt per password
const hashPw = async p => { const s = crypto.randomBytes(16); return s.toString('hex') + ':' + (await scrypt(p, s, 64)).toString('hex'); };
const checkPw = async (p, st) => { const [s, h] = st.split(':'), d = await scrypt(p, Buffer.from(s, 'hex'), 64);
  return crypto.timingSafeEqual(d, Buffer.from(h, 'hex')); };
let DUMMY; hashPw('placeholder').then(h => DUMMY = h); // equalizes timing for unknown emails
const weakPw = (p, e) => p.length < 12 || p.length > 128 || !/[a-z]/.test(p) || !/[A-Z]/.test(p) || !/\d/.test(p) ||
  !/[^A-Za-z0-9]/.test(p) || /password|qwerty|123456|letmein|welcome|admin|harbor|savings/i.test(p) ||
  (e.split('@')[0].length > 3 && p.toLowerCase().includes(e.split('@')[0]));

/* ---------- JWT (HS256, 15 min, pinned algorithm/issuer/audience, revocable by jti) ---------- */
const cookieOpt = { httpOnly: true, secure: PROD, sameSite: 'strict', path: '/' };
const sign = (p, exp) => jwt.sign(p, JWT_SECRET, { algorithm: 'HS256', expiresIn: exp, issuer: ISS, audience: AUD, jwtid: crypto.randomUUID() });
const verify = t => jwt.verify(t, JWT_SECRET, { algorithms: ['HS256'], issuer: ISS, audience: AUD });
const jar = q => Object.fromEntries((q.headers.cookie || '').split(';').map(c => c.trim().split(/=(.*)/s).slice(0, 2)).filter(a => a[0]));

/* ---------- IAM: authentication + role-based access + CSRF check; role is read from DB, never from the token ---------- */
const auth = (...roles) => (q, s, n) => {
  try {
    const c = verify(jar(q).sid || '');
    if (c.scope !== 'access' || db.prepare('SELECT 1 FROM revoked WHERE jti=?').get(c.jti)) throw 0;
    if (q.method !== 'GET' && q.get('x-csrf-token') !== c.csrf) return s.status(403).json({ error: 'Request blocked.' });
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(c.sub);
    if (!u || (roles.length && !roles.includes(u.role))) return s.status(403).json({ error: 'Not permitted.' });
    q.u = u; q.c = c; n();
  } catch { s.status(401).json({ error: 'Please sign in.' }); }
};

/* ---------- App, headers, DDoS controls ---------- */
const app = express(); app.set('trust proxy', PROD ? 1 : false); app.disable('x-powered-by');
if (PROD) app.use((q, s, n) => q.secure ? n() : s.redirect(301, 'https://' + q.headers.host + q.url)); // force HTTPS (MITM)
app.use(helmet({
  contentSecurityPolicy: { useDefaults: false, directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"],
    imgSrc: ["'self'", 'data:'], objectSrc: ["'none'"], frameAncestors: ["'none'"], baseUri: ["'self'"], formAction: ["'self'"],
    ...(PROD ? { upgradeInsecureRequests: [] } : {}) } },
  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true }, referrerPolicy: { policy: 'no-referrer' },
  crossOriginResourcePolicy: { policy: 'same-origin' } }));
const limiter = (limit, extra = {}) => rl({ windowMs: 9e5, limit, standardHeaders: true, legacyHeaders: false, ...extra });
app.use(limiter(300));
const authLimit = limiter(15, { message: { error: 'Too many attempts. Try again later.' } });
app.use('/api', (q, s, n) => { s.set('Cache-Control', 'no-store'); n(); });
app.use('/api', (q, s, n) => q.method === 'GET' || q.is('json') ? n() : s.status(415).json({ error: 'Unsupported request.' }));
app.use(express.json({ limit: '10kb' }));
app.use(express.static('public', { dotfiles: 'ignore', maxAge: '1h' }));

const bad = (s, m = 'Invalid request.', c = 400) => s.status(c).json({ error: m });
const A = f => (q, s, n) => f(q, s, n).catch(n);
const str = (v, max) => typeof v === 'string' ? v.trim().slice(0, max) : '';
const cents = v => /^\d{1,7}(\.\d{1,2})?$/.test(String(v)) ? Math.round(parseFloat(v) * 100) : 0;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

/* ---------- Auth routes ---------- */
app.post('/api/register', authLimit, A(async (q, s) => {
  const b = q.body || {}, name = str(b.name, 80), email = str(b.email, 100).toLowerCase(), pw = typeof b.password === 'string' ? b.password : '';
  if (name.length < 2 || !EMAIL.test(email) || weakPw(pw, email))
    return bad(s, 'Check your details. Passwords need 12+ characters with upper, lower, number and symbol.');
  if (!db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) { // same response either way: no account enumeration
    db.prepare('INSERT INTO users(email,name_enc,pw) VALUES(?,?,?)').run(email, enc(name), await hashPw(pw)); log(null, 'register', q.ip);
  }
  s.status(201).json({ ok: true });
}));

app.post('/api/login', authLimit, A(async (q, s) => {
  const b = q.body || {}, email = str(b.email, 100).toLowerCase(), pw = typeof b.password === 'string' ? b.password.slice(0, 128) : '';
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email), good = await checkPw(pw, u ? u.pw : DUMMY);
  const fail = () => bad(s, 'Sign-in failed. Check your details or try again later.', 401); // one message for every failure
  if (!u || u.locked_until > now()) return fail();
  if (!good) { const f = u.failed + 1; // lockout: 5 failures = 15 minutes
    db.prepare('UPDATE users SET failed=?, locked_until=? WHERE id=?').run(f % 5, f >= 5 ? now() + 9e5 : 0, u.id);
    log(u.id, f >= 5 ? 'locked' : 'login_fail', q.ip); return fail(); }
  db.prepare('UPDATE users SET failed=0 WHERE id=?').run(u.id);
  const code = String(crypto.randomInt(1e6)).padStart(6, '0');
  db.prepare('INSERT OR REPLACE INTO otps(user_id,code,expires,tries) VALUES(?,?,?,0)').run(u.id, sha(code), now() + 3e5);
  if (!PROD) console.log(`[MFA demo] ${email}: ${code}`); // production: send by email/SMS provider here instead
  s.cookie('mfa', sign({ sub: u.id, scope: 'mfa' }, '5m'), { ...cookieOpt, maxAge: 3e5 });
  s.json({ mfa: true, ...(PROD ? {} : { demoCode: code }) });
}));

app.post('/api/mfa', authLimit, (q, s) => {
  let c; try { c = verify(jar(q).mfa || ''); if (c.scope !== 'mfa') throw 0; } catch { return bad(s, 'Code expired. Sign in again.', 401); }
  const o = db.prepare('SELECT * FROM otps WHERE user_id=?').get(c.sub), code = str(q.body && q.body.code, 6);
  if (!o || o.expires < now() || o.tries >= 5) return bad(s, 'Code expired. Sign in again.', 401);
  db.prepare('UPDATE otps SET tries=tries+1 WHERE user_id=?').run(c.sub);
  if (!/^\d{6}$/.test(code) || !crypto.timingSafeEqual(Buffer.from(sha(code)), Buffer.from(o.code))) return bad(s, 'Incorrect code.', 401);
  db.prepare('DELETE FROM otps WHERE user_id=?').run(c.sub);
  db.prepare('UPDATE users SET prev_login=last_login, last_login=? WHERE id=?').run(now(), c.sub);
  s.cookie('sid', sign({ sub: c.sub, scope: 'access', csrf: crypto.randomBytes(24).toString('hex') }, '15m'), { ...cookieOpt, maxAge: 9e5 });
  s.clearCookie('mfa', cookieOpt); log(c.sub, 'login', q.ip); s.json({ ok: true });
});

app.get('/api/me', auth(), (q, s) => s.json({ name: dec(q.u.name_enc), email: q.u.email, role: q.u.role,
  balance: q.u.balance, lastLogin: q.u.prev_login, csrf: q.c.csrf }));
app.post('/api/logout', auth(), (q, s) => {
  db.prepare('INSERT OR IGNORE INTO revoked(jti,exp) VALUES(?,?)').run(q.c.jti, q.c.exp);
  s.clearCookie('sid', cookieOpt); log(q.u.id, 'logout', q.ip); s.json({ ok: true });
});

/* ---------- Savings (integer cents, atomic transactions, ownership enforced in every query) ---------- */
const move = kind => (q, s) => {
  const a = cents(q.body && q.body.amount); if (!a) return bad(s, 'Enter a valid amount.');
  const d = kind === 'deposit' ? a : -a;
  const ok = db.transaction(() => {
    if (!db.prepare('UPDATE users SET balance=balance+? WHERE id=? AND balance+?>=0').run(d, q.u.id, d).changes) return false;
    db.prepare('INSERT INTO txns(user_id,kind,amount,ts) VALUES(?,?,?,?)').run(q.u.id, kind, a, now()); return true; })();
  if (!ok) return bad(s, 'Insufficient funds.');
  log(q.u.id, kind, q.ip); s.json({ balance: db.prepare('SELECT balance FROM users WHERE id=?').get(q.u.id).balance });
};
app.post('/api/deposit', auth(), move('deposit'));
app.post('/api/withdraw', auth(), move('withdraw'));
app.get('/api/transactions', auth(), (q, s) =>
  s.json(db.prepare('SELECT kind,amount,ts FROM txns WHERE user_id=? ORDER BY id DESC LIMIT 8').all(q.u.id)));

/* ---------- Loans (8.5% fixed APR, payment computed server-side) ---------- */
app.post('/api/loans', auth(), (q, s) => {
  const b = q.body || {}, amt = Number(b.amount), n = Number(b.term), purpose = str(b.purpose, 200);
  if (!Number.isInteger(amt) || amt < 500 || amt > 50000 || !Number.isInteger(n) || n < 6 || n > 60 || purpose.length < 3)
    return bad(s, 'Amount $500 to $50,000, term 6 to 60 months, and a purpose are required.');
  if (db.prepare("SELECT COUNT(*) c FROM loans WHERE user_id=? AND status='pending'").get(q.u.id).c >= 3)
    return bad(s, 'You already have 3 pending applications.');
  const r = .085 / 12, pay = Math.round(amt * 100 * r / (1 - Math.pow(1 + r, -n)));
  db.prepare('INSERT INTO loans(user_id,amount,term,payment,purpose_enc,ts) VALUES(?,?,?,?,?,?)').run(q.u.id, amt * 100, n, pay, enc(purpose), now());
  log(q.u.id, 'loan_apply', q.ip); s.status(201).json({ ok: true });
});
app.get('/api/loans', auth(), (q, s) => s.json(db.prepare('SELECT id,amount,term,payment,purpose_enc,status,ts FROM loans WHERE user_id=? ORDER BY id DESC')
  .all(q.u.id).map(({ purpose_enc, ...l }) => ({ ...l, purpose: dec(purpose_enc) }))));

/* ---------- Loan officer role (least privilege; cannot decide their own loan) ---------- */
app.get('/api/officer/loans', auth('officer'), (q, s) => s.json(db.prepare(
  "SELECT l.id,l.amount,l.term,l.purpose_enc,u.email FROM loans l JOIN users u ON u.id=l.user_id WHERE l.status='pending' ORDER BY l.id").all()
  .map(({ purpose_enc, ...l }) => ({ ...l, purpose: dec(purpose_enc) }))));
app.patch('/api/officer/loans/:id', auth('officer'), (q, s) => {
  const st = q.body && q.body.status, id = Number(q.params.id);
  if (!['approved', 'rejected'].includes(st) || !Number.isInteger(id)) return bad(s);
  const ok = db.transaction(() => {
    const l = db.prepare("SELECT * FROM loans WHERE id=? AND status='pending'").get(id); if (!l || l.user_id === q.u.id) return false;
    db.prepare('UPDATE loans SET status=? WHERE id=?').run(st, id);
    if (st === 'approved') { db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(l.amount, l.user_id);
      db.prepare("INSERT INTO txns(user_id,kind,amount,ts) VALUES(?,'loan',?,?)").run(l.user_id, l.amount, now()); }
    return true; })();
  if (!ok) return bad(s, 'Not found.', 404);
  log(q.u.id, `loan_${st}_${id}`, q.ip); s.json({ ok: true });
});

app.use('/api', (q, s) => bad(s, 'Not found.', 404));
app.use((e, q, s, n) => { if (e.type) return bad(s, 'Invalid request.', e.status || 400); console.error(e.message); s.status(500).json({ error: 'Something went wrong.' }); });
const srv = app.listen(PORT, () => console.log('Harbor Savings & Loan on :' + PORT));
srv.headersTimeout = srv.requestTimeout = 15e3; srv.keepAliveTimeout = 5e3; srv.maxHeadersCount = 50; // slow-request (Slowloris) limits