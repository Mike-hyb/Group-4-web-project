'use strict';
// All server text is written with textContent only, so injected HTML or script can never run (XSS).
const $ = id => document.getElementById(id);
const fmt = c => (c / 100).toLocaleString('en-US', { style: 'currency', currency: 'USD' });
const when = t => new Date(t).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });
let csrf = '', mode = 'in', idle;
const views = ['homeView', 'authView', 'mfaView', 'dashView'];
const show = v => { views.forEach(x => $(x).hidden = x !== v); $('navSign').textContent = csrf ? 'Sign out' : 'Sign in'; window.scrollTo(0, 0); };
const say = (id, t, ok) => { const m = $(id); m.textContent = t || ''; m.className = 'msg' + (ok ? ' ok' : ''); };

async function api(path, method = 'GET', body) {
  const r = await fetch('/api' + path, { method, credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: method === 'GET' ? undefined : JSON.stringify(body || {}) });
  const d = await r.json().catch(() => ({}));
  if (r.status === 401 && csrf && path !== '/logout') { out('Your session has expired. Please sign in again.'); }
  if (!r.ok) throw new Error(d.error || 'Request failed.');
  return d;
}
async function out(msg) {
  try { await api('/logout', 'POST'); } catch {}
  csrf = ''; clearTimeout(idle); setMode('in'); say('authMsg', msg || 'You have been signed out.', true);
}
const bump = () => { clearTimeout(idle); if (csrf) idle = setTimeout(() => out('You were signed out after 5 minutes of inactivity.'), 3e5); };
['click', 'keydown', 'touchstart'].forEach(e => addEventListener(e, bump, { passive: true }));

/* Navigation */
document.querySelectorAll('[data-go]').forEach(b => b.onclick = () => {
  if (csrf) return; show('homeView'); setTimeout(() => $(b.dataset.go).scrollIntoView(), 0); });
$('navSign').onclick = () => csrf ? out() : setMode('in');
$('heroOpen').onclick = () => setMode('up');

/* Sign in / register */
const RULES = [['12+ characters', p => p.length >= 12], ['Upper and lower case', p => /[a-z]/.test(p) && /[A-Z]/.test(p)],
  ['A number', p => /\d/.test(p)], ['A symbol', p => /[^A-Za-z0-9]/.test(p)], ['No common words', p => !/password|qwerty|123456|letmein|welcome|admin|harbor|savings/i.test(p)]];
RULES.forEach(([t]) => { const li = document.createElement('li'); li.textContent = t; $('rules').append(li); });
$('pw').oninput = () => RULES.forEach(([, f], i) => $('rules').children[i].classList.toggle('met', f($('pw').value)));
function setMode(m) {
  mode = m; const up = m === 'up';
  $('authTitle').textContent = up ? 'Create your account' : 'Sign in'; $('nameRow').hidden = !up; $('rules').hidden = !up;
  $('authBtn').textContent = up ? 'Create account' : 'Sign in'; $('switchBtn').textContent = up ? 'I already have an account' : 'Create an account';
  $('pw').autocomplete = up ? 'new-password' : 'current-password'; say('authMsg', ''); show('authView');
}
$('switchBtn').onclick = () => setMode(mode === 'in' ? 'up' : 'in');
$('authForm').onsubmit = async e => {
  e.preventDefault(); const b = $('authBtn'); b.disabled = true;
  try {
    const email = $('email').value, password = $('pw').value;
    if (mode === 'up') { await api('/register', 'POST', { name: $('name').value, email, password });
      $('pw').value = ''; setMode('in'); say('authMsg', 'Account request received. Sign in to continue.', true); }
    else { const d = await api('/login', 'POST', { email, password }); $('pw').value = '';
      $('demoCode').textContent = d.demoCode ? 'Demo only: your code is ' + d.demoCode : ''; say('mfaMsg', ''); show('mfaView'); }
  } catch (err) { say('authMsg', err.message); } finally { b.disabled = false; }
};
$('mfaForm').onsubmit = async e => {
  e.preventDefault();
  try { await api('/mfa', 'POST', { code: $('code').value }); $('code').value = ''; await enter(); }
  catch (err) { say('mfaMsg', err.message); }
};

/* Dashboard */
const li = (ul, ...parts) => { const e = document.createElement('li'); parts.forEach(t => { const s = document.createElement('span'); s.textContent = t; e.append(s); }); ul.append(e); };
async function enter() {
  const me = await api('/me'); csrf = me.csrf;
  $('who').textContent = 'Welcome, ' + me.name;
  $('lastSeen').textContent = me.lastLogin ? 'Last sign-in: ' + when(me.lastLogin) + '. If this was not you, change your password.' : 'This is your first sign-in.';
  show('dashView'); bump(); refresh(me.balance);
}
async function refresh(bal) {
  if (bal === undefined) bal = (await api('/me')).balance; $('balance').textContent = fmt(bal);
  const [t, l] = await Promise.all([api('/transactions'), api('/loans')]);
  $('txns').replaceChildren(); t.forEach(x => li($('txns'), x.kind[0].toUpperCase() + x.kind.slice(1) + ' · ' + when(x.ts), (x.kind === 'withdraw' ? '-' : '+') + fmt(x.amount)));
  $('loans').replaceChildren(); l.forEach(x => li($('loans'), fmt(x.amount) + ' · ' + x.term + ' mo · ' + fmt(x.payment) + '/mo', x.status[0].toUpperCase() + x.status.slice(1)));
}
const money = kind => async () => {
  try { const d = await api('/' + kind, 'POST', { amount: $('amount').value }); $('amount').value = ''; say('moveMsg', 'Done.', true); refresh(d.balance); }
  catch (e) { say('moveMsg', e.message); }
};
$('depBtn').onclick = money('deposit'); $('wdBtn').onclick = money('withdraw');
$('loanForm').onsubmit = async e => {
  e.preventDefault();
  try { await api('/loans', 'POST', { amount: $('amt').value, term: $('term').value, purpose: $('purpose').value });
    ['amt', 'term', 'purpose'].forEach(i => $(i).value = ''); say('loanMsg', 'Application submitted.', true); $('est').textContent = ''; refresh(); }
  catch (err) { say('loanMsg', err.message); }
};
const pmt = (a, n) => { const r = .085 / 12; return a * r / (1 - Math.pow(1 + r, -n)); };
const estimate = () => { const a = +$('amt').value, n = +$('term').value;
  $('est').textContent = a >= 500 && a <= 50000 && n >= 6 && n <= 60 ? 'Estimated payment: ' + fmt(pmt(a, n) * 100) + ' per month' : ''; };
$('amt').oninput = $('term').oninput = estimate;

/* Home calculator */
const calc = () => { const a = +$('cAmt').value, n = +$('cTerm').value, p = pmt(a, n);
  $('cAmtOut').textContent = fmt(a * 100); $('cTermOut').textContent = n + ' months'; $('cPay').textContent = fmt(p * 100); $('cInt').textContent = fmt((p * n - a) * 100); };
$('cAmt').oninput = $('cTerm').oninput = calc; calc();

/* Restore an existing session on page load */
api('/me').then(enter).catch(() => show('homeView'));