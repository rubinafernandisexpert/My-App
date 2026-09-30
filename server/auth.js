'use strict';
/* ---------------------------------------------------------------------------
   Authentication, sessions and CSRF.

   * Passwords: scrypt (node:crypto) with a per-user random salt.
   * Sessions:  stateless, HMAC-SHA256 signed cookie — survives restarts, no
               session store required. Payload: { sub, iat, exp }.
   * CSRF:      double-submit cookie. `brio_csrf` is readable by JS (by design,
               so fetch() can echo it in X-CSRF-Token) while the session
               cookie stays httpOnly.
   * Login:     in-memory rate limit per IP + email.
   --------------------------------------------------------------------------- */
const crypto = require('crypto');
const db = require('./db');

const SESSION_COOKIE = 'brio_sid';
const CSRF_COOKIE = 'brio_csrf';
const SESSION_DAYS = 7;
const IS_PROD = process.env.NODE_ENV === 'production';

/* ---- session secret ---------------------------------------------------- */
let SECRET = process.env.SESSION_SECRET || '';
if (!SECRET || SECRET.length < 24) {
  if (IS_PROD && process.env.ALLOW_INSECURE_SECRET !== 'true') {
    console.error('\nFATAL: SESSION_SECRET is missing or shorter than 24 characters.');
    console.error('Generate one with:  openssl rand -hex 32\n');
    process.exit(1);
  }
  SECRET = crypto.randomBytes(32).toString('hex');
  if (IS_PROD) console.warn('WARNING: using an ephemeral SESSION_SECRET — all sessions drop on restart.');
}

/* ---- passwords --------------------------------------------------------- */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return 'scrypt$' + salt + '$' + hash;
}

function verifyPassword(password, stored) {
  try {
    const parts = String(stored || '').split('$');
    if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
    const expected = Buffer.from(parts[2], 'hex');
    const actual = crypto.scryptSync(String(password), parts[1], expected.length);
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  } catch (e) {
    return false;
  }
}

/* ---- signed session tokens --------------------------------------------- */
const b64 = (buf) => Buffer.from(buf).toString('base64url');
const sign = (payload) => {
  const body = b64(JSON.stringify(payload));
  return body + '.' + crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
};

function unsign(token) {
  try {
    const [body, mac] = String(token || '').split('.');
    if (!body || !mac) return null;
    const expected = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
    const a = Buffer.from(mac);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

/* ---- cookies ----------------------------------------------------------- */
function parseCookies(req) {
  if (req.cookies) return req.cookies;
  const out = {};
  String(req.headers.cookie || '').split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  req.cookies = out;
  return out;
}

function cookieOptions(maxAgeMs) {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.COOKIE_SECURE === 'true' || IS_PROD,
    path: '/',
    maxAge: maxAgeMs
  };
}

function setSession(res, userId) {
  res.cookie(SESSION_COOKIE, sign({ sub: userId, iat: Date.now(), exp: Date.now() + SESSION_DAYS * 86400000 }),
    cookieOptions(SESSION_DAYS * 86400000));
}

function clearSession(res) {
  res.cookie(SESSION_COOKIE, '', { httpOnly: true, sameSite: 'lax', secure: cookieOptions().secure, path: '/', maxAge: 0 });
}

/* ---- CSRF -------------------------------------------------------------- */
function ensureCsrf(req, res, next) {
  const jar = parseCookies(req);
  if (!jar[CSRF_COOKIE] || jar[CSRF_COOKIE].length < 16) {
    const token = crypto.randomBytes(24).toString('base64url');
    jar[CSRF_COOKIE] = token;
    res.cookie(CSRF_COOKIE, token, {
      httpOnly: false,                       // JS must read it to echo it back
      sameSite: 'lax',
      secure: cookieOptions().secure,
      path: '/',
      maxAge: SESSION_DAYS * 86400000
    });
  }
  res.locals.csrf = jar[CSRF_COOKIE];
  next();
}

const safeEq = (a, b) => {
  const x = Buffer.from(String(a || ''));
  const y = Buffer.from(String(b || ''));
  return x.length === y.length && x.length > 0 && crypto.timingSafeEqual(x, y);
};

/* State-changing requests must present the token twice: in the cookie and in
   either the X-CSRF-Token header, the _csrf body field, or ?csrf= (sendBeacon). */
function checkCsrf(req, res, next) {
  const jar = parseCookies(req);
  const cookie = jar[CSRF_COOKIE];
  const sent = req.get('x-csrf-token') || (req.body && req.body._csrf) || req.query.csrf;
  if (!cookie || !sent || !safeEq(cookie, sent)) {
    return res.status(403).json({ ok: false, error: 'csrf_token_invalid' });
  }
  const origin = req.get('origin');
  if (origin && !req.get('host')) return res.status(403).json({ ok: false, error: 'origin_invalid' });
  if (origin) {
    try {
      const o = new URL(origin);
      const host = req.get('host');
      if (o.host !== host && !/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
        return res.status(403).json({ ok: false, error: 'origin_mismatch' });
      }
    } catch (e) {
      return res.status(403).json({ ok: false, error: 'origin_invalid' });
    }
  }
  next();
}

/* ---- request actors ---------------------------------------------------- */
function currentUser(req) {
  const jar = parseCookies(req);
  const payload = unsign(jar[SESSION_COOKIE]);
  if (!payload) return null;
  return db.findUserById(payload.sub);
}

function optionalAuth(req, res, next) {
  req.user = currentUser(req);
  res.locals.user = req.user;
  next();
}

function wantsJson(req) {
  return req.path.startsWith('/api/') || /application\/json/.test(req.get('accept') || '');
}

function requireAuth(req, res, next) {
  req.user = req.user || currentUser(req);
  if (req.user) { res.locals.user = req.user; return next(); }
  if (wantsJson(req)) return res.status(401).json({ ok: false, error: 'auth_required' });
  const next_ = encodeURIComponent(req.originalUrl || '/library');
  return res.redirect(302, '/login?next=' + next_);
}

/* ---- login throttle ---------------------------------------------------- */
const attempts = new Map();
const WINDOW_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS = 8;

function throttleKey(req, email) {
  return (req.ip || 'unknown') + '|' + String(email || '').toLowerCase();
}

function loginBlocked(req, email) {
  const rec = attempts.get(throttleKey(req, email));
  if (!rec) return false;
  if (Date.now() - rec.first > WINDOW_MS) { attempts.delete(throttleKey(req, email)); return false; }
  return rec.count >= MAX_ATTEMPTS;
}

function noteFailure(req, email) {
  const k = throttleKey(req, email);
  const rec = attempts.get(k);
  if (!rec || Date.now() - rec.first > WINDOW_MS) attempts.set(k, { count: 1, first: Date.now() });
  else rec.count++;
  return Math.max(0, MAX_ATTEMPTS - (attempts.get(k).count || 0));
}

function clearFailures(req, email) {
  attempts.delete(throttleKey(req, email));
}

module.exports = {
  SESSION_COOKIE, CSRF_COOKIE,
  hashPassword, verifyPassword, sign, unsign,
  parseCookies, setSession, clearSession,
  ensureCsrf, checkCsrf, currentUser, optionalAuth, requireAuth,
  loginBlocked, noteFailure, clearFailures
};
