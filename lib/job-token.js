/**
 * Short-lived HMAC job tokens shared by the website (mints) and the signing worker (verifies).
 * Payload: { v, typ:'job', jid, udid, name, exp }.
 * The secret is JOB_HMAC_SECRET (>=16 chars); there is no built-in default.
 */
const crypto = require('crypto');
const { requireSecret } = require('./secret');

const JOB_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours to finish upload + signing

function b64(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
}

function mac(body) {
  return crypto.createHmac('sha256', requireSecret('JOB_HMAC_SECRET')).update('ecid-finder/job/v1\n' + body).digest('base64url');
}

function newJobId() {
  return crypto.randomBytes(12).toString('hex');
}

function mintJobToken({ jid, udid, name }, ttlMs = JOB_TTL_MS) {
  const body = b64({ v: 1, typ: 'job', jid, udid, name: name || '', exp: Date.now() + ttlMs });
  return `${body}.${mac(body)}`;
}

function verifyJobToken(token) {
  if (typeof token !== 'string' || token.length > 2048 || !token.includes('.')) return { ok: false, error: 'missing_token' };
  const [body, sig] = token.split('.');
  const expected = mac(body);
  const a = Buffer.from(sig || '');
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { ok: false, error: 'bad_signature' };
  let p;
  try {
    p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch (_) {
    return { ok: false, error: 'bad_payload' };
  }
  if (!p || p.typ !== 'job' || p.v !== 1 || typeof p.jid !== 'string' || typeof p.udid !== 'string') {
    return { ok: false, error: 'bad_payload' };
  }
  if (typeof p.exp !== 'number' || Date.now() > p.exp) return { ok: false, error: 'expired' };
  return { ok: true, payload: p };
}

module.exports = { mintJobToken, verifyJobToken, newJobId, JOB_TTL_MS };
