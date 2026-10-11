const crypto = require('crypto');

const TTL_MS = 10 * 60 * 1000; // 10 minutes

function getSecret() {
  const secret = process.env.RESULT_HMAC_SECRET;
  if (!secret || secret.length < 16) {
    throw new Error('RESULT_HMAC_SECRET is not configured');
  }
  return secret;
}

function signPayload(payload) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', getSecret()).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) {
    return { ok: false, error: 'missing_token' };
  }
  const [body, sig] = token.split('.');
  if (!body || !sig) return { ok: false, error: 'bad_token' };
  const expected = crypto.createHmac('sha256', getSecret()).update(body).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, error: 'bad_signature' };
  }
  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return { ok: false, error: 'bad_payload' };
  }
  if (!payload || typeof payload.exp !== 'number' || Date.now() > payload.exp) {
    return { ok: false, error: 'expired' };
  }
  return { ok: true, payload };
}

function makeResultToken(attrs) {
  return signPayload({
    ecid: attrs.ECID || '',
    udid: attrs.UDID || '',
    product: attrs.PRODUCT || '',
    version: attrs.VERSION || '',
    exp: Date.now() + TTL_MS,
  });
}

module.exports = { makeResultToken, verifyToken, TTL_MS };
