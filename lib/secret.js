const crypto = require('crypto');

const ephemeral = new Map();

/**
 * Returns the HMAC secret from env. Never uses a hardcoded default.
 * Outside production (no VERCEL / NODE_ENV!=production) a random per-process secret is used
 * so local development works; such tokens die with the process.
 */
function requireSecret(name) {
  const v = process.env[name];
  if (v && v.length >= 16) return v;
  const prod = process.env.NODE_ENV === 'production' || process.env.VERCEL || process.env.ECID_REQUIRE_SECRETS === '1';
  if (prod) {
    const err = new Error(`${name} is not configured`);
    err.code = 'SECRET_MISSING';
    throw err;
  }
  if (!ephemeral.has(name)) ephemeral.set(name, crypto.randomBytes(32).toString('hex'));
  return ephemeral.get(name);
}

function hasSecret(name) {
  const v = process.env[name];
  return Boolean(v && v.length >= 16);
}

module.exports = { requireSecret, hasSecret };
