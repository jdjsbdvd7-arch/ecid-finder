/**
 * GET /api/blob-sweep — daily Vercel Cron: delete any ipa/* blob older than 3 hours
 * (abandoned uploads). Vercel sends `Authorization: Bearer $CRON_SECRET`.
 */
const crypto = require('crypto');
const { list, del } = require('@vercel/blob');
const { sendJson } = require('../lib/http-utils');

const MAX_AGE_MS = 3 * 60 * 60 * 1000;

function okAuth(req) {
  const secret = process.env.CRON_SECRET;
  if (!secret || secret.length < 16) return false;
  const got = Buffer.from(req.headers.authorization || '');
  const want = Buffer.from('Bearer ' + secret);
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}

module.exports = async function handler(req, res) {
  if (!okAuth(req)) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
  if (!process.env.BLOB_READ_WRITE_TOKEN) return sendJson(res, 503, { ok: false, error: 'blob_not_configured' });
  try {
    let deleted = 0;
    let cursor;
    const cutoff = Date.now() - MAX_AGE_MS;
    do {
      const page = await list({ prefix: 'ipa/', cursor, limit: 200 });
      const old = page.blobs.filter((b) => new Date(b.uploadedAt).getTime() < cutoff).map((b) => b.url);
      if (old.length) {
        await del(old);
        deleted += old.length;
      }
      cursor = page.hasMore ? page.cursor : undefined;
    } while (cursor);
    return sendJson(res, 200, { ok: true, deleted });
  } catch (e) {
    return sendJson(res, 502, { ok: false, error: 'sweep_failed' });
  }
};
