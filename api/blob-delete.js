/**
 * POST /api/blob-delete — delete every Blob under ipa/<jobId>/ (the user's uploaded IPA).
 * Auth: Bearer job token. Called by the wizard right after the worker has fetched the file,
 * and again on "wipe". api/blob-sweep.js is the safety net for abandoned uploads.
 */
const { list, del } = require('@vercel/blob');
const { verifyJobToken } = require('../lib/job-token');
const { sendJson } = require('../lib/http-utils');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return sendJson(res, 405, { ok: false, error: 'method_not_allowed' });
  }
  if (!process.env.BLOB_READ_WRITE_TOKEN) return sendJson(res, 503, { ok: false, error: 'blob_not_configured' });
  const h = req.headers.authorization || '';
  let v;
  try {
    v = verifyJobToken(h.startsWith('Bearer ') ? h.slice(7) : '');
  } catch (e) {
    return sendJson(res, 503, { ok: false, error: 'not_configured' });
  }
  if (!v.ok) return sendJson(res, 401, { ok: false, error: v.error });
  try {
    let deleted = 0;
    let cursor;
    do {
      const page = await list({ prefix: `ipa/${v.payload.jid}/`, cursor, limit: 100 });
      if (page.blobs.length) {
        await del(page.blobs.map((b) => b.url));
        deleted += page.blobs.length;
      }
      cursor = page.hasMore ? page.cursor : undefined;
    } while (cursor);
    return sendJson(res, 200, { ok: true, deleted });
  } catch (e) {
    return sendJson(res, 502, { ok: false, error: 'blob_delete_failed' });
  }
};
