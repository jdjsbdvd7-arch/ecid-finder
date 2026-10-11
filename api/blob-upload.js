/**
 * POST /api/blob-upload — token handler for Vercel Blob CLIENT uploads of the user's own IPA.
 * The browser sends `Authorization: Bearer <job token from /api/jobs>`; we only hand out a
 * short-lived, path-scoped, size/type-limited client token. The IPA bytes never pass through here.
 */
const { handleUpload } = require('@vercel/blob/client');
const { verifyJobToken } = require('../lib/job-token');
const { hasSecret } = require('../lib/secret');
const { sendJson, readJsonBody } = require('../lib/http-utils');
const { MAX_IPA_BYTES_DEFAULT, UPLOAD_TOKEN_TTL_MS, ALLOWED_CONTENT_TYPES, checkUploadPath } = require('../lib/blob-policy');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return sendJson(res, 405, { ok: false, error: 'method_not_allowed' });
  }
  if (!process.env.BLOB_READ_WRITE_TOKEN || !hasSecret('JOB_HMAC_SECRET')) {
    return sendJson(res, 503, { ok: false, error: 'blob_not_configured' });
  }
  const h = req.headers.authorization || '';
  const v = verifyJobToken(h.startsWith('Bearer ') ? h.slice(7) : '');
  if (!v.ok) return sendJson(res, 401, { ok: false, error: v.error });
  const { jid } = v.payload;

  let body;
  try {
    body = await readJsonBody(req, 8 * 1024);
  } catch (e) {
    return sendJson(res, 400, { ok: false, error: 'bad_json' });
  }
  // Only token generation is served; completion callbacks are not used (no onUploadCompleted).
  if (!body || body.type !== 'blob.generate-client-token') return sendJson(res, 400, { ok: false, error: 'unsupported_event' });
  try {
    const out = await handleUpload({
      request: req,
      body,
      onBeforeGenerateToken: async (pathname) => {
        const p = checkUploadPath(pathname);
        if (!p.ok || p.jid !== jid) throw new Error('path_not_allowed_for_this_job');
        return {
          allowedContentTypes: ALLOWED_CONTENT_TYPES,
          maximumSizeInBytes: Number(process.env.MAX_IPA_BYTES || MAX_IPA_BYTES_DEFAULT),
          validUntil: Date.now() + UPLOAD_TOKEN_TTL_MS,
          addRandomSuffix: true, // unguessable URL
          allowOverwrite: false,
          cacheControlMaxAge: 60,
        };
      },
    });
    return sendJson(res, 200, out);
  } catch (e) {
    const msg = String((e && e.message) || '');
    return sendJson(res, msg.includes('path_not_allowed') ? 403 : 400, { ok: false, error: msg.includes('path_not_allowed') ? 'path_not_allowed' : 'token_failed' });
  }
};
