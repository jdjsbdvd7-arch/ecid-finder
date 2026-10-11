/** GET /api/config → capability flags for the UI (no secrets). */
const { sendJson } = require('../lib/http-utils');
const { hasSecret } = require('../lib/secret');

module.exports = async function handler(req, res) {
  const workerUrl = (process.env.WORKER_PUBLIC_URL || '').replace(/\/+$/, '');
  const configured = Boolean(workerUrl) && hasSecret('JOB_HMAC_SECRET');
  sendJson(res, 200, {
    ok: true,
    workerConfigured: configured,
    workerUrl,
    blobEnabled: Boolean(process.env.BLOB_READ_WRITE_TOKEN),
    maxIpaBytes: Number(process.env.MAX_IPA_BYTES || 600 * 1024 * 1024),
    notes: {
      credentials: 'session-only; sent from your browser directly to the signing worker, never stored',
      ipa: 'user-supplied only; uploaded straight to Vercel Blob, fetched once by the worker, then deleted',
    },
  });
};
