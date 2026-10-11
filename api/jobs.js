/**
 * POST /api/jobs  { ecid, cpid?, udid?, product?, deviceName? }
 * Validates the manually-entered device identifiers, derives the UDID and mints a short-lived
 * job token. The browser then sends the IPA and the Apple sign-in DIRECTLY to the signing worker;
 * this serverless function never receives an IPA, an Apple ID or a password.
 */
const { deriveUdid } = require('../lib/udid');
const { mintJobToken, newJobId } = require('../lib/job-token');
const { hasSecret } = require('../lib/secret');
const { sendJson, readJsonBody } = require('../lib/http-utils');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return sendJson(res, 405, { ok: false, error: 'method_not_allowed' });
  }
  const workerUrl = (process.env.WORKER_PUBLIC_URL || '').replace(/\/+$/, '');
  if (!hasSecret('JOB_HMAC_SECRET') && (process.env.VERCEL || process.env.NODE_ENV === 'production')) {
    return sendJson(res, 503, { ok: false, error: 'worker_not_configured', message: 'JOB_HMAC_SECRET is not set on this deployment.' });
  }
  if (process.env.VERCEL && !workerUrl) {
    return sendJson(res, 503, {
      ok: false,
      error: 'worker_not_configured',
      message: 'No signing worker is connected (WORKER_PUBLIC_URL unset). See README → Signing worker.',
    });
  }
  let body;
  try {
    body = await readJsonBody(req);
  } catch (e) {
    return sendJson(res, e.code === 'TOO_LARGE' ? 413 : 400, { ok: false, error: e.code === 'TOO_LARGE' ? 'too_large' : 'bad_json' });
  }
  const d = deriveUdid({ ecid: body.ecid, cpid: body.cpid, udid: body.udid, product: body.product });
  if (!d.ok) return sendJson(res, 400, d);
  const deviceName = String(body.deviceName || 'ECID Finder device').replace(/[^\p{L}\p{N} ._\-]/gu, '').slice(0, 40) || 'ECID Finder device';
  const jid = newJobId();
  let token;
  try {
    token = mintJobToken({ jid, udid: d.udid, name: deviceName });
  } catch (e) {
    return sendJson(res, 503, { ok: false, error: 'worker_not_configured', message: String(e.message) });
  }
  return sendJson(res, 200, {
    ok: true,
    jobId: jid,
    token,
    udid: d.udid,
    cpid: d.cpid,
    ecid: d.ecid ? { hex: d.ecid.hex, decimal: d.ecid.decimal, padded: d.ecid.padded, ambiguous: d.ecid.ambiguous } : null,
    udidSource: d.source,
    legacyUdid: d.cpid === null,
    workerUrl, // '' = same origin (worker serves this page itself)
  });
};
