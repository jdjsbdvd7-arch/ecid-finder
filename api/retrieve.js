const { parseDeviceResponse } = require('../lib/parse-device-response');
const { makeResultToken } = require('../lib/token');

function baseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) {
    return process.env.PUBLIC_BASE_URL.replace(/\/$/, '');
  }
  const proto = (req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
  const host = (req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
  if (host) return `${proto}://${host}`;
  if (process.env.VERCEL_URL) return `https://${process.env.VERCEL_URL}`;
  return '';
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    if (Buffer.isBuffer(req.body)) {
      resolve(req.body);
      return;
    }
    if (typeof req.body === 'string') {
      resolve(Buffer.from(req.body, 'latin1'));
      return;
    }
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.statusCode = 405;
    res.setHeader('Allow', 'POST');
    res.end('Method Not Allowed');
    return;
  }

  try {
    const raw = await readRawBody(req);
    const parsed = parseDeviceResponse(raw);
    if (!parsed.ok) {
      res.statusCode = 400;
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.end('Could not parse device response.');
      return;
    }

    const token = makeResultToken(parsed.attrs);
    const origin = baseUrl(req);
    const loc = `${origin}/result.html?t=${encodeURIComponent(token)}`;

    // Safari follows redirect after Profile Service POST on many iOS versions.
    res.statusCode = 303;
    res.setHeader('Location', loc);
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(
      `<!doctype html><meta http-equiv="refresh" content="0;url=${loc}"><a href="${loc}">Continue</a>`
    );
  } catch (err) {
    const msg = err && err.message === 'RESULT_HMAC_SECRET is not configured'
      ? 'Server misconfigured (missing RESULT_HMAC_SECRET).'
      : 'Retrieve failed.';
    res.statusCode = 500;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.end(msg);
  }
};

// Ensure Vercel does not try to JSON-parse the PKCS#7 body
module.exports.config = {
  api: {
    bodyParser: false,
  },
};
