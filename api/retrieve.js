const crypto = require('crypto');
const { parseDeviceResponse } = require('../lib/parse-device-response');
const { makeResultToken } = require('../lib/token');

function baseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) {
    return process.env.PUBLIC_BASE_URL.replace(/\/$/, '');
  }
  const proto = (req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
  const host = (req.headers['x-forwarded-host'] || req.headers.host || '')
    .split(',')[0]
    .trim();
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
    if (req.body && typeof req.body === 'object' && !Array.isArray(req.body)) {
      // Unexpected pre-parsed body — cannot recover PKCS#7
      resolve(Buffer.alloc(0));
      return;
    }
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function xmlEscape(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * After Profile Service POST, iOS expects a Configuration .mobileconfig back
 * (Apple OTA docs). A bare 303/HTML redirect produces "Invalid Profile".
 * Return a removable WebClip that opens the signed result page in Safari.
 */
function buildResultConfiguration(resultUrl) {
  const profileUuid = crypto.randomUUID().toUpperCase();
  const clipUuid = crypto.randomUUID().toUpperCase();
  const safeUrl = xmlEscape(resultUrl);
  return (
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n` +
    `<plist version="1.0">\n` +
    `<dict>\n` +
    `\t<key>PayloadContent</key>\n` +
    `\t<array>\n` +
    `\t\t<dict>\n` +
    `\t\t\t<key>PayloadType</key>\n` +
    `\t\t\t<string>com.apple.webClip.managed</string>\n` +
    `\t\t\t<key>PayloadVersion</key>\n` +
    `\t\t\t<integer>1</integer>\n` +
    `\t\t\t<key>PayloadIdentifier</key>\n` +
    `\t\t\t<string>app.ecidfinder.webclip</string>\n` +
    `\t\t\t<key>PayloadUUID</key>\n` +
    `\t\t\t<string>${clipUuid}</string>\n` +
    `\t\t\t<key>PayloadDisplayName</key>\n` +
    `\t\t\t<string>ECID Result</string>\n` +
    `\t\t\t<key>PayloadDescription</key>\n` +
    `\t\t\t<string>Opens your ECID result page. Delete this profile afterward.</string>\n` +
    `\t\t\t<key>PayloadOrganization</key>\n` +
    `\t\t\t<string>ecid-finder.vercel.app</string>\n` +
    `\t\t\t<key>URL</key>\n` +
    `\t\t\t<string>${safeUrl}</string>\n` +
    `\t\t\t<key>Label</key>\n` +
    `\t\t\t<string>ECID Result</string>\n` +
    `\t\t\t<key>IsRemovable</key>\n` +
    `\t\t\t<true/>\n` +
    `\t\t\t<key>FullScreen</key>\n` +
    `\t\t\t<true/>\n` +
    `\t\t</dict>\n` +
    `\t</array>\n` +
    `\t<key>PayloadDisplayName</key>\n` +
    `\t<string>ECID Finder Result</string>\n` +
    `\t<key>PayloadIdentifier</key>\n` +
    `\t<string>app.ecidfinder.result</string>\n` +
    `\t<key>PayloadDescription</key>\n` +
    `\t<string>Shows your ECID. Delete after viewing.</string>\n` +
    `\t<key>PayloadOrganization</key>\n` +
    `\t<string>ecid-finder.vercel.app</string>\n` +
    `\t<key>PayloadRemovalDisallowed</key>\n` +
    `\t<false/>\n` +
    `\t<key>PayloadType</key>\n` +
    `\t<string>Configuration</string>\n` +
    `\t<key>PayloadUUID</key>\n` +
    `\t<string>${profileUuid}</string>\n` +
    `\t<key>PayloadVersion</key>\n` +
    `\t<integer>1</integer>\n` +
    `</dict>\n` +
    `</plist>\n`
  );
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
    const resultUrl = `${origin}/result.html?t=${encodeURIComponent(token)}`;
    const mobileconfig = buildResultConfiguration(resultUrl);

    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/x-apple-aspen-config');
    res.setHeader('Content-Disposition', 'attachment; filename="ecid-result.mobileconfig"');
    res.setHeader('Cache-Control', 'no-store');
    res.end(mobileconfig);
  } catch (err) {
    const msg =
      err && err.message === 'RESULT_HMAC_SECRET is not configured'
        ? 'Server misconfigured (missing RESULT_HMAC_SECRET).'
        : 'Retrieve failed.';
    res.statusCode = 500;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.end(msg);
  }
};

// Ensure Vercel / Next-style runtimes do not JSON-parse the PKCS#7 body
module.exports.config = {
  api: {
    bodyParser: false,
  },
};
