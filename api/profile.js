const crypto = require('crypto');

function baseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) {
    return process.env.PUBLIC_BASE_URL.replace(/\/$/, '');
  }
  const proto = (req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
  const host = (req.headers['x-forwarded-host'] || req.headers.host || '')
    .split(',')[0]
    .trim();
  if (!host) {
    if (process.env.VERCEL_URL) return `https://${process.env.VERCEL_URL}`;
    throw new Error('Cannot determine public base URL');
  }
  return `${proto}://${host}`;
}

function uuid() {
  return crypto.randomUUID().toUpperCase();
}

/**
 * Build Profile Service .mobileconfig matching working open-source examples
 * (getudid.co, shaojiankui/iOS-UDID-Safari, Apple OTA ConfigurationProfileExamples).
 * Signing is NOT required for structural validity; unsigned shows a warning.
 */
function buildMobileconfig(retrieveUrl, challenge) {
  // Structure mirrors Apple's Phase-1 Profile Service sample and getudid.co.
  // DeviceAttributes: documented attrs + ECID (returned by many devices / getudid).
  // Challenge is optional but lets us correlate the response.
  return (
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n` +
    `<plist version="1.0">\n` +
    `<dict>\n` +
    `\t<key>PayloadContent</key>\n` +
    `\t<dict>\n` +
    `\t\t<key>URL</key>\n` +
    `\t\t<string>${retrieveUrl}</string>\n` +
    `\t\t<key>DeviceAttributes</key>\n` +
    `\t\t<array>\n` +
    `\t\t\t<string>UDID</string>\n` +
    `\t\t\t<string>ECID</string>\n` +
    `\t\t\t<string>PRODUCT</string>\n` +
    `\t\t\t<string>VERSION</string>\n` +
    `\t\t\t<string>DEVICE_NAME</string>\n` +
    `\t\t</array>\n` +
    `\t\t<key>Challenge</key>\n` +
    `\t\t<string>${challenge}</string>\n` +
    `\t</dict>\n` +
    `\t<key>PayloadOrganization</key>\n` +
    `\t<string>ecid-finder.vercel.app</string>\n` +
    `\t<key>PayloadDisplayName</key>\n` +
    `\t<string>ECID Finder</string>\n` +
    `\t<key>PayloadVersion</key>\n` +
    `\t<integer>1</integer>\n` +
    `\t<key>PayloadUUID</key>\n` +
    `\t<string>${uuid()}</string>\n` +
    `\t<key>PayloadIdentifier</key>\n` +
    `\t<string>app.ecidfinder.profile-service</string>\n` +
    `\t<key>PayloadDescription</key>\n` +
    `\t<string>Temporary profile to read ECID and UDID. Remove it after viewing the result.</string>\n` +
    `\t<key>PayloadType</key>\n` +
    `\t<string>Profile Service</string>\n` +
    `</dict>\n` +
    `</plist>\n`
  );
}

module.exports = async function handler(req, res) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.statusCode = 405;
    res.setHeader('Allow', 'GET, HEAD');
    res.end('Method Not Allowed');
    return;
  }

  try {
    const origin = baseUrl(req);
    const challenge = crypto.randomUUID();
    // Use /retrieve rewrite path (no /api) — some older notes prefer extension-less URLs
    const retrieveUrl = `${origin}/retrieve`;
    const body = buildMobileconfig(retrieveUrl, challenge);

    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/x-apple-aspen-config');
    res.setHeader('Content-Disposition', 'attachment; filename="ecid-finder.mobileconfig"');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader(
      'Set-Cookie',
      `ecid_chal=${challenge}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=None`
    );
    if (req.method === 'HEAD') {
      res.end();
      return;
    }
    res.end(body);
  } catch (err) {
    res.statusCode = 500;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.end('Failed to build profile.');
  }
};
