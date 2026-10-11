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

/**
 * Profile Service enrollment — dict structure matches working getudid.co /
 * Apple OTA Phase-1 samples exactly:
 * - DOCTYPE "-//Apple Inc//DTD PLIST 1.0//EN"
 * - PayloadContent is a <dict> (NOT array)
 * - Inside PayloadContent: DeviceAttributes array THEN URL (getudid order)
 * - No Challenge (optional; omitting avoids type mismatch string vs data)
 * - Outer keys in getudid order
 * - Tab indentation (Apple / getudid style)
 */
function buildMobileconfig(retrieveUrl) {
  const uuid = crypto.randomUUID().toUpperCase();
  // Exact structural template used by public UDID/ECID Safari tools
  return (
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<!DOCTYPE plist PUBLIC "-//Apple Inc//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n` +
    `<plist version="1.0">\n` +
    `\t<dict>\n` +
    `\t\t<key>PayloadContent</key>\n` +
    `\t\t<dict>\n` +
    `\t\t\t<key>DeviceAttributes</key>\n` +
    `\t\t\t<array>\n` +
    `\t\t\t\t<string>UDID</string>\n` +
    `\t\t\t\t<string>IMEI</string>\n` +
    `\t\t\t\t<string>VERSION</string>\n` +
    `\t\t\t\t<string>PRODUCT</string>\n` +
    `\t\t\t\t<string>SERIAL</string>\n` +
    `\t\t\t\t<string>ECID</string>\n` +
    `\t\t\t</array>\n` +
    `\t\t\t<key>URL</key>\n` +
    `\t\t\t<string>${retrieveUrl}</string>\n` +
    `\t\t</dict>\n` +
    `\t\t<key>PayloadOrganization</key>\n` +
    `\t\t<string>ecid-finder.vercel.app</string>\n` +
    `\t\t<key>PayloadDisplayName</key>\n` +
    `\t\t<string>ECID Finder</string>\n` +
    `\t\t<key>PayloadIdentifier</key>\n` +
    `\t\t<string>app.ecidfinder.profile-service</string>\n` +
    `\t\t<key>PayloadDescription</key>\n` +
    `\t\t<string>Install this temporary profile to find and display your device ECID and UDID. Remove it after viewing the result.</string>\n` +
    `\t\t<key>PayloadType</key>\n` +
    `\t\t<string>Profile Service</string>\n` +
    `\t\t<key>PayloadUUID</key>\n` +
    `\t\t<string>${uuid}</string>\n` +
    `\t\t<key>PayloadVersion</key>\n` +
    `\t\t<integer>1</integer>\n` +
    `\t</dict>\n` +
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
    const retrieveUrl = `${origin}/retrieve`;
    const body = buildMobileconfig(retrieveUrl);

    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/x-apple-aspen-config');
    res.setHeader(
      'Content-Disposition',
      'attachment; filename="ecid-finder.mobileconfig"'
    );
    res.setHeader('Cache-Control', 'no-store');
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
