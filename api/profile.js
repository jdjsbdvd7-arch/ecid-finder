const crypto = require('crypto');

function baseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) {
    return process.env.PUBLIC_BASE_URL.replace(/\/$/, '');
  }
  const proto = (req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
  const host = (req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
  if (!host) {
    if (process.env.VERCEL_URL) return `https://${process.env.VERCEL_URL}`;
    throw new Error('Cannot determine public base URL');
  }
  return `${proto}://${host}`;
}

function uuid() {
  return crypto.randomUUID();
}

function buildMobileconfig(retrieveUrl, challenge) {
  // Privacy-minimal DeviceAttributes (no IMEI/ICCID/SERIAL)
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <dict>
    <key>URL</key>
    <string>${retrieveUrl}</string>
    <key>DeviceAttributes</key>
    <array>
      <string>UDID</string>
      <string>ECID</string>
      <string>PRODUCT</string>
      <string>VERSION</string>
    </array>
    <key>Challenge</key>
    <string>${challenge}</string>
  </dict>
  <key>PayloadOrganization</key>
  <string>ECID Finder</string>
  <key>PayloadDisplayName</key>
  <string>ECID Finder (Temporary)</string>
  <key>PayloadIdentifier</key>
  <string>app.ecid-finder.profile-service</string>
  <key>PayloadDescription</key>
  <string>Temporary Profile Service profile. Install in Safari to read ECID/UDID/PRODUCT/VERSION, then remove it from Settings → General → VPN &amp; Device Management.</string>
  <key>PayloadType</key>
  <string>Profile Service</string>
  <key>PayloadUUID</key>
  <string>${uuid()}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
`;
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
    const challenge = uuid();
    const retrieveUrl = `${origin}/api/retrieve`;
    const body = buildMobileconfig(retrieveUrl, challenge);

    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/x-apple-aspen-config');
    res.setHeader(
      'Content-Disposition',
      'attachment; filename="ecid-finder.mobileconfig"'
    );
    res.setHeader('Cache-Control', 'no-store');
    // Help Safari associate the challenge if cookies work during install
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
