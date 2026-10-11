/**
 * Profile Service callback.
 * iOS POSTs application/pkcs7-signature (CMS SignedData with embedded XML plist).
 *
 * CRITICAL: plain Vercel Node helpers auto-parse some Content-Types and can destroy
 * the binary body. module.exports.config.bodyParser is Next.js-only and does nothing
 * here. Use the Web Handler signature + request.arrayBuffer() for raw bytes.
 *
 * NEVER return text/plain to Profile Service — iOS shows
 * «فشل تثبيت ملف التعريف / حاول العملية مرة أخرى» on 400/500 HTML/text.
 */
const crypto = require('crypto');
const { parseDeviceResponse } = require('../lib/parse-device-response');
const { makeResultToken } = require('../lib/token');

function originFrom(request) {
  if (process.env.PUBLIC_BASE_URL) {
    return process.env.PUBLIC_BASE_URL.replace(/\/$/, '');
  }
  try {
    return new URL(request.url).origin;
  } catch {
    if (process.env.VERCEL_URL) return `https://${process.env.VERCEL_URL}`;
    return '';
  }
}

function xmlEscape(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function buildResultConfiguration(resultUrl, displayName) {
  const profileUuid = crypto.randomUUID().toUpperCase();
  const clipUuid = crypto.randomUUID().toUpperCase();
  const safeUrl = xmlEscape(resultUrl);
  const title = xmlEscape(displayName || 'ECID Result');
  return (
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n` +
    `<plist version="1.0">\n` +
    `<dict>\n` +
    `\t<key>PayloadContent</key>\n` +
    `\t<array>\n` +
    `\t\t<dict>\n` +
    `\t\t\t<key>FullScreen</key>\n` +
    `\t\t\t<true/>\n` +
    `\t\t\t<key>IsRemovable</key>\n` +
    `\t\t\t<true/>\n` +
    `\t\t\t<key>Label</key>\n` +
    `\t\t\t<string>${title}</string>\n` +
    `\t\t\t<key>PayloadDescription</key>\n` +
    `\t\t\t<string>Opens your ECID result page. Delete this profile afterward.</string>\n` +
    `\t\t\t<key>PayloadDisplayName</key>\n` +
    `\t\t\t<string>${title}</string>\n` +
    `\t\t\t<key>PayloadIdentifier</key>\n` +
    `\t\t\t<string>app.ecidfinder.webclip.${clipUuid}</string>\n` +
    `\t\t\t<key>PayloadOrganization</key>\n` +
    `\t\t\t<string>ecid-finder.vercel.app</string>\n` +
    `\t\t\t<key>PayloadType</key>\n` +
    `\t\t\t<string>com.apple.webClip.managed</string>\n` +
    `\t\t\t<key>PayloadUUID</key>\n` +
    `\t\t\t<string>${clipUuid}</string>\n` +
    `\t\t\t<key>PayloadVersion</key>\n` +
    `\t\t\t<integer>1</integer>\n` +
    `\t\t\t<key>Precomposed</key>\n` +
    `\t\t\t<true/>\n` +
    `\t\t\t<key>URL</key>\n` +
    `\t\t\t<string>${safeUrl}</string>\n` +
    `\t\t</dict>\n` +
    `\t</array>\n` +
    `\t<key>PayloadDescription</key>\n` +
    `\t<string>Shows your ECID. Delete after viewing.</string>\n` +
    `\t<key>PayloadDisplayName</key>\n` +
    `\t<string>ECID Finder Result</string>\n` +
    `\t<key>PayloadIdentifier</key>\n` +
    `\t<string>app.ecidfinder.result</string>\n` +
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

function mobileconfigResponse(xml) {
  return new Response(xml, {
    status: 200,
    headers: {
      // No Content-Disposition: some iOS versions are picky on Profile Service replies
      'Content-Type': 'application/x-apple-aspen-config',
      'Cache-Control': 'no-store',
    },
  });
}

async function POST(request) {
  const contentType = request.headers.get('content-type') || '';
  let raw;
  try {
    raw = Buffer.from(await request.arrayBuffer());
  } catch (err) {
    console.error('retrieve:arrayBuffer_failed', String(err && err.message));
    raw = Buffer.alloc(0);
  }

  console.log(
    JSON.stringify({
      tag: 'retrieve',
      contentType,
      bodyBytes: raw.length,
      hasXml: raw.includes(Buffer.from('<?xml')),
      hasPlist: raw.includes(Buffer.from('</plist>')),
      hasBplist: raw.includes(Buffer.from('bplist')),
    })
  );

  const origin = originFrom(request);

  try {
    const parsed = parseDeviceResponse(raw);
    if (!parsed.ok) {
      console.warn('retrieve:parse_failed', {
        error: parsed.error,
        bodyBytes: raw.length,
        contentType,
        headHex: raw.slice(0, 32).toString('hex'),
      });
      // Still return a valid Configuration so iOS does not show retry-failure.
      const errUrl = `${origin}/result.html?error=parse&n=${raw.length}`;
      return mobileconfigResponse(
        buildResultConfiguration(errUrl, 'ECID — Retry')
      );
    }

    console.log(
      JSON.stringify({
        tag: 'retrieve:ok',
        hasEcid: Boolean(parsed.attrs.ECID),
        hasUdid: Boolean(parsed.attrs.UDID),
        product: parsed.attrs.PRODUCT || '',
        challengeLen: (parsed.attrs.Challenge || '').length,
      })
    );

    const token = makeResultToken(parsed.attrs);
    const resultUrl = `${origin}/result.html?t=${encodeURIComponent(token)}`;
    return mobileconfigResponse(buildResultConfiguration(resultUrl, 'ECID Result'));
  } catch (err) {
    console.error('retrieve:exception', String(err && err.message));
    const errUrl = `${origin}/result.html?error=server`;
    return mobileconfigResponse(
      buildResultConfiguration(errUrl, 'ECID — Error')
    );
  }
}

async function GET() {
  return new Response(
    'Profile Service retrieve endpoint. iOS devices POST PKCS#7 here.\n',
    { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
  );
}

module.exports = { POST, GET };
