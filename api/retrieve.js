/**
 * Profile Service callback.
 * iOS POSTs application/pkcs7-signature (CMS SignedData with embedded XML plist).
 *
 * CRITICAL for "Invalid Profile" / «ملف التعريف غير صالح»:
 * Working get-UDID tools respond with HTTP 301 Location to a results page.
 * Returning HTML, text, or an unsigned Configuration/WebClip causes iOS to show
 * Profile Installation Failed → Invalid Profile → Try Again.
 *
 * Refs: StackOverflow 13341630 / 5781314, zhangkn/UDIDFromSafari, getudid.co PHP.
 *
 * Use Web Handler + request.arrayBuffer() so Vercel does not destroy the body.
 */
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
    return 'https://ecid-finder.vercel.app';
  }
}

function redirect301(url) {
  return new Response(null, {
    status: 301,
    headers: {
      Location: url,
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
        keys: parsed.keys || [],
        headHex: raw.slice(0, 48).toString('hex'),
        xmlPreview: (parsed.xmlPreview || '').slice(0, 200),
      });
      return redirect301(
        `${origin}/result.html?error=parse&n=${raw.length}`
      );
    }

    console.log(
      JSON.stringify({
        tag: 'retrieve:ok',
        hasEcid: Boolean(parsed.attrs.ECID),
        hasUdid: Boolean(parsed.attrs.UDID),
        product: parsed.attrs.PRODUCT || '',
        keys: parsed.keys || [],
      })
    );

    const token = makeResultToken(parsed.attrs);
    return redirect301(
      `${origin}/result.html?t=${encodeURIComponent(token)}`
    );
  } catch (err) {
    console.error('retrieve:exception', String(err && err.message));
    return redirect301(`${origin}/result.html?error=server`);
  }
}

async function GET() {
  return new Response(
    'Profile Service retrieve endpoint. iOS devices POST PKCS#7 here.\n',
    { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
  );
}

module.exports = { POST, GET };
