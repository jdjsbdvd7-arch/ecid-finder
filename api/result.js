const { verifyToken } = require('../lib/token');
const {
  normalizeEcid,
  ecidFromUdid,
} = require('../lib/parse-device-response');

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.statusCode = 405;
    res.end('Method Not Allowed');
    return;
  }

  const url = new URL(req.url, 'http://localhost');
  const token = url.searchParams.get('t') || '';
  let verified;
  try {
    verified = verifyToken(token);
  } catch {
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ ok: false, error: 'server_misconfigured' }));
    return;
  }

  if (!verified.ok) {
    res.statusCode = 400;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store');
    res.end(JSON.stringify({ ok: false, error: verified.error }));
    return;
  }

  const p = verified.payload;
  let rawEcid = p.ecid || '';
  let ecidSource = p.ecidSource || '';
  if (!rawEcid && p.udid) {
    const derived = ecidFromUdid(p.udid);
    if (derived) {
      rawEcid = derived;
      ecidSource = 'udid';
    }
  }
  const ecid = normalizeEcid(rawEcid);
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(
    JSON.stringify({
      ok: true,
      ecidHex: ecid ? ecid.hex : '',
      ecidDecimal: ecid ? ecid.decimal : '',
      ecidPadded16: ecid ? ecid.padded16 || '' : '',
      ecidSource: ecidSource || (ecid ? 'attribute' : ''),
      udid: p.udid || '',
      product: p.product || '',
      version: p.version || '',
    })
  );
};
