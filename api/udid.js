/** GET /api/udid?ecid=...&cpid=...&product=... → derives a modern UDID (no state). */
const { deriveUdid, CHIP_CHOICES, cpidForProduct } = require('../lib/udid');
const { sendJson } = require('../lib/http-utils');

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return sendJson(res, 405, { ok: false, error: 'method_not_allowed' });
  }
  const q = new URL(req.url, 'http://localhost').searchParams;
  const out = deriveUdid({ ecid: q.get('ecid'), cpid: q.get('cpid'), udid: q.get('udid'), product: q.get('product') });
  const product = q.get('product') || '';
  const res2 = out.ok
    ? { ok: true, udid: out.udid, cpid: out.cpid, ecidHex: out.ecid && out.ecid.hex, ecidDecimal: out.ecid && out.ecid.decimal, ecidPadded: out.ecid && out.ecid.padded, ambiguous: Boolean(out.ecid && out.ecid.ambiguous), interpretedAs: out.ecid && out.ecid.interpretedAs, source: out.source }
    : out;
  return sendJson(res, out.ok ? 200 : 400, { ...res2, productCpid: cpidForProduct(product), chips: CHIP_CHOICES });
};
