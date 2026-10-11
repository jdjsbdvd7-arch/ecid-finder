/**
 * Combined device card + signed firmware snapshot.
 * GET /api/device-report?product=iPhone14,3&udid=...&version=...&ecidHex=...&ecidDecimal=...
 */

const { buildDeviceCard } = require('../lib/device-info');
const { normalizeEcid } = require('../lib/parse-device-response');

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.statusCode = 405;
    res.end('Method Not Allowed');
    return;
  }

  const url = new URL(req.url, 'http://localhost');
  const product = (url.searchParams.get('product') || '').trim();
  const udid = (url.searchParams.get('udid') || '').trim();
  const version = (url.searchParams.get('version') || '').trim();
  let ecidHex = (url.searchParams.get('ecidHex') || '').trim();
  let ecidDecimal = (url.searchParams.get('ecidDecimal') || '').trim();
  const norm = normalizeEcid(ecidHex || ecidDecimal);
  if (norm) {
    ecidHex = norm.hex;
    ecidDecimal = norm.decimal;
  }

  const card = buildDeviceCard({
    product,
    udid,
    version,
    ecidHex,
    ecidDecimal,
  });

  let firmwares = [];
  let firmwareMeta = { ok: false };
  if (/^[A-Za-z]+\d+,\d+$/.test(product)) {
    try {
      const upstream = `https://api.ipsw.me/v4/device/${encodeURIComponent(product)}?type=ipsw`;
      const r = await fetch(upstream, {
        headers: { Accept: 'application/json', 'User-Agent': 'ecid-finder/1.1' },
      });
      if (r.ok) {
        const data = await r.json();
        const all = Array.isArray(data.firmwares) ? data.firmwares : [];
        firmwares = all
          .filter((f) => f.signed)
          .map((f) => ({
            version: f.version,
            buildid: f.buildid,
            signed: true,
            releasedate: f.releasedate || null,
            filesize: f.filesize || null,
            url: f.url || null,
          }));
        firmwareMeta = {
          ok: true,
          name: data.name || '',
          boardconfig: data.boardconfig || '',
          cpid: data.cpid ?? null,
          source: 'https://api.ipsw.me',
        };
        if (!card.marketingName || card.marketingName === product) {
          if (data.name) {
            card.marketingName = data.name;
            card.marketingNameAr = data.name;
          }
        }
      } else {
        firmwareMeta = { ok: false, error: 'upstream_http', status: r.status };
      }
    } catch (e) {
      firmwareMeta = {
        ok: false,
        error: 'upstream_fetch',
        message: e && e.message ? String(e.message) : 'fetch failed',
      };
    }
  } else if (product) {
    firmwareMeta = { ok: false, error: 'invalid_product' };
  } else {
    firmwareMeta = { ok: false, error: 'missing_product' };
  }

  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(
    JSON.stringify({
      ok: true,
      device: card,
      signedFirmwares: firmwares,
      firmwareMeta,
      disclaimer: {
        en: 'Research helper only. Signing status comes from a public third-party API and can change without notice. Not medical, legal, or Apple-official advice.',
        ar: 'مساعد بحثي فقط. حالة التوقيع من واجهة عامة لطرف ثالث وقد تتغير دون إشعار. ليست نصيحة طبية أو قانونية أو رسمية من أبل.',
      },
    })
  );
};
