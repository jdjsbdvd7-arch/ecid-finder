/**
 * Proxy ipsw.me device firmware list (avoids browser CORS).
 * GET /api/firmwares?product=iPhone14,3&signed=1
 */

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.statusCode = 405;
    res.setHeader('Allow', 'GET');
    res.end('Method Not Allowed');
    return;
  }

  const url = new URL(req.url, 'http://localhost');
  const product = (url.searchParams.get('product') || '').trim();
  const signedOnly =
    url.searchParams.get('signed') === '1' ||
    url.searchParams.get('signed') === 'true';

  if (!/^[A-Za-z]+\d+,\d+$/.test(product)) {
    res.statusCode = 400;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.end(JSON.stringify({ ok: false, error: 'invalid_product' }));
    return;
  }

  const upstream = `https://api.ipsw.me/v4/device/${encodeURIComponent(product)}?type=ipsw`;

  try {
    const r = await fetch(upstream, {
      headers: { Accept: 'application/json', 'User-Agent': 'ecid-finder/1.1' },
    });
    if (!r.ok) {
      res.statusCode = 502;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store');
      res.end(
        JSON.stringify({
          ok: false,
          error: 'upstream_http',
          status: r.status,
        })
      );
      return;
    }
    const data = await r.json();
    const all = Array.isArray(data.firmwares) ? data.firmwares : [];
    const firmwares = (signedOnly ? all.filter((f) => f.signed) : all).map(
      (f) => ({
        version: f.version,
        buildid: f.buildid,
        signed: Boolean(f.signed),
        releasedate: f.releasedate || null,
        filesize: f.filesize || null,
        url: f.url || null,
      })
    );

    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'public, s-maxage=300, stale-while-revalidate=600');
    res.end(
      JSON.stringify({
        ok: true,
        product,
        name: data.name || '',
        boardconfig: data.boardconfig || '',
        cpid: data.cpid ?? null,
        signedOnly,
        count: firmwares.length,
        firmwares,
        source: 'https://api.ipsw.me',
      })
    );
  } catch (e) {
    res.statusCode = 502;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.end(
      JSON.stringify({
        ok: false,
        error: 'upstream_fetch',
        message: e && e.message ? String(e.message) : 'fetch failed',
      })
    );
  }
};
