const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

const data = fs.mkdtempSync(path.join(os.tmpdir(), 'ecid-worker-'));
process.env.ECID_WORKER_DATA = data;
process.env.JOB_HMAC_SECRET = 'e2e-secret-0123456789abcdef0123';
process.env.ECID_SIGNER_BIN = path.join(__dirname, 'fake-signer.js');
process.env.ALLOWED_ORIGINS = 'https://ecid-finder.vercel.app';
process.env.MAX_IPA_BYTES = String(5 * 1024 * 1024);
process.env.ECID_TEST_ALLOW_LOOPBACK_INGEST = '1';

const { server } = require('../server');
const { makeIpa } = require('../../test/helpers');
const { parsePlist } = require('../../lib/plist-lite');

let base;
test.before(() => new Promise((r) => server.listen(0, '127.0.0.1', () => { base = `http://127.0.0.1:${server.address().port}`; r(); })));
test.after(() => { server.close(); fs.rmSync(data, { recursive: true, force: true }); });

const j = async (method, url, { token, body, headers } = {}) => {
  const r = await fetch(base + url, { method, headers: { ...(token ? { Authorization: 'Bearer ' + token } : {}), ...(body && !Buffer.isBuffer(body) ? { 'Content-Type': 'application/json' } : {}), ...headers }, body: body && !Buffer.isBuffer(body) ? JSON.stringify(body) : body });
  const t = await r.text();
  try { return { status: r.status, json: JSON.parse(t), headers: r.headers }; } catch { return { status: r.status, text: t, headers: r.headers }; }
};
const poll = async (jid, token, pred) => { for (let i = 0; i < 100; i++) { const r = await j('GET', `/jobs/${jid}`, { token }); if (pred(r.json.job)) return r.json.job; await new Promise((x) => setTimeout(x, 50)); } throw new Error('poll timeout'); };

test('full pipeline with test signer', async () => {
  const mint = await j('POST', '/api/jobs', { body: { ecid: '0x1965E62213801E', cpid: '8110', deviceName: 'My iPhone' } });
  assert.equal(mint.status, 200, JSON.stringify(mint));
  assert.equal(mint.json.udid, '00008110-001965E62213801E');
  const { jobId, token } = mint.json;

  // auth required
  assert.equal((await j('GET', `/jobs/${jobId}`)).status, 401);
  const other = (await j('POST', '/api/jobs', { body: { ecid: '5', cpid: '8110' } })).json;
  assert.equal((await j('GET', `/jobs/${jobId}`, { token: other.token })).status, 403);

  // garbage upload rejected
  let r = await j('PUT', `/jobs/${jobId}/ipa`, { token, body: Buffer.from('not an ipa at all, just text'), headers: { 'Content-Type': 'application/octet-stream' } });
  assert.equal(r.status, 422); assert.equal(r.json.error, 'not_zip');

  // oversize rejected
  r = await j('PUT', `/jobs/${jobId}/ipa`, { token, body: Buffer.alloc(6 * 1024 * 1024), headers: { 'Content-Type': 'application/octet-stream' } });
  assert.equal(r.status, 413);

  // signing before upload refused
  r = await j('POST', `/jobs/${jobId}/sign`, { token, body: { email: 'a@b.co', password: 'test-password', confirm: true } });
  assert.equal(r.status, 409);

  // good upload
  r = await j('PUT', `/jobs/${jobId}/ipa`, { token, body: makeIpa(), headers: { 'Content-Type': 'application/octet-stream' } });
  assert.equal(r.status, 200, JSON.stringify(r));
  assert.equal(r.json.job.ipa.bundleId, 'com.example.hello');

  // must confirm
  r = await j('POST', `/jobs/${jobId}/sign`, { token, body: { email: 'a@b.co', password: 'test-password' } });
  assert.equal(r.status, 400);

  // wrong password → error state, then retry works
  r = await j('POST', `/jobs/${jobId}/sign`, { token, body: { email: 'a@b.co', password: 'wrong-pass', confirm: true } });
  assert.equal(r.status, 202);
  let job = await poll(jobId, token, (x) => x.status === 'error');
  assert.equal(job.error.code, 'apple_login_failed');
  assert.ok(!JSON.stringify(job).includes('wrong-pass'), 'password must be redacted from errors');

  r = await j('POST', `/jobs/${jobId}/sign`, { token, body: { email: 'a@b.co', password: 'test-password', confirm: true } });
  assert.equal(r.status, 202);
  job = await poll(jobId, token, (x) => x.stage === 'need_2fa');
  assert.ok(job.twofa);
  assert.equal((await j('POST', `/jobs/${jobId}/2fa`, { token, body: { action: 'code', code: 'abc' } })).status, 400);
  assert.equal((await j('POST', `/jobs/${jobId}/2fa`, { token, body: { action: 'code', code: '123456' } })).status, 200);
  job = await poll(jobId, token, (x) => x.status === 'ready');
  assert.equal(job.team.id, 'TESTTEAM00');
  assert.ok(job.install.manifestUrl.includes('/ota/'));
  assert.equal(job.install.https, false); // local http: UI must warn

  // credentials never persisted
  const onDisk = fs.readFileSync(path.join(data, 'jobs', jobId, 'job.json'), 'utf8');
  assert.ok(!onDisk.includes('test-password') && !onDisk.includes('a@b.co'));
  assert.ok(!fs.existsSync(path.join(data, 'jobs', jobId, 'upload.ipa')), 'original upload removed after signing');

  // OTA endpoints
  const iid = job.install.manifestUrl.split('/')[4];
  const man = await j('GET', `/ota/${iid}/manifest.plist`);
  assert.equal(man.status, 200);
  assert.match(man.headers.get('content-type'), /text\/xml/);
  const parsed = parsePlist(man.text);
  assert.equal(parsed.items[0].metadata['bundle-identifier'], 'com.example.hello');
  assert.equal(parsed.items[0].assets[0].url, `${base}/ota/${iid}/app.ipa`);
  const ipa = await fetch(`${base}/ota/${iid}/app.ipa`, { headers: { Range: 'bytes=0-3' } });
  assert.equal(ipa.status, 206);
  assert.equal(Buffer.from(await ipa.arrayBuffer()).toString('latin1').slice(0, 2), 'PK');
  assert.equal((await j('GET', `/ota/${'x'.repeat(30)}/app.ipa`)).status, 404);
  assert.equal((await j('GET', `/i/${iid}`)).status, 200);

  // delete wipes
  assert.equal((await j('DELETE', `/jobs/${jobId}`, { token })).status, 200);
  assert.equal((await j('GET', `/ota/${iid}/app.ipa`)).status, 404);
});

test('cors only for allowed origins; static + traversal', async () => {
  let r = await fetch(base + '/healthz', { headers: { Origin: 'https://evil.example' } });
  assert.equal(r.headers.get('access-control-allow-origin'), null);
  r = await fetch(base + '/healthz', { headers: { Origin: 'https://ecid-finder.vercel.app' } });
  assert.equal(r.headers.get('access-control-allow-origin'), 'https://ecid-finder.vercel.app');
  // raw request to avoid fetch path normalisation
  const status = await new Promise((res) => { const rq = http.request({ host: '127.0.0.1', port: server.address().port, path: '/..%2f..%2fetc/passwd' }, (x) => { x.resume(); res(x.statusCode); }); rq.end(); });
  assert.ok([403, 404].includes(status));
});

test('ingest from Blob URL: allowlist, size cap, validation, then signs', async () => {
  const goodIpa = makeIpa();
  const blobSrv = http.createServer((rq, rs) => {
    if (rq.url.includes('/big.ipa')) { rs.setHeader('Content-Length', 6 * 1024 * 1024); rs.end(Buffer.alloc(6 * 1024 * 1024)); }
    else if (rq.url.includes('/bad.ipa')) rs.end('definitely not a zip');
    else if (rq.url.includes('/gone.ipa')) { rs.statusCode = 404; rs.end('no'); }
    else rs.end(goodIpa);
  });
  await new Promise((r) => blobSrv.listen(0, '127.0.0.1', r));
  const bu = `http://127.0.0.1:${blobSrv.address().port}`;
  try {
    const mint = (await j('POST', '/api/jobs', { body: { ecid: '0x1965E62213801F', cpid: '8110' } })).json;
    const { jobId, token } = mint;
    const ing = (u, t = token) => j('POST', `/jobs/${jobId}/ingest`, { token: t, body: { ipaUrl: u } });
    assert.equal((await ing(`${bu}/ipa/${jobId}/a.ipa`, 'bad.token')).status, 401);
    // SSRF / scope checks
    assert.equal((await ing('https://example.com/ipa/' + jobId + '/a.ipa')).json.error, 'host_not_allowed');
    assert.equal((await ing('http://169.254.169.254/ipa/' + jobId + '/a.ipa')).json.error, 'bad_url');
    assert.equal((await ing('https://abcdefgh12.public.blob.vercel-storage.com/ipa/' + 'f'.repeat(24) + '/a.ipa')).json.error, 'path_not_allowed');
    assert.equal((await ing(`${bu}/other/${jobId}/a.ipa`)).json.error, 'path_not_allowed');
    assert.equal((await ing(`${bu}/ipa/${'0'.repeat(24)}/a.ipa`)).json.error, 'path_not_allowed');
    // failures
    assert.equal((await ing(`${bu}/ipa/${jobId}/big.ipa`)).status, 413);
    assert.equal((await ing(`${bu}/ipa/${jobId}/bad.ipa`)).status, 422);
    assert.equal((await ing(`${bu}/ipa/${jobId}/gone.ipa`)).status, 502);
    // success
    const ok = await ing(`${bu}/ipa/${jobId}/app-AbC123.ipa`);
    assert.equal(ok.status, 200, JSON.stringify(ok.json));
    assert.equal(ok.json.job.status, 'uploaded');
    assert.equal(ok.json.job.ipa.bundleId, 'com.example.hello');
    assert.ok(!fs.existsSync(path.join(data, 'jobs', jobId, 'upload.ipa.part')));
    const r = await j('POST', `/jobs/${jobId}/sign`, { token, body: { email: 'a@b.co', password: 'test-password', confirm: true } });
    assert.equal(r.status, 202);
    await j('DELETE', `/jobs/${jobId}`, { token });
  } finally { blobSrv.close(); }
});
