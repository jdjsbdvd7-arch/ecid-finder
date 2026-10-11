#!/usr/bin/env node
/**
 * ECID Finder signing worker (zero npm dependencies).
 *
 *  - PUT  /jobs/:id/ipa      raw IPA upload (size-capped, validated)      [Bearer job token]
 *  - POST /jobs/:id/ingest   {ipaUrl} worker downloads the IPA from Vercel Blob  [Bearer job token]
 *  - POST /jobs/:id/sign     {email,password,maxCerts,confirm}            [Bearer job token]
 *  - POST /jobs/:id/2fa      {action:'code'|'sms'|'devices'|'resend'|'abort', code?, id?}
 *  - GET  /jobs/:id          status                                       [Bearer job token]
 *  - DELETE /jobs/:id        wipe everything for this job
 *  - GET  /ota/:iid/manifest.plist | /ota/:iid/app.ipa | /i/:iid          (unguessable install id)
 *  - Also serves ../public and /api/{jobs,udid,config} so the whole app runs standalone.
 *
 * Apple credentials only transit this process's memory and the signer child's stdin.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { verifyJobToken, mintJobToken } = require('../lib/job-token');
const { inspectIpa } = require('../lib/ipa-inspect');
const { buildManifest, installLink } = require('../lib/ota');
const { sendJson, readJsonBody, makeLimiter, clientIp } = require('../lib/http-utils');
const { hasSecret } = require('../lib/secret');
const { checkIpaUrl } = require('../lib/blob-policy');
const https = require('https');
const httpMod = require('http');
const store = require('./jobs');
const { runSigner, signerAvailable } = require('./signer-runner');

// ani.stikstore.app (isideload's default) sits behind a Cloudflare challenge for datacenter IPs; ani.sidestore.io answered Apple-login probes from a Vercel Sandbox.
const DEFAULT_ANISETTE_URL = 'https://ani.sidestore.io';
const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || '127.0.0.1';
const MAX_IPA_BYTES = Number(process.env.MAX_IPA_BYTES || 600 * 1024 * 1024);
const MAX_CONCURRENT_SIGN = Number(process.env.MAX_CONCURRENT_SIGN || 2);
const UPLOAD_TTL_MS = Number(process.env.UPLOAD_TTL_MS || 2 * 60 * 60 * 1000);
const SIGNED_TTL_MS = Number(process.env.SIGNED_TTL_MS || 3 * 60 * 60 * 1000);
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const jobsLimiter = makeLimiter({ windowMs: 60_000, max: 30 });
const signLimiter = makeLimiter({ windowMs: 10 * 60_000, max: 8 });

if (!hasSecret('JOB_HMAC_SECRET')) {
  console.warn('[worker] JOB_HMAC_SECRET not set: using an ephemeral secret. Tokens minted by the Vercel site will NOT validate. Set the same JOB_HMAC_SECRET on both sides.');
}

function cors(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization,Content-Type');
    res.setHeader('Access-Control-Max-Age', '600');
  }
}

function baseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL.replace(/\/+$/, '');
  const proto = process.env.TRUST_PROXY === '1' && req.headers['x-forwarded-proto'] ? String(req.headers['x-forwarded-proto']).split(',')[0] : 'http';
  const host = (process.env.TRUST_PROXY === '1' && req.headers['x-forwarded-host']) || req.headers.host;
  return `${proto}://${host}`;
}

function authJob(req, jid) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  const v = verifyJobToken(token);
  if (!v.ok) return { ok: false, status: 401, error: v.error };
  if (v.payload.jid !== jid) return { ok: false, status: 403, error: 'job_mismatch' };
  return { ok: true, payload: v.payload };
}

function redact(msg, secrets) {
  let s = String(msg || '');
  for (const x of secrets) if (x && x.length >= 3) s = s.split(x).join('***');
  return s.slice(0, 600);
}

function publicJob(job, req) {
  const l = store.live.get(job.jid);
  const out = {
    jobId: job.jid,
    status: job.status,
    stage: job.stage,
    progress: job.progress || 0,
    udid: job.udid,
    ipa: job.ipa || null,
    team: job.team || null,
    error: job.error || null,
    warnings: job.warnings || [],
    bundleRewrite: job.bundleRewrite || null,
    expiresAt: job.expiresAt,
    twofa: l && l.twofa ? l.twofa : null,
  };
  if (job.status === 'ready' && job.installId) {
    const b = baseUrl(req);
    const manifestUrl = `${b}/ota/${job.installId}/manifest.plist`;
    out.install = {
      pageUrl: `${b}/i/${job.installId}`,
      manifestUrl,
      itms: installLink(manifestUrl),
      https: b.startsWith('https://'),
      signedBundleId: job.signedBundleId,
      expiresAt: (job.readyAt || 0) + SIGNED_TTL_MS,
      profileValidDays: 7,
    };
  }
  return out;
}

/* ---------------- upload ---------------- */

async function handleUpload(req, res, jid) {
  const a = authJob(req, jid);
  if (!a.ok) return sendJson(res, a.status, { ok: false, error: a.error });
  let job;
  try {
    job = store.ensureJob(a.payload);
  } catch (e) {
    return sendJson(res, 409, { ok: false, error: e.message });
  }
  if (!['created', 'uploaded', 'error'].includes(job.status) || store.live.get(jid)?.runner) {
    return sendJson(res, 409, { ok: false, error: 'job_busy', status: job.status });
  }
  const len = Number(req.headers['content-length'] || 0);
  if (!len) return sendJson(res, 411, { ok: false, error: 'length_required' });
  if (len > MAX_IPA_BYTES) return sendJson(res, 413, { ok: false, error: 'too_large', maxBytes: MAX_IPA_BYTES });
  const dir = store.jobDir(jid);
  const dest = path.join(dir, 'upload.ipa');
  const tmp = dest + '.part';
  const out = fs.createWriteStream(tmp, { mode: 0o600 });
  let got = 0;
  let aborted = false;
  const hash = crypto.createHash('sha256');
  const fail = (status, error, extra) => {
    if (aborted) return;
    aborted = true;
    out.destroy();
    fs.rmSync(tmp, { force: true });
    if (!res.headersSent) sendJson(res, status, { ok: false, error, ...extra }, { Connection: 'close' });
    req.destroy();
  };
  req.on('data', (c) => {
    got += c.length;
    if (got > MAX_IPA_BYTES || got > len) return fail(413, 'too_large', { maxBytes: MAX_IPA_BYTES });
    hash.update(c);
    if (!out.write(c)) {
      req.pause();
      out.once('drain', () => req.resume());
    }
  });
  req.on('error', () => fail(400, 'upload_error'));
  req.on('aborted', () => fail(400, 'aborted'));
  req.on('end', () => {
    if (aborted) return;
    out.end(async () => {
      if (got !== len) return fail(400, 'length_mismatch');
      const result = await inspectIpa(tmp);
      if (!result.ok) {
        fs.rmSync(tmp, { force: true });
        return sendJson(res, 422, { ok: false, error: result.error, message: result.message });
      }
      fs.renameSync(tmp, dest);
      job.status = 'uploaded';
      job.stage = 'uploaded';
      job.error = null;
      job.ipa = { ...result.info, sha256: hash.digest('hex') };
      job.warnings = result.warnings;
      store.saveJob(job);
      sendJson(res, 200, { ok: true, job: publicJob(job, req) });
    });
  });
}


/* ---------------- ingest from Vercel Blob ---------------- */

/** Download `url` (no redirects) into `tmp`, enforcing the size cap. Resolves {got, sha256}. */
function downloadTo(url, tmp, maxBytes) {
  return new Promise((resolve, reject) => {
    const mod = url.protocol === 'https:' ? https : httpMod;
    const req = mod.get(url, { headers: { 'User-Agent': 'ecid-worker/1' }, timeout: 30_000 }, (r) => {
      if (r.statusCode !== 200) {
        r.resume();
        return reject(Object.assign(new Error('fetch_failed'), { status: r.statusCode }));
      }
      const len = Number(r.headers['content-length'] || 0);
      if (len > maxBytes) {
        r.resume();
        return reject(Object.assign(new Error('too_large'), { status: 413 }));
      }
      const out = fs.createWriteStream(tmp, { mode: 0o600 });
      const hash = crypto.createHash('sha256');
      let got = 0;
      r.on('data', (c) => {
        got += c.length;
        if (got > maxBytes) {
          r.destroy(Object.assign(new Error('too_large'), { status: 413 }));
          return;
        }
        hash.update(c);
        if (!out.write(c)) {
          r.pause();
          out.once('drain', () => r.resume());
        }
      });
      r.on('error', (e) => { out.destroy(); reject(e); });
      r.on('end', () => out.end(() => resolve({ got, sha256: hash.digest('hex') })));
    });
    req.on('timeout', () => req.destroy(Object.assign(new Error('timeout'), { status: 504 })));
    req.on('error', reject);
  });
}

async function handleIngest(req, res, jid) {
  const a = authJob(req, jid);
  if (!a.ok) return sendJson(res, a.status, { ok: false, error: a.error });
  let body;
  try {
    body = await readJsonBody(req, 2048);
  } catch (_) {
    return sendJson(res, 400, { ok: false, error: 'bad_json' });
  }
  const chk = checkIpaUrl(body.ipaUrl, jid, { allowHttpLoopback: process.env.ECID_TEST_ALLOW_LOOPBACK_INGEST === '1' });
  if (!chk.ok) return sendJson(res, 400, { ok: false, error: chk.error });
  let job;
  try {
    job = store.ensureJob(a.payload);
  } catch (e) {
    return sendJson(res, 409, { ok: false, error: e.message });
  }
  const entry = store.live.get(jid);
  if (!['created', 'uploaded', 'error'].includes(job.status) || (entry && entry.runner) || (entry && entry.ingesting)) {
    return sendJson(res, 409, { ok: false, error: 'job_busy', status: job.status });
  }
  const live = entry || { attempts: 0 };
  live.ingesting = true;
  store.live.set(jid, live);
  const dir = store.jobDir(jid);
  const dest = path.join(dir, 'upload.ipa');
  const tmp = dest + '.part';
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    const { got, sha256 } = await downloadTo(chk.url, tmp, MAX_IPA_BYTES);
    if (!got) throw Object.assign(new Error('empty'), { status: 422 });
    const result = await inspectIpa(tmp);
    if (!result.ok) {
      fs.rmSync(tmp, { force: true });
      return sendJson(res, 422, { ok: false, error: result.error, message: result.message });
    }
    fs.renameSync(tmp, dest);
    job.status = 'uploaded';
    job.stage = 'uploaded';
    job.error = null;
    job.ipa = { ...result.info, sha256 };
    job.warnings = result.warnings;
    store.saveJob(job);
    return sendJson(res, 200, { ok: true, job: publicJob(job, req) });
  } catch (e) {
    fs.rmSync(tmp, { force: true });
    if (e && e.message === 'too_large') return sendJson(res, 413, { ok: false, error: 'too_large', maxBytes: MAX_IPA_BYTES });
    return sendJson(res, 502, { ok: false, error: 'ingest_failed', message: 'Could not fetch the IPA from storage (' + (e && (e.status || e.code || e.message)) + ').' });
  } finally {
    live.ingesting = false;
  }
}

/* ---------------- sign ---------------- */

function activeSigners() {
  let n = 0;
  for (const l of store.live.values()) if (l.runner) n++;
  return n;
}

async function handleSign(req, res, jid) {
  const a = authJob(req, jid);
  if (!a.ok) return sendJson(res, a.status, { ok: false, error: a.error });
  if (!signLimiter(clientIp(req) + ':sign')) return sendJson(res, 429, { ok: false, error: 'rate_limited' });
  let body;
  try {
    body = await readJsonBody(req, 4096);
  } catch (e) {
    return sendJson(res, 400, { ok: false, error: e.code === 'TOO_LARGE' ? 'too_large' : 'bad_json' });
  }
  const job = store.loadJob(jid);
  if (!job) return sendJson(res, 404, { ok: false, error: 'no_such_job' });
  if (!signerAvailable()) {
    return sendJson(res, 501, {
      ok: false,
      error: 'signer_not_built',
      message: 'ecid-signer is not built on this worker. Run: cd worker/signer && cargo build --release (see README).',
    });
  }
  if (job.status !== 'uploaded' && job.status !== 'error') {
    return sendJson(res, 409, { ok: false, error: 'bad_state', status: job.status });
  }
  if (!fs.existsSync(path.join(store.jobDir(jid), 'upload.ipa'))) {
    return sendJson(res, 409, { ok: false, error: 'no_ipa', message: 'Upload an IPA first.' });
  }
  if (body.confirm !== true) {
    return sendJson(res, 400, { ok: false, error: 'confirm_required', message: 'You must confirm this is your own Apple ID and IPA.' });
  }
  const email = typeof body.email === 'string' ? body.email.trim() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  if (!/^[^\s@]{1,64}@[^\s@]{1,190}$/.test(email) || email.length > 254) return sendJson(res, 400, { ok: false, error: 'bad_email' });
  if (!password || password.length > 256) return sendJson(res, 400, { ok: false, error: 'bad_password' });
  let customBundleId = '';
  if (body.bundleId != null && String(body.bundleId).trim() !== '') {
    customBundleId = String(body.bundleId).trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9.\-]{2,99}$/.test(customBundleId) || !customBundleId.includes('.') || /\.\.|\.$/.test(customBundleId) || /^com\.apple(\.|$)/i.test(customBundleId)) {
      return sendJson(res, 400, { ok: false, error: 'bad_bundle_id', message: 'معرّف الحزمة غير صالح أو محجوز (com.apple.* غير مسموح) · Invalid or reserved bundle ID (com.apple.* not allowed).' });
    }
  }
  if (activeSigners() >= MAX_CONCURRENT_SIGN) return sendJson(res, 503, { ok: false, error: 'busy', message: 'Worker is busy; retry in a minute.' });
  const entry = store.live.get(jid) || { attempts: 0 };
  if (entry.runner) {
    // A finished-with-error signer may still be shutting down: let the user retry immediately.
    if (job.status === 'error') {
      entry.runner.kill();
      entry.runner = null;
    } else return sendJson(res, 409, { ok: false, error: 'already_running' });
  }
  entry.run = (entry.run || 0) + 1;
  const myRun = entry.run;
  entry.attempts = (entry.attempts || 0) + 1;
  entry.errored = false;
  entry.doneEvent = null;
  entry.twofa = null;
  if (entry.attempts > 5) return sendJson(res, 429, { ok: false, error: 'too_many_attempts' });
  store.live.set(jid, entry);

  const outPath = path.join(store.jobDir(jid), 'signed.ipa');
  const secrets = [password, email];
  job.status = 'signing';
  job.stage = 'starting';
  job.progress = 0;
  job.error = null;
  job.bundleRewrite = null;
  store.saveJob(job);

  const onEvent = (ev) => {
    if (entry.run !== myRun) return; // stale signer from an earlier attempt
    const j = store.loadJob(jid) || job;
    switch (ev.event) {
      case 'stage':
        j.stage = ev.stage;
        entry.twofa = null;
        break;
      case 'need_2fa':
        j.stage = 'need_2fa';
        entry.twofa = ev.params || {};
        break;
      case 'progress':
        j.progress = Math.max(j.progress || 0, Number(ev.value) || 0);
        break;
      case 'team':
        j.team = { id: ev.teamId, name: ev.name };
        break;
      case 'bundle_rewrite':
        // App ID hygiene: reserved/unavailable bundle id was rewritten to a unique one before signing.
        j.bundleRewrite = {
          from: String(ev.from || '').slice(0, 155),
          to: String(ev.to || '').slice(0, 155),
          reason: ['reserved', 'unavailable', 'override'].includes(ev.reason) ? ev.reason : 'unavailable',
        };
        break;
      case 'device_registered':
        j.deviceRegistered = true;
        break;
      case 'error':
        j.status = 'error';
        j.stage = 'error';
        j.error = { code: String(ev.code || 'error'), message: redact(ev.message, secrets) };
        entry.errored = true;
        break;
      case 'done':
        entry.doneEvent = ev;
        break;
      default:
    }
    store.saveJob(j);
  };

  const runner = runSigner(
    {
      email,
      password,
      udid: job.udid,
      deviceName: job.deviceName,
      ipa: path.join(store.jobDir(jid), 'upload.ipa'),
      out: outPath,
      maxCerts: body.maxCerts === 'revoke' ? 'revoke' : 'error',
      bundleId: customBundleId || undefined,
      anisetteUrl: process.env.ANISETTE_URL || DEFAULT_ANISETTE_URL,
      stateDir: store.ANISETTE_DIR,
    },
    onEvent
  );
  entry.runner = runner;
  runner.done.then(async ({ code }) => {
    if (entry.run !== myRun) return; // superseded by a newer attempt
    entry.runner = null;
    entry.twofa = null;
    const j = store.loadJob(jid);
    if (!j) return;
    if (entry.doneEvent && !entry.errored && fs.existsSync(outPath)) {
      const insp = await inspectIpa(outPath);
      if (!insp.ok) {
        j.status = 'error';
        j.stage = 'error';
        j.error = { code: 'signed_ipa_invalid', message: 'Signed IPA failed validation: ' + insp.message };
      } else {
        j.status = 'ready';
        j.stage = 'ready';
        j.progress = 1;
        j.readyAt = Date.now();
        j.installId = store.newInstallId();
        j.signedBundleId = insp.info.bundleId;
        j.signedVersion = insp.info.build || insp.info.version || '1.0';
        j.signedTitle = insp.info.name;
        fs.rmSync(path.join(store.jobDir(jid), 'upload.ipa'), { force: true }); // original no longer needed
        fs.rmSync(outPath + '.rewritten.ipa', { force: true });
      }
    } else if (j.status !== 'error') {
      j.status = 'error';
      j.stage = 'error';
      j.error = j.error || { code: 'signer_exit', message: `Signer exited unexpectedly (code ${code}).` };
    }
    store.saveJob(j);
  });
  // credentials are now only inside the child's stdin pipe
  body.password = undefined;
  sendJson(res, 202, { ok: true, job: publicJob(store.loadJob(jid), req) });
}

async function handle2fa(req, res, jid) {
  const a = authJob(req, jid);
  if (!a.ok) return sendJson(res, a.status, { ok: false, error: a.error });
  let body;
  try {
    body = await readJsonBody(req, 1024);
  } catch (_) {
    return sendJson(res, 400, { ok: false, error: 'bad_json' });
  }
  const entry = store.live.get(jid);
  if (!entry || !entry.runner || !entry.twofa) return sendJson(res, 409, { ok: false, error: 'no_2fa_pending' });
  const action = String(body.action || 'code');
  if (action === 'code') {
    if (!/^\d{4,8}$/.test(String(body.code || ''))) return sendJson(res, 400, { ok: false, error: 'bad_code' });
    entry.runner.write({ action: 'code', code: String(body.code) });
  } else if (action === 'sms') {
    entry.runner.write({ action: 'sms', id: Number(body.id) || 1 });
  } else if (['devices', 'resend', 'abort'].includes(action)) {
    entry.runner.write({ action });
  } else {
    return sendJson(res, 400, { ok: false, error: 'bad_action' });
  }
  entry.twofa = null;
  const j = store.loadJob(jid);
  j.stage = 'apple_login';
  store.saveJob(j);
  sendJson(res, 200, { ok: true });
}

/* ---------------- OTA ---------------- */

function serveFile(req, res, file, type, extra = {}) {
  let st;
  try {
    st = fs.statSync(file);
  } catch (_) {
    res.statusCode = 404;
    return res.end('Not found');
  }
  const range = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || '');
  let start = 0;
  let end = st.size - 1;
  let status = 200;
  if (range && (range[1] || range[2])) {
    if (range[1]) start = Number(range[1]);
    if (range[2]) end = range[1] ? Math.min(Number(range[2]), end) : st.size - 1;
    if (!range[1]) start = Math.max(0, st.size - Number(range[2]));
    if (start > end || start >= st.size) {
      res.statusCode = 416;
      res.setHeader('Content-Range', `bytes */${st.size}`);
      return res.end();
    }
    status = 206;
    res.setHeader('Content-Range', `bytes ${start}-${end}/${st.size}`);
  }
  res.statusCode = status;
  res.setHeader('Content-Type', type);
  res.setHeader('Accept-Ranges', 'bytes');
  res.setHeader('Content-Length', end - start + 1);
  res.setHeader('Cache-Control', 'no-store');
  for (const [k, v] of Object.entries(extra)) res.setHeader(k, v);
  if (req.method === 'HEAD') return res.end();
  fs.createReadStream(file, { start, end }).pipe(res);
}

function handleOta(req, res, iid, what) {
  const job = store.findByInstallId(iid);
  if (!job || job.status !== 'ready' || Date.now() - job.readyAt > SIGNED_TTL_MS) {
    res.statusCode = 404;
    return res.end('Not found');
  }
  const b = baseUrl(req);
  if (what === 'manifest.plist') {
    const xml = buildManifest({
      ipaUrl: `${b}/ota/${iid}/app.ipa`,
      bundleId: job.signedBundleId,
      version: job.signedVersion,
      title: job.signedTitle,
    });
    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/xml; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Length', Buffer.byteLength(xml));
    return res.end(req.method === 'HEAD' ? undefined : xml);
  }
  if (what === 'app.ipa') {
    return serveFile(req, res, path.join(store.jobDir(job.jid), 'signed.ipa'), 'application/octet-stream');
  }
  res.statusCode = 404;
  res.end('Not found');
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function handleInstallPage(req, res, iid) {
  const job = store.findByInstallId(iid);
  if (!job || job.status !== 'ready') {
    res.statusCode = 404;
    return res.end('Not found');
  }
  const b = baseUrl(req);
  const link = installLink(`${b}/ota/${iid}/manifest.plist`);
  const warn = b.startsWith('https://')
    ? ''
    : '<p class="warn">⚠️ This worker is not served over valid HTTPS, so iOS will refuse the install. Put it behind HTTPS (see README).</p>';
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'");
  res.end(`<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(job.signedTitle)} · Install</title>
<style>body{font-family:system-ui,sans-serif;background:#0f1419;color:#e7ecf3;padding:24px}main{max-width:520px;margin:auto;background:#1a2332;border:1px solid #2a3548;border-radius:16px;padding:24px}a.btn{display:block;text-align:center;background:#3d8bfd;color:#fff;text-decoration:none;padding:14px;border-radius:10px;font-weight:600;margin:16px 0}.warn{background:#f0c14b22;border:1px solid #f0c14b66;padding:10px;border-radius:8px}li{margin:6px 0;line-height:1.5}</style></head><body><main>
<h1>${esc(job.signedTitle)}</h1><p dir="ltr">${esc(job.signedBundleId)}</p>${warn}
<a class="btn" href="${esc(link)}">تثبيت لاسلكياً · Install wirelessly</a>
<ol><li>افتح هذه الصفحة في Safari على نفس الجهاز المسجّل · Open in Safari on the registered device.</li>
<li>فعّل وضع المطوّر (Settings → Privacy &amp; Security → Developer Mode) ثم أعد التشغيل · Enable Developer Mode and reboot.</li>
<li>بعد التثبيت: Settings → General → VPN &amp; Device Management → ثق بحسابك · Trust your developer profile.</li>
<li>الملف صالح 7 أيام (حساب مجاني) · Valid 7 days on a free account.</li></ol></main></body></html>`);
}

/* ---------------- static (standalone mode) ---------------- */

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };

function serveStatic(req, res, pathname) {
  let rel = decodeURIComponent(pathname);
  if (rel === '/') rel = '/index.html';
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) {
    res.statusCode = 403;
    return res.end('Forbidden');
  }
  if (rel === '/sideload.html') {
    res.setHeader('Content-Security-Policy', "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
    res.setHeader('Referrer-Policy', 'no-referrer');
  }
  serveFile(req, res, file, MIME[path.extname(file)] || 'application/octet-stream');
}

/* ---------------- router ---------------- */

const apiJobs = require('../api/jobs');
const apiUdid = require('../api/udid');

const server = http.createServer(async (req, res) => {
  try {
    cors(req, res);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (req.method === 'OPTIONS') {
      res.statusCode = 204;
      return res.end();
    }
    const url = new URL(req.url, 'http://localhost');
    const p = url.pathname;
    let m;
    if (p.startsWith('/ota/') || p.startsWith('/i/')) {
      // OTA access log (no secrets: install id redacted) to diagnose on-device install failures.
      const t0 = Date.now();
      res.on('finish', () => console.log(`[ota] ${new Date().toISOString()} ${req.method} ${p.replace(/^(\/(?:ota|i)\/)[A-Za-z0-9_-]+/, '$1<id>')} -> ${res.statusCode} range=${req.headers.range || '-'} ua=${String(req.headers['user-agent'] || '-').slice(0, 80)} ${Date.now() - t0}ms`));
    }
    if (p === '/healthz') {
      return sendJson(res, 200, { ok: true, signer: signerAvailable(), https: baseUrl(req).startsWith('https://') });
    }
    if (p === '/api/config') {
      return sendJson(res, 200, {
        ok: true,
        workerConfigured: true,
        workerUrl: '',
        signerBuilt: signerAvailable(),
        maxIpaBytes: MAX_IPA_BYTES,
        https: baseUrl(req).startsWith('https://'),
      });
    }
    if (p === '/api/jobs') {
      if (!jobsLimiter(clientIp(req))) return sendJson(res, 429, { ok: false, error: 'rate_limited' });
      return apiJobs(req, res);
    }
    if (p === '/api/udid') return apiUdid(req, res);
    if ((m = /^\/jobs\/([a-f0-9]{24})\/ipa$/.exec(p)) && req.method === 'PUT') return handleUpload(req, res, m[1]);
    if ((m = /^\/jobs\/([a-f0-9]{24})\/ingest$/.exec(p)) && req.method === 'POST') return handleIngest(req, res, m[1]);
    if ((m = /^\/jobs\/([a-f0-9]{24})\/sign$/.exec(p)) && req.method === 'POST') return handleSign(req, res, m[1]);
    if ((m = /^\/jobs\/([a-f0-9]{24})\/2fa$/.exec(p)) && req.method === 'POST') return handle2fa(req, res, m[1]);
    if ((m = /^\/jobs\/([a-f0-9]{24})$/.exec(p))) {
      const a = authJob(req, m[1]);
      if (!a.ok) return sendJson(res, a.status, { ok: false, error: a.error });
      if (req.method === 'GET') {
        const job = store.loadJob(m[1]);
        if (!job) return sendJson(res, 404, { ok: false, error: 'no_such_job' });
        return sendJson(res, 200, { ok: true, job: publicJob(job, req) });
      }
      if (req.method === 'DELETE') {
        store.removeJob(m[1]);
        return sendJson(res, 200, { ok: true });
      }
    }
    if ((m = /^\/ota\/([A-Za-z0-9_-]+)\/(manifest\.plist|app\.ipa)$/.exec(p)) && ['GET', 'HEAD'].includes(req.method)) {
      return handleOta(req, res, m[1], m[2]);
    }
    if ((m = /^\/i\/([A-Za-z0-9_-]+)$/.exec(p)) && req.method === 'GET') return handleInstallPage(req, res, m[1]);
    if (['GET', 'HEAD'].includes(req.method) && process.env.WORKER_SERVE_STATIC !== '0') return serveStatic(req, res, p);
    sendJson(res, 404, { ok: false, error: 'not_found' });
  } catch (e) {
    console.error('[worker] handler error:', e && e.code ? e.code : e && e.message);
    if (!res.headersSent) sendJson(res, 500, { ok: false, error: 'internal' });
    else res.end();
  }
});

server.requestTimeout = 0; // large uploads
server.headersTimeout = 30_000;

if (require.main === module) {
  setInterval(() => store.sweep({ uploadTtlMs: UPLOAD_TTL_MS, signedTtlMs: SIGNED_TTL_MS }), 60_000).unref();
  store.sweep({ uploadTtlMs: UPLOAD_TTL_MS, signedTtlMs: SIGNED_TTL_MS });
  server.listen(PORT, HOST, () => {
    console.log(`[worker] listening on http://${HOST}:${PORT}  signer=${signerAvailable() ? 'built' : 'NOT built'}  data=${store.DATA}`);
  });
}

module.exports = { server };
