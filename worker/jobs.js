/** File-backed job store. job.json holds NO credentials (only ids, stages, metadata). */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA = process.env.ECID_WORKER_DATA || path.join(__dirname, 'data');
const JOBS_DIR = path.join(DATA, 'jobs');
const ANISETTE_DIR = path.join(DATA, 'anisette');
fs.mkdirSync(JOBS_DIR, { recursive: true, mode: 0o700 });
fs.mkdirSync(ANISETTE_DIR, { recursive: true, mode: 0o700 });

const live = new Map(); // jid -> { runner, twofa, attempts }
const installIndex = new Map(); // installId -> jid

function jobDir(jid) {
  if (!/^[a-f0-9]{24}$/.test(jid)) throw new Error('bad_job_id');
  return path.join(JOBS_DIR, jid);
}

function loadJob(jid) {
  try {
    return JSON.parse(fs.readFileSync(path.join(jobDir(jid), 'job.json'), 'utf8'));
  } catch (_) {
    return null;
  }
}

function saveJob(job) {
  const dir = jobDir(job.jid);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = path.join(dir, 'job.json.tmp');
  fs.writeFileSync(tmp, JSON.stringify(job), { mode: 0o600 });
  fs.renameSync(tmp, path.join(dir, 'job.json'));
  if (job.installId) installIndex.set(job.installId, job.jid);
}

function ensureJob(payload) {
  let job = loadJob(payload.jid);
  if (!job) {
    job = {
      jid: payload.jid,
      udid: payload.udid,
      deviceName: payload.name || 'ECID Finder device',
      status: 'created',
      stage: 'created',
      createdAt: Date.now(),
      expiresAt: payload.exp,
    };
    saveJob(job);
  } else if (job.udid !== payload.udid) {
    throw new Error('job_udid_mismatch');
  }
  return job;
}

function findByInstallId(iid) {
  if (!/^[A-Za-z0-9_-]{20,64}$/.test(iid)) return null;
  const jid = installIndex.get(iid);
  if (jid) return loadJob(jid);
  // rebuild index lazily after restart
  for (const d of fs.readdirSync(JOBS_DIR)) {
    const j = loadJob(d);
    if (j && j.installId) installIndex.set(j.installId, j.jid);
  }
  const j2 = installIndex.get(iid);
  return j2 ? loadJob(j2) : null;
}

function newInstallId() {
  return crypto.randomBytes(24).toString('base64url');
}

function removeJob(jid) {
  const l = live.get(jid);
  if (l && l.runner) l.runner.kill();
  live.delete(jid);
  const j = loadJob(jid);
  if (j && j.installId) installIndex.delete(j.installId);
  fs.rmSync(jobDir(jid), { recursive: true, force: true });
}

/** Delete expired jobs. */
function sweep({ uploadTtlMs, signedTtlMs }) {
  const now = Date.now();
  for (const d of fs.readdirSync(JOBS_DIR)) {
    if (!/^[a-f0-9]{24}$/.test(d)) continue;
    const j = loadJob(d);
    if (!j) {
      fs.rmSync(path.join(JOBS_DIR, d), { recursive: true, force: true });
      continue;
    }
    const ref = j.readyAt || j.createdAt;
    const ttl = j.status === 'ready' ? signedTtlMs : uploadTtlMs;
    if (now - ref > ttl && !(live.get(d) && live.get(d).runner)) removeJob(d);
  }
}

module.exports = { DATA, JOBS_DIR, ANISETTE_DIR, live, jobDir, loadJob, saveJob, ensureJob, findByInstallId, newInstallId, removeJob, sweep };
