/**
 * Shared rules for the Vercel Blob IPA hand-off (used by api/blob-*.js and the signing worker).
 * The IPA is the USER'S OWN file: it goes browser -> Blob (direct client upload) -> signing worker
 * (which downloads it once) -> deleted. Paths are namespaced per job: ipa/<jobId>/<file>.ipa
 */
const MAX_IPA_BYTES_DEFAULT = 600 * 1024 * 1024;
const UPLOAD_TOKEN_TTL_MS = 30 * 60 * 1000; // client upload token lifetime
const ALLOWED_CONTENT_TYPES = ['application/octet-stream', 'application/zip', 'application/x-zip-compressed'];

const JID_RE = /^[a-f0-9]{24}$/;
const PATH_RE = /^ipa\/([a-f0-9]{24})\/[A-Za-z0-9._-]{1,100}\.ipa$/i;
// Vercel Blob public store hosts look like <storeId>.public.blob.vercel-storage.com
const HOST_RE = /^[a-z0-9]{8,64}\.public\.blob\.vercel-storage\.com$/;

function safeFileName(name) {
  const base = String(name || 'app.ipa').split(/[\\/]/).pop().replace(/[^A-Za-z0-9._-]/g, '_').replace(/^\.+/, '');
  const stem = base.replace(/\.ipa$/i, '').slice(0, 80) || 'app';
  return stem + '.ipa';
}

function blobPathFor(jid, name) {
  return `ipa/${jid}/${safeFileName(name)}`;
}

/** @returns {{ok:true, jid:string}|{ok:false, error:string}} */
function checkUploadPath(pathname) {
  const m = PATH_RE.exec(String(pathname || ''));
  return m ? { ok: true, jid: m[1] } : { ok: false, error: 'bad_path' };
}

/**
 * The worker only fetches https URLs on Vercel Blob public hosts whose path is inside this job's prefix.
 * (Prevents SSRF: the worker never fetches an arbitrary user-supplied URL.)
 * `extraHosts` is for tests only (never set in production).
 */
function checkIpaUrl(raw, jid, { allowHttpLoopback = false } = {}) {
  let u;
  try {
    u = new URL(String(raw));
  } catch (_) {
    return { ok: false, error: 'bad_url' };
  }
  if (u.username || u.password) return { ok: false, error: 'bad_url' };
  const loop = allowHttpLoopback && u.protocol === 'http:' && u.hostname === '127.0.0.1';
  if (!loop) {
    if (u.protocol !== 'https:' || u.port) return { ok: false, error: 'bad_url' };
    if (!HOST_RE.test(u.hostname)) return { ok: false, error: 'host_not_allowed' };
  }
  let p;
  try {
    p = decodeURIComponent(u.pathname).replace(/^\//, '');
  } catch (_) {
    return { ok: false, error: 'bad_url' };
  }
  const pm = PATH_RE.exec(p);
  if (!pm || pm[1] !== jid) return { ok: false, error: 'path_not_allowed' };
  return { ok: true, url: u };
}

module.exports = { MAX_IPA_BYTES_DEFAULT, UPLOAD_TOKEN_TTL_MS, ALLOWED_CONTENT_TYPES, JID_RE, PATH_RE, HOST_RE, safeFileName, blobPathFor, checkUploadPath, checkIpaUrl };
