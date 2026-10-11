/**
 * itms-services OTA manifest helpers. iOS requires the manifest and IPA over valid HTTPS.
 *
 * The output is deliberately the minimal canonical form from Apple's "Distributing apps using
 * itms-services" docs: one `items[0]` with a single `software-package` asset and the four
 * required metadata keys (bundle-identifier, bundle-version, kind, title). No extra keys.
 */
const { buildXmlPlist } = require('./plist-lite');

// Control chars (incl. CR/LF/TAB, which break XML text and URLs), DEL, and Unicode line/para separators.
// eslint-disable-next-line no-control-regex
const CTRL_RE = /[\u0000-\u001f\u007f\u2028\u2029\ufeff]/;
const CTRL_RE_G = new RegExp(CTRL_RE.source, 'g');

function assertCleanHttpsUrl(u, what) {
  const s = String(u);
  // https in production (iOS refuses anything else); http only so the local test worker can run.
  if (!/^https?:\/\/[^\s/?#]+(\/[^\s?#]*)?$/.test(s) || CTRL_RE.test(s)) {
    throw new Error(`ota: ${what} must be a bare http(s) URL (no query, fragment, whitespace or control chars)`);
  }
  return s;
}

function cleanText(v, fallback) {
  const s = String(v == null ? '' : v).replace(CTRL_RE_G, ' ').trim();
  return s || fallback;
}

function buildManifest({ ipaUrl, bundleId, version, title }) {
  const id = cleanText(bundleId, '');
  if (!id) throw new Error('ota: bundleId required');
  return buildXmlPlist({
    items: [
      {
        assets: [{ kind: 'software-package', url: assertCleanHttpsUrl(ipaUrl, 'ipaUrl') }],
        metadata: {
          'bundle-identifier': id,
          'bundle-version': cleanText(version, '1.0'),
          kind: 'software',
          title: cleanText(title, id),
        },
      },
    ],
  });
}

/**
 * Canonical Apple form: itms-services://?action=download-manifest&url=https://host/path/manifest.plist
 * The manifest URL is left RAW (not percent-encoded) when it is a plain https URL with no
 * `& ? # %` or whitespace, exactly as in Apple's docs. It is only encoded if it contains
 * characters that would otherwise corrupt the outer query string.
 */
function installLink(manifestUrl) {
  const u = String(manifestUrl);
  const raw = /^https?:\/\/[A-Za-z0-9.\-]+(:\d+)?(\/[A-Za-z0-9._~\-\/]*)?$/.test(u);
  return 'itms-services://?action=download-manifest&url=' + (raw ? u : encodeURIComponent(u));
}

module.exports = { buildManifest, installLink };
