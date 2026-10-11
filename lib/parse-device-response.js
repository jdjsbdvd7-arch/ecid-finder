/**
 * Device POSTs CMS/PKCS#7 (application/pkcs7-signature). The XML plist is
 * embedded in cleartext inside signedData — same extraction pattern as
 * getudid.co / EmperorEarth / Apple OTA samples.
 *
 * Device attribute plists are a top-level <dict> of key/value pairs. Some
 * builds nest attributes under an inner <dict>; we walk every dict and merge
 * string/integer/data keys (CHALLENGE → Challenge).
 */

function extractPlistXml(raw) {
  if (!raw) return null;
  const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(String(raw), 'utf8');
  // latin1 preserves byte positions for binary CMS with ASCII XML inside
  const latin = buf.toString('latin1');
  const utf = buf.toString('utf8');
  for (const source of [latin, utf]) {
    const begin = source.indexOf('<?xml');
    if (begin === -1) continue;
    const endTag = '</plist>';
    const end = source.indexOf(endTag, begin);
    if (end === -1) continue;
    return source.slice(begin, end + endTag.length);
  }
  // Fallback: bare <plist> without xml decl
  for (const source of [latin, utf]) {
    const begin = source.indexOf('<plist');
    if (begin === -1) continue;
    const endTag = '</plist>';
    const end = source.indexOf(endTag, begin);
    if (end === -1) continue;
    return source.slice(begin, end + endTag.length);
  }
  return null;
}

function unescapeXml(s) {
  return String(s)
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

/**
 * Tokenize plist XML into a stream of structural events, then parse dicts
 * with precise key → typed-value pairing (handles nested <dict>).
 */
function parsePlistValue(tokens, i) {
  if (i >= tokens.length) return { value: null, next: i };
  const t = tokens[i];
  if (t.type === 'string') return { value: unescapeXml(t.text), next: i + 1 };
  if (t.type === 'integer') return { value: t.text.trim(), next: i + 1 };
  if (t.type === 'real') return { value: t.text.trim(), next: i + 1 };
  if (t.type === 'data') return { value: t.text.replace(/\s+/g, ''), next: i + 1 };
  if (t.type === 'true') return { value: true, next: i + 1 };
  if (t.type === 'false') return { value: false, next: i + 1 };
  if (t.type === 'dictOpen') {
    const dict = {};
    let j = i + 1;
    while (j < tokens.length && tokens[j].type !== 'dictClose') {
      if (tokens[j].type !== 'key') {
        j += 1;
        continue;
      }
      const key = tokens[j].text.trim();
      j += 1;
      const parsed = parsePlistValue(tokens, j);
      dict[key] = parsed.value;
      j = parsed.next;
    }
    return { value: dict, next: j + 1 };
  }
  if (t.type === 'arrayOpen') {
    const arr = [];
    let j = i + 1;
    while (j < tokens.length && tokens[j].type !== 'arrayClose') {
      const parsed = parsePlistValue(tokens, j);
      arr.push(parsed.value);
      j = parsed.next;
    }
    return { value: arr, next: j + 1 };
  }
  return { value: null, next: i + 1 };
}

function tokenizePlist(xml) {
  const tokens = [];
  const re =
    /<(key)>([\s\S]*?)<\/key>|<(string)>([\s\S]*?)<\/string>|<(integer)>([\s\S]*?)<\/integer>|<(real)>([\s\S]*?)<\/real>|<(data)>([\s\S]*?)<\/data>|<true\s*\/>|<false\s*\/>|<dict\b[^>]*>|<\/dict>|<array\b[^>]*>|<\/array>/g;
  let m;
  while ((m = re.exec(xml)) !== null) {
    if (m[1] === 'key') tokens.push({ type: 'key', text: m[2] });
    else if (m[3] === 'string') tokens.push({ type: 'string', text: m[4] });
    else if (m[5] === 'integer') tokens.push({ type: 'integer', text: m[6] });
    else if (m[7] === 'real') tokens.push({ type: 'real', text: m[8] });
    else if (m[9] === 'data') tokens.push({ type: 'data', text: m[10] });
    else if (m[0].startsWith('<true')) tokens.push({ type: 'true' });
    else if (m[0].startsWith('<false')) tokens.push({ type: 'false' });
    else if (m[0].startsWith('<dict')) tokens.push({ type: 'dictOpen' });
    else if (m[0].startsWith('</dict')) tokens.push({ type: 'dictClose' });
    else if (m[0].startsWith('<array')) tokens.push({ type: 'arrayOpen' });
    else if (m[0].startsWith('</array')) tokens.push({ type: 'arrayClose' });
  }
  return tokens;
}

function flattenAttrs(node, out) {
  if (!node || typeof node !== 'object' || Array.isArray(node)) return out;
  for (const [k, v] of Object.entries(node)) {
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      flattenAttrs(v, out);
    } else if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') {
      out[k] = typeof v === 'boolean' ? (v ? 'true' : 'false') : String(v);
    }
  }
  return out;
}

function parseAttributeDict(xml) {
  const tokens = tokenizePlist(xml);
  // Find first dictOpen (top-level plist dict)
  let start = tokens.findIndex((t) => t.type === 'dictOpen');
  if (start === -1) {
    // Fallback: flat regex for key/string pairs (legacy getudid style)
    const attrs = {};
    const re =
      /<key>([^<]+)<\/key>\s*(?:<string>([^<]*)<\/string>|<integer>([^<]*)<\/integer>|<data>([^<]*)<\/data>)/g;
    let m;
    while ((m = re.exec(xml)) !== null) {
      const key = m[1].trim();
      if (m[2] !== undefined) attrs[key] = unescapeXml(m[2]);
      else if (m[3] !== undefined) attrs[key] = m[3].trim();
      else if (m[4] !== undefined) attrs[key] = m[4].replace(/\s+/g, '');
    }
    return attrs;
  }
  const parsed = parsePlistValue(tokens, start);
  return flattenAttrs(parsed.value || {}, {});
}

/**
 * Modern UDID (A12+ / post-2018): CHIPID(8 hex)-ECID(16 hex).
 * See The iPhone Wiki UDID page / kakel ECID decode.
 * Profile Service often returns UDID but omits ECID on recent iOS.
 */
function ecidFromUdid(udid) {
  if (!udid) return null;
  const m = String(udid).trim().match(/^([0-9A-Fa-f]{8})-([0-9A-Fa-f]{16})$/);
  if (!m) return null;
  return m[2];
}

function normalizeEcid(raw) {
  if (raw === undefined || raw === null || raw === '') return null;
  let s = String(raw).trim();
  if (/^0x[0-9a-fA-F]+$/i.test(s)) s = s.slice(2);
  // Prefer hex when value is hex digits (ECID attribute may be integer OR hex string;
  // UDID-derived values are always 16 hex digits).
  if (/^[0-9a-fA-F]+$/.test(s) && (/[a-fA-F]/.test(s) || s.length >= 8)) {
    const hex = s.toLowerCase().replace(/^0+/, '') || '0';
    let dec = '';
    try {
      dec = BigInt('0x' + hex).toString(10);
    } catch (_) {}
    return { hex, decimal: dec, raw: s, padded16: s.toLowerCase().padStart(16, '0').slice(-16) };
  }
  if (/^\d+$/.test(s)) {
    let hex = '';
    try {
      hex = BigInt(s).toString(16);
    } catch (_) {}
    return { hex, decimal: s, raw: s, padded16: hex.padStart(16, '0') };
  }
  return { hex: s, decimal: '', raw: s };
}

function parseDeviceResponse(rawBody) {
  const xml = extractPlistXml(rawBody);
  if (!xml) {
    return { ok: false, error: 'no_plist' };
  }
  const attrs = parseAttributeDict(xml);
  // Apple Phase-2 sample uses CHALLENGE (all caps); some stacks use Challenge
  const challenge = attrs.Challenge || attrs.CHALLENGE || '';
  let ecid = attrs.ECID || attrs.ecid || '';
  const udid = attrs.UDID || attrs.udid || '';
  const product = attrs.PRODUCT || attrs.Product || '';
  const version = attrs.VERSION || attrs.Version || '';

  // Modern iOS often omits ECID from DeviceAttributes even when requested.
  // Working get-ecid style tools derive it from the UDID suffix.
  let ecidSource = ecid ? 'attribute' : '';
  if (!ecid && udid) {
    const derived = ecidFromUdid(udid);
    if (derived) {
      ecid = derived;
      ecidSource = 'udid';
    }
  }

  if (!udid && !ecid && !product) {
    return {
      ok: false,
      error: 'empty_attrs',
      xmlPreview: xml.slice(0, 400),
      keys: Object.keys(attrs),
    };
  }

  return {
    ok: true,
    attrs: {
      ECID: ecid,
      UDID: udid,
      PRODUCT: product,
      VERSION: version,
      Challenge: challenge,
      ECID_SOURCE: ecidSource,
    },
    ecidInfo: normalizeEcid(ecid),
    ecidSource,
    xmlPreview: xml.slice(0, 400),
    keys: Object.keys(attrs),
  };
}

module.exports = {
  extractPlistXml,
  parseAttributeDict,
  normalizeEcid,
  ecidFromUdid,
  parseDeviceResponse,
};
