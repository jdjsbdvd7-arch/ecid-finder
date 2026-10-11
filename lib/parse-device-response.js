/**
 * Device POSTs a CMS/PKCS#7 signed plist. The XML plist is embedded in cleartext
 * inside the signedData; extract between <?xml ... </plist> (public OTA pattern).
 */
function extractPlistXml(raw) {
  const text = Buffer.isBuffer(raw) ? raw.toString('utf8') : String(raw || '');
  // Also try latin1 for binary CMS with embedded ASCII XML
  const latin = Buffer.isBuffer(raw) ? raw.toString('latin1') : text;
  for (const source of [text, latin]) {
    const begin = source.indexOf('<?xml');
    const endTag = '</plist>';
    const end = source.indexOf(endTag, begin);
    if (begin !== -1 && end !== -1) {
      return source.slice(begin, end + endTag.length);
    }
  }
  return null;
}

function unescapeXml(s) {
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

/**
 * Minimal plist dict parser for Profile Service responses:
 * alternating <key>NAME</key> then <string>|integer|data.
 */
function parseAttributeDict(xml) {
  const attrs = {};
  const re =
    /<key>([^<]+)<\/key>\s*(?:<string>([^<]*)<\/string>|<integer>([^<]*)<\/integer>|<data>([^<]*)<\/data>|<true\s*\/>|<false\s*\/>)/g;
  let m;
  while ((m = re.exec(xml)) !== null) {
    const key = m[1].trim();
    if (m[2] !== undefined) attrs[key] = unescapeXml(m[2]);
    else if (m[3] !== undefined) attrs[key] = m[3].trim();
    else if (m[4] !== undefined) attrs[key] = m[4].replace(/\s+/g, '');
  }
  return attrs;
}

function normalizeEcid(raw) {
  if (raw === undefined || raw === null || raw === '') return null;
  let s = String(raw).trim();
  // Sometimes hex with 0x prefix
  if (/^0x[0-9a-fA-F]+$/.test(s)) s = s.slice(2);
  // Pure hex
  if (/^[0-9a-fA-F]+$/.test(s) && /[a-fA-F]/.test(s)) {
    const hex = s.toLowerCase().replace(/^0+/, '') || '0';
    let dec;
    try {
      dec = BigInt('0x' + hex).toString(10);
    } catch {
      dec = '';
    }
    return { hex, decimal: dec, raw: s };
  }
  // Decimal integer string
  if (/^\d+$/.test(s)) {
    let hex;
    try {
      hex = BigInt(s).toString(16);
    } catch {
      hex = '';
    }
    return { hex, decimal: s, raw: s };
  }
  return { hex: s, decimal: '', raw: s };
}

function parseDeviceResponse(rawBody) {
  const xml = extractPlistXml(rawBody);
  if (!xml) {
    return { ok: false, error: 'no_plist' };
  }
  const attrs = parseAttributeDict(xml);
  const ecidInfo = normalizeEcid(attrs.ECID);
  return {
    ok: true,
    attrs: {
      ECID: attrs.ECID || '',
      UDID: attrs.UDID || '',
      PRODUCT: attrs.PRODUCT || '',
      VERSION: attrs.VERSION || '',
      Challenge: attrs.Challenge || '',
    },
    ecidInfo,
    xmlPreview: xml.slice(0, 200),
  };
}

module.exports = {
  extractPlistXml,
  parseAttributeDict,
  normalizeEcid,
  parseDeviceResponse,
};
