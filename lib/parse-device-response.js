/**
 * Device POSTs a CMS/PKCS#7 signed plist. The XML plist is embedded in cleartext
 * inside the signedData; extract between <?xml ... </plist> (public OTA pattern
 * used by getudid / iOS-UDID-Safari / Apple OTA docs).
 */
function extractPlistXml(raw) {
  const buffers = [];
  if (Buffer.isBuffer(raw)) {
    buffers.push(raw.toString('utf8'), raw.toString('latin1'));
  } else {
    buffers.push(String(raw || ''));
  }
  for (const source of buffers) {
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
 * alternating <key>NAME</key> then <string>|integer|data|true|false.
 * Device responses use uppercase keys like CHALLENGE (Apple OTA samples).
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

function pick(attrs, ...names) {
  for (const n of names) {
    if (attrs[n] !== undefined && attrs[n] !== '') return attrs[n];
  }
  return '';
}

function normalizeEcid(raw) {
  if (raw === undefined || raw === null || raw === '') return null;
  let s = String(raw).trim();
  if (/^0x[0-9a-fA-F]+$/i.test(s)) s = s.slice(2);
  if (/^[0-9a-fA-F]+$/.test(s) && /[a-fA-F]/.test(s)) {
    const hex = s.toLowerCase().replace(/^0+/, '') || '0';
    let dec = '';
    try {
      dec = BigInt('0x' + hex).toString(10);
    } catch {
      /* ignore */
    }
    return { hex, decimal: dec, raw: s };
  }
  if (/^\d+$/.test(s)) {
    let hex = '';
    try {
      hex = BigInt(s).toString(16);
    } catch {
      /* ignore */
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
  const ecidRaw = pick(attrs, 'ECID', 'ecid');
  const ecidInfo = normalizeEcid(ecidRaw);
  return {
    ok: true,
    attrs: {
      ECID: ecidRaw,
      UDID: pick(attrs, 'UDID', 'udid'),
      PRODUCT: pick(attrs, 'PRODUCT', 'PRODUCT_NAME'),
      VERSION: pick(attrs, 'VERSION'),
      // Apple samples return CHALLENGE (uppercase)
      Challenge: pick(attrs, 'CHALLENGE', 'Challenge', 'challenge'),
      DEVICE_NAME: pick(attrs, 'DEVICE_NAME'),
      SERIAL: pick(attrs, 'SERIAL'),
      MAC_ADDRESS_EN0: pick(attrs, 'MAC_ADDRESS_EN0'),
    },
    ecidInfo,
    xmlPreview: xml.slice(0, 240),
  };
}

module.exports = {
  extractPlistXml,
  parseAttributeDict,
  normalizeEcid,
  parseDeviceResponse,
};
