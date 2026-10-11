/**
 * ECID → UDID helpers (modern devices only).
 *
 * Devices with an A12 or newer SoC (iPhone XS/XR, 2018+) use the UDID format
 *   <CPID: 8 hex>-<ECID: 16 hex, zero padded>      e.g. 00008110-001965E62213801E
 * so the UDID can be formed from CPID + ECID. Older devices (A11 and earlier)
 * use a 40-hex SHA-1-style UDID that CANNOT be derived from an ECID.
 */

/** Model identifier → CPID (hex). Only models whose UDID uses the CPID-ECID format. */
const CPID_BY_PRODUCT = {
  // A12
  'iPhone11,2': '8020', 'iPhone11,4': '8020', 'iPhone11,6': '8020', 'iPhone11,8': '8020',
  'iPad11,6': '8020', 'iPad11,7': '8020', 'iPad11,1': '8020', 'iPad11,2': '8020', 'iPad11,3': '8020', 'iPad11,4': '8020',
  // A12X/A12Z
  'iPad8,1': '8027', 'iPad8,2': '8027', 'iPad8,3': '8027', 'iPad8,4': '8027', 'iPad8,5': '8027', 'iPad8,6': '8027',
  'iPad8,7': '8027', 'iPad8,8': '8027', 'iPad8,9': '8027', 'iPad8,10': '8027', 'iPad8,11': '8027', 'iPad8,12': '8027',
  // A13
  'iPhone12,1': '8030', 'iPhone12,3': '8030', 'iPhone12,5': '8030', 'iPhone12,8': '8030', 'iPad12,1': '8030', 'iPad12,2': '8030',
  // A14
  'iPhone13,1': '8101', 'iPhone13,2': '8101', 'iPhone13,3': '8101', 'iPhone13,4': '8101',
  'iPad13,1': '8101', 'iPad13,2': '8101', 'iPad13,18': '8101', 'iPad13,19': '8101',
  // M1
  'iPad13,4': '8103', 'iPad13,5': '8103', 'iPad13,6': '8103', 'iPad13,7': '8103',
  'iPad13,8': '8103', 'iPad13,9': '8103', 'iPad13,10': '8103', 'iPad13,11': '8103',
  'iPad13,16': '8103', 'iPad13,17': '8103',
  // A15
  'iPhone14,2': '8110', 'iPhone14,3': '8110', 'iPhone14,4': '8110', 'iPhone14,5': '8110',
  'iPhone14,6': '8110', 'iPhone14,7': '8110', 'iPhone14,8': '8110', 'iPad14,1': '8110', 'iPad14,2': '8110',
  // M2
  'iPad14,3': '8112', 'iPad14,4': '8112', 'iPad14,5': '8112', 'iPad14,6': '8112',
  'iPad14,8': '8112', 'iPad14,9': '8112', 'iPad14,10': '8112', 'iPad14,11': '8112',
  // A16
  'iPhone15,2': '8120', 'iPhone15,3': '8120', 'iPhone15,4': '8120', 'iPhone15,5': '8120',
  // A17 Pro
  'iPhone16,1': '8130', 'iPhone16,2': '8130',
  // A18 / A18 Pro
  'iPhone17,1': '8140', 'iPhone17,2': '8140', 'iPhone17,3': '8140', 'iPhone17,4': '8140', 'iPhone17,5': '8140',
};

/** Chips selectable in the UI when the model identifier is unknown. */
const CHIP_CHOICES = [
  { cpid: '8020', name: 'A12 Bionic' },
  { cpid: '8027', name: 'A12X / A12Z' },
  { cpid: '8030', name: 'A13 Bionic' },
  { cpid: '8101', name: 'A14 Bionic' },
  { cpid: '8103', name: 'M1' },
  { cpid: '8110', name: 'A15 Bionic' },
  { cpid: '8112', name: 'M2' },
  { cpid: '8120', name: 'A16 Bionic' },
  { cpid: '8130', name: 'A17 Pro' },
  { cpid: '8140', name: 'A18 / A18 Pro' },
];

/**
 * Parse an ECID given as decimal, 0x-hex, bare hex, or `dec:<digits>`.
 * A 16-digit all-numeric string is ambiguous (hex vs decimal); it is read as hex
 * (the UDID suffix is 16 hex digits) and flagged `ambiguous` so the UI can warn.
 */
function parseEcid(raw) {
  if (raw === undefined || raw === null) return null;
  let s = String(raw).trim().replace(/[\s_]/g, '');
  if (!s) return null;
  let v;
  let ambiguous = false;
  let interpretedAs = 'hex';
  try {
    if (/^dec:[0-9]+$/i.test(s)) {
      v = BigInt(s.slice(4));
      interpretedAs = 'decimal';
    } else if (/^0x[0-9a-f]+$/i.test(s)) v = BigInt(s);
    else if (/^[0-9]+$/.test(s) && s.length !== 16) {
      v = BigInt(s); // decimal
      interpretedAs = 'decimal';
    } else if (/^[0-9a-f]+$/i.test(s)) {
      v = BigInt('0x' + s); // hex (incl. 16-digit all-numeric)
      // A 16-digit all-numeric string could also be a decimal ECID.
      ambiguous = /^[0-9]{16}$/.test(s);
    } else return null;
  } catch (_) {
    return null;
  }
  if (v <= 0n || v >= 1n << 64n) return null;
  const hex = v.toString(16);
  return {
    hex,
    decimal: v.toString(10),
    padded: hex.padStart(16, '0').toUpperCase(),
    interpretedAs,
    ambiguous,
  };
}

function parseCpid(raw) {
  if (raw === undefined || raw === null) return null;
  let s = String(raw).trim().replace(/^0x/i, '');
  if (!/^[0-9a-f]{1,8}$/i.test(s)) return null;
  return s.padStart(8, '0').toUpperCase();
}

function isModernUdid(u) {
  return typeof u === 'string' && /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}$/.test(u.trim());
}

function isLegacyUdid(u) {
  return typeof u === 'string' && /^[0-9A-Fa-f]{40}$/.test(u.trim());
}

function cpidForProduct(product) {
  return CPID_BY_PRODUCT[String(product || '').trim()] || null;
}

/**
 * Build a UDID from user input.
 * @param {{ecid: string, cpid?: string, udid?: string, product?: string}} input
 * @returns {{ok: true, udid, cpid, ecid, source} | {ok: false, error, message}}
 */
function deriveUdid(input) {
  const ecid = parseEcid(input.ecid);
  const given = (input.udid || '').trim();
  if (given) {
    if (isLegacyUdid(given)) {
      return { ok: true, udid: given.toLowerCase(), cpid: null, ecid, source: 'user_udid_legacy' };
    }
    if (!isModernUdid(given)) {
      return { ok: false, error: 'bad_udid', message: 'UDID must be 8hex-16hex (A12+) or 40 hex.' };
    }
    const [c, e] = given.toUpperCase().split('-');
    if (ecid && ecid.padded !== e) {
      return { ok: false, error: 'udid_ecid_mismatch', message: 'The ECID does not match the UDID suffix.' };
    }
    return {
      ok: true,
      udid: given.toUpperCase(),
      cpid: c,
      ecid: ecid || parseEcid(e),
      source: 'user_udid',
    };
  }
  if (!ecid) return { ok: false, error: 'bad_ecid', message: 'ECID is missing or invalid.' };
  let cpid = parseCpid(input.cpid);
  let source = 'ecid_plus_cpid';
  if (!cpid && input.cpid) {
    return { ok: false, error: 'bad_cpid', message: 'CPID must be 1-8 hex digits (for example 8110).' };
  }
  if (!cpid) {
    const fromProduct = cpidForProduct(input.product);
    if (fromProduct) {
      cpid = parseCpid(fromProduct);
      source = 'ecid_plus_product';
    }
  }
  if (!cpid) {
    return {
      ok: false,
      error: 'need_cpid',
      message:
        'A chip id (CPID) or a model identifier is required to form the UDID. Devices older than A12 use a 40-hex UDID that cannot be derived from an ECID.',
    };
  }
  return { ok: true, udid: `${cpid}-${ecid.padded}`, cpid, ecid, source };
}

module.exports = {
  CPID_BY_PRODUCT,
  CHIP_CHOICES,
  parseEcid,
  parseCpid,
  isModernUdid,
  isLegacyUdid,
  cpidForProduct,
  deriveUdid,
};
