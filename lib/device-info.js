/**
 * Device marketing names, chip map (UDID CHIP- prefix), and Apple build-id heuristics.
 * Heuristics only — research helper, not an official Apple catalog.
 */

const MARKETING = {
  'iPhone14,2': 'iPhone 13 Pro',
  'iPhone14,3': 'iPhone 13 Pro Max',
  'iPhone14,4': 'iPhone 13 mini',
  'iPhone14,5': 'iPhone 13',
  'iPhone14,6': 'iPhone SE (3rd generation)',
  'iPhone14,7': 'iPhone 14',
  'iPhone14,8': 'iPhone 14 Plus',
  'iPhone15,2': 'iPhone 14 Pro',
  'iPhone15,3': 'iPhone 14 Pro Max',
  'iPhone15,4': 'iPhone 15',
  'iPhone15,5': 'iPhone 15 Plus',
  'iPhone16,1': 'iPhone 15 Pro',
  'iPhone16,2': 'iPhone 15 Pro Max',
  'iPhone17,1': 'iPhone 16 Pro',
  'iPhone17,2': 'iPhone 16 Pro Max',
  'iPhone17,3': 'iPhone 16',
  'iPhone17,4': 'iPhone 16 Plus',
  'iPhone17,5': 'iPhone 16e',
  'iPhone13,1': 'iPhone 12 mini',
  'iPhone13,2': 'iPhone 12',
  'iPhone13,3': 'iPhone 12 Pro',
  'iPhone13,4': 'iPhone 12 Pro Max',
  'iPhone12,1': 'iPhone 11',
  'iPhone12,3': 'iPhone 11 Pro',
  'iPhone12,5': 'iPhone 11 Pro Max',
  'iPhone12,8': 'iPhone SE (2nd generation)',
  'iPad13,16': 'iPad Air (5th generation)',
  'iPad14,1': 'iPad mini (6th generation)',
};

/** UDID prefix (8 hex chars) → chip label */
const CHIP_BY_PREFIX = {
  '00008110': { name: 'A15 Bionic', soc: 'T8110', cpid: 0x8110 },
  '00008120': { name: 'A16 Bionic', soc: 'T8120', cpid: 0x8120 },
  '00008130': { name: 'A17 Pro', soc: 'T8130', cpid: 0x8130 },
  '00008140': { name: 'A18', soc: 'T8140', cpid: 0x8140 },
  '00008030': { name: 'A14 Bionic', soc: 'T8030', cpid: 0x8030 },
  '00008020': { name: 'A13 Bionic', soc: 'T8020', cpid: 0x8020 },
  '00008010': { name: 'A12 Bionic', soc: 'T8015/T8020-era', cpid: 0x8010 },
  '00008098': { name: 'A12X/A12Z', soc: 'T8027', cpid: 0x8098 },
};

/** Build major → typical marketed iOS major (post-renumber era included). */
const BUILD_MAJOR_TO_IOS = {
  19: 15,
  20: 16,
  21: 17,
  22: 18,
  23: 26,
  24: 27,
  25: 28,
};

const TRAIN_HINT = {
  A: { en: 'A-train (typically fall / first release train)', ar: 'قطار A (عادة خريف / أول إصدار)' },
  B: { en: 'B-train (often winter/spring)', ar: 'قطار B (غالباً شتاء/ربيع)' },
  C: { en: 'C-train', ar: 'قطار C' },
  D: { en: 'D-train', ar: 'قطار D' },
  E: { en: 'E-train', ar: 'قطار E' },
  F: { en: 'F-train', ar: 'قطار F' },
  G: { en: 'G-train (often late summer)', ar: 'قطار G (غالباً أواخر الصيف)' },
  H: { en: 'H-train', ar: 'قطار H' },
};

function marketingName(product) {
  if (!product) return '';
  return MARKETING[product] || '';
}

function chipFromUdid(udid) {
  if (!udid || typeof udid !== 'string') return null;
  const m = udid.trim().toUpperCase().match(/^([0-9A-F]{8})-/);
  if (!m) return null;
  const prefix = m[1].toLowerCase().padStart(8, '0');
  // normalize: keep as returned in UDID (usually already 00008110)
  const key = m[1].toLowerCase();
  const padded = key.length === 8 ? key : key.padStart(8, '0');
  const info = CHIP_BY_PREFIX[padded] || CHIP_BY_PREFIX[key];
  if (info) {
    return { prefix: padded, ...info };
  }
  const cpid = parseInt(padded, 16);
  return {
    prefix: padded,
    name: 'Unknown chip',
    soc: `CPID 0x${padded}`,
    cpid: Number.isFinite(cpid) ? cpid : null,
  };
}

/**
 * Decode Apple-style build ids like 24A446 (GM-ish) or 24B5089g (beta/seed-ish).
 */
function decodeBuild(build) {
  if (!build || typeof build !== 'string') {
    return { ok: false, reason: 'empty' };
  }
  const raw = build.trim();
  const m = raw.match(/^(\d{1,2})([A-Z])(\d+)([a-z])?$/);
  if (!m) {
    return { ok: false, reason: 'unparsed', raw };
  }
  const major = parseInt(m[1], 10);
  const train = m[2];
  const rev = m[3];
  const seedLetter = m[4] || '';
  const iosMajor = BUILD_MAJOR_TO_IOS[major] || null;
  const trainHint = TRAIN_HINT[train] || {
    en: `${train}-train`,
    ar: `قطار ${train}`,
  };

  // Heuristic: trailing lowercase seed letter, or unusually long revision digits,
  // strongly suggests Developer Beta / Seed rather than public GM.
  const longRev = rev.length >= 4;
  const isBetaLike = Boolean(seedLetter) || longRev;
  const kind = isBetaLike ? 'beta_or_seed' : 'release_like';

  return {
    ok: true,
    raw,
    major,
    train,
    revision: rev,
    seedLetter: seedLetter || null,
    iosMajor,
    iosHint: iosMajor ? `iOS ${iosMajor}.x (approx.)` : 'unknown iOS major',
    iosHintAr: iosMajor ? `iOS ${iosMajor}.x تقريباً` : 'إصدار iOS غير محدد',
    trainHintEn: trainHint.en,
    trainHintAr: trainHint.ar,
    kind,
    kindEn: isBetaLike
      ? 'Likely Developer Beta / Seed build (not a typical public GM tag)'
      : 'Looks like a release-style (GM/public) build id',
    kindAr: isBetaLike
      ? 'يبدو بناء تجريبي / Seed للمطوّرين (ليس وسم إصدار عام نموذجي)'
      : 'يشبه رقم بناء إصدار عام (GM/عام)',
  };
}

function buildDeviceCard({ product, udid, version, ecidHex, ecidDecimal }) {
  const marketing = marketingName(product);
  const chip = chipFromUdid(udid);
  const build = decodeBuild(version);
  return {
    product: product || '',
    marketingName: marketing || product || 'Unknown device',
    marketingNameAr: marketing
      ? marketing
      : product
        ? product
        : 'جهاز غير معروف',
    udid: udid || '',
    version: version || '',
    ecidHex: ecidHex || '',
    ecidDecimal: ecidDecimal || '',
    chip,
    build,
  };
}

module.exports = {
  MARKETING,
  CHIP_BY_PREFIX,
  marketingName,
  chipFromUdid,
  decodeBuild,
  buildDeviceCard,
};
