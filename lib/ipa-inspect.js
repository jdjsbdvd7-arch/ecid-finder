/**
 * Validate and describe a user-supplied IPA without extracting it.
 * Heuristic checks only; real signing happens in the signer worker.
 */
const fs = require('fs');
const { listEntries, readEntry, isSafeName } = require('./zip-lite');
const { parsePlist } = require('./plist-lite');

const MAX_ENTRIES = 50000;

function machoInfo(buf) {
  // Returns {ok, encrypted, archs}
  if (buf.length < 8) return { ok: false };
  const magicBE = buf.readUInt32BE(0);
  const FAT = [0xcafebabe, 0xcafebabf];
  const THIN_LE = [0xfeedface, 0xfeedfacf]; // as read BE on little-endian files
  const THIN_LE_BYTES = [0xcefaedfe, 0xcffaedfe];
  const slices = [];
  if (FAT.includes(magicBE)) {
    const is64 = magicBE === 0xcafebabf;
    const n = buf.readUInt32BE(4);
    for (let i = 0; i < Math.min(n, 8); i++) {
      const base = 8 + i * (is64 ? 32 : 20);
      if (base + 20 > buf.length) break;
      const offset = is64 ? Number(buf.readBigUInt64BE(base + 8)) : buf.readUInt32BE(base + 8);
      slices.push({ offset, cputype: buf.readInt32BE(base) });
    }
  } else if (THIN_LE_BYTES.includes(magicBE) || THIN_LE.includes(magicBE)) {
    slices.push({ offset: 0 });
  } else {
    return { ok: false };
  }
  let encrypted = false;
  let checked = 0;
  const archs = [];
  for (const sl of slices) {
    const o = sl.offset;
    if (o + 32 > buf.length) continue; // slice beyond the prefix we read
    const magic = buf.readUInt32LE(o);
    const is64 = magic === 0xfeedfacf;
    if (!is64 && magic !== 0xfeedface) continue;
    const cputype = buf.readInt32LE(o + 4);
    archs.push(cputype === 0x0100000c ? 'arm64' : cputype === 12 ? 'arm' : String(cputype));
    const ncmds = buf.readUInt32LE(o + 16);
    let p = o + (is64 ? 32 : 28);
    for (let i = 0; i < ncmds && p + 8 <= buf.length; i++) {
      const cmd = buf.readUInt32LE(p);
      const size = buf.readUInt32LE(p + 4);
      if (size < 8) break;
      if ((cmd === 0x21 || cmd === 0x2c) && p + 20 <= buf.length) {
        // LC_ENCRYPTION_INFO / _64
        checked++;
        if (buf.readUInt32LE(p + 16) !== 0) encrypted = true;
      }
      p += size;
    }
  }
  return { ok: archs.length > 0, encrypted, archs, encryptionInfoSeen: checked > 0 };
}

/**
 * @param {string} path
 * @returns {Promise<{ok:true, info:object, warnings:string[]} | {ok:false, error:string, message:string}>}
 */
async function inspectIpa(path) {
  const warnings = [];
  let st;
  try {
    st = fs.statSync(path);
  } catch (_) {
    return { ok: false, error: 'missing', message: 'File not found.' };
  }
  let head = Buffer.alloc(4);
  const fd = fs.openSync(path, 'r');
  try {
    fs.readSync(fd, head, 0, 4, 0);
  } finally {
    fs.closeSync(fd);
  }
  if (head.readUInt32LE(0) !== 0x04034b50) {
    return { ok: false, error: 'not_zip', message: 'Not a ZIP/IPA file (bad magic bytes).' };
  }
  let entries;
  try {
    entries = listEntries(path, { maxEntries: MAX_ENTRIES });
  } catch (e) {
    return { ok: false, error: 'bad_zip', message: 'Corrupt or unsupported ZIP: ' + e.message };
  }
  for (const e of entries) {
    if (!isSafeName(e.name)) {
      return { ok: false, error: 'unsafe_path', message: 'IPA contains an unsafe path entry: ' + e.name.slice(0, 80) };
    }
  }
  const totalUncompressed = entries.reduce((a, e) => a + e.usize, 0);
  if (totalUncompressed > 8 * 1024 ** 3 || totalUncompressed > st.size * 1000 + 1e8) {
    return { ok: false, error: 'zip_bomb', message: 'Archive expands to an implausible size.' };
  }
  const plistEntry = entries.find((e) => /^Payload\/[^/]+\.app\/Info\.plist$/.test(e.name));
  if (!plistEntry) {
    return { ok: false, error: 'no_app', message: 'No Payload/<App>.app/Info.plist found. Is this an iOS .ipa?' };
  }
  let info;
  try {
    const raw = await readEntry(path, plistEntry, 2 * 1024 * 1024);
    info = parsePlist(raw);
  } catch (e) {
    return { ok: false, error: 'bad_plist', message: 'Could not read Info.plist: ' + e.message };
  }
  const bundleId = info.CFBundleIdentifier;
  if (typeof bundleId !== 'string' || !/^[A-Za-z0-9.\-]{1,155}$/.test(bundleId)) {
    return { ok: false, error: 'bad_bundle_id', message: 'Missing or invalid CFBundleIdentifier.' };
  }
  const appDir = plistEntry.name.replace(/Info\.plist$/, '');
  const exeName = info.CFBundleExecutable;
  let macho = null;
  if (typeof exeName === 'string') {
    const exe = entries.find((e) => e.name === appDir + exeName);
    if (!exe) {
      return { ok: false, error: 'no_executable', message: `Executable ${exeName} not found in the bundle.` };
    }
    try {
      macho = machoInfo(await readEntry(path, exe, 256 * 1024));
    } catch (e) {
      warnings.push('Could not inspect the main executable: ' + e.message);
    }
    if (macho && !macho.ok) warnings.push('Main executable does not look like a Mach-O binary.');
    if (macho && macho.ok && !macho.archs.includes('arm64')) {
      warnings.push('Executable has no arm64 slice; it will not run on modern devices.');
    }
    if (macho && macho.encrypted) {
      return {
        ok: false,
        error: 'fairplay_encrypted',
        message:
          'This IPA is FairPlay-encrypted (an App Store download tied to an Apple ID). It cannot be re-signed. Use a decrypted IPA you are entitled to use, or your own build.',
      };
    }
  }
  const dsStore = entries.some((e) => e.name.endsWith('.app/embedded.mobileprovision'));
  const exts = entries.filter((e) => /\.appex\/Info\.plist$/.test(e.name)).length;
  const frameworks = entries.filter((e) => /\.framework\/Info\.plist$/.test(e.name)).length;
  if (exts > 0) warnings.push(`${exts} app extension(s) found; each needs its own App ID (free accounts: 10 App IDs / week).`);
  if (isReservedBundleId(bundleId)) {
    warnings.push(
      `معرّف الحزمة ${bundleId} محجوز لشركة Apple ولا يمكن تسجيله في حساب مجاني؛ سيُغيَّر تلقائياً إلى معرّف فريد عند التوقيع (يمكنك تحديد معرّف خاص في الخطوة 3). · Bundle ID ${bundleId} is reserved by Apple and cannot be registered on a free account; it will be automatically changed to a unique ID when signing (you can set your own in step 3).`
    );
  }
  if (dsStore) warnings.push('An existing embedded.mobileprovision will be replaced.');
  return {
    ok: true,
    info: {
      bundleId,
      reservedBundleId: isReservedBundleId(bundleId),
      name: info.CFBundleDisplayName || info.CFBundleName || exeName || bundleId,
      version: info.CFBundleShortVersionString || '',
      build: info.CFBundleVersion || '',
      minOS: info.MinimumOSVersion || '',
      deviceFamily: info.UIDeviceFamily || [],
      executable: exeName || '',
      entries: entries.length,
      extensions: exts,
      frameworks,
      size: st.size,
      archs: macho && macho.archs ? macho.archs : [],
    },
    warnings,
  };
}

/** Identifiers a free Personal Team can never register (Apple error 9400). */
function isReservedBundleId(id) {
  return /^com\.apple(\.|$)/i.test(String(id || ''));
}

module.exports = { inspectIpa, machoInfo, isReservedBundleId };
