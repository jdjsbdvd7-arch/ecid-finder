const zlib = require('zlib');
const crypto = require('crypto');

function crc32(buf) {
  let c, crc = 0xffffffff;
  for (let n = 0; n < buf.length; n++) {
    c = (crc ^ buf[n]) & 0xff;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    crc = (crc >>> 8) ^ c;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/** Minimal ZIP writer for fixtures. files: [{name, data:Buffer, store?:boolean}] */
function makeZip(files) {
  const locals = [];
  const cds = [];
  let offset = 0;
  for (const f of files) {
    const name = Buffer.from(f.name, 'utf8');
    const method = f.store ? 0 : 8;
    const comp = method ? zlib.deflateRawSync(f.data) : f.data;
    const crc = crc32(f.data);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0x800, 6); lh.writeUInt16LE(method, 8);
    lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(f.data.length, 22); lh.writeUInt16LE(name.length, 26);
    locals.push(lh, name, comp);
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(20, 4); cd.writeUInt16LE(20, 6); cd.writeUInt16LE(0x800, 8); cd.writeUInt16LE(method, 10);
    cd.writeUInt32LE(crc, 16); cd.writeUInt32LE(comp.length, 20); cd.writeUInt32LE(f.data.length, 24); cd.writeUInt16LE(name.length, 28);
    cd.writeUInt32LE(offset, 42);
    cds.push(cd, name);
    offset += 30 + name.length + comp.length;
  }
  const cdBuf = Buffer.concat(cds);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(files.length, 8); eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12); eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cdBuf, eocd]);
}

function infoPlistXml(o = {}) {
  const d = { CFBundleIdentifier: 'com.example.hello', CFBundleName: 'Hello', CFBundleExecutable: 'Hello', CFBundleShortVersionString: '1.2.3', CFBundleVersion: '42', ...o };
  return Buffer.from(
    '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>' +
      Object.entries(d).map(([k, v]) => `<key>${k}</key><string>${v}</string>`).join('') +
      '</dict></plist>'
  );
}

/** Minimal arm64 Mach-O with optional LC_ENCRYPTION_INFO_64 (cryptid). */
function fakeMachO({ cryptid = null } = {}) {
  const lcs = [];
  if (cryptid !== null) {
    const lc = Buffer.alloc(24);
    lc.writeUInt32LE(0x2c, 0); lc.writeUInt32LE(24, 4); lc.writeUInt32LE(cryptid, 16);
    lcs.push(lc);
  }
  const body = Buffer.concat(lcs);
  const h = Buffer.alloc(32);
  h.writeUInt32LE(0xfeedfacf, 0); h.writeInt32LE(0x0100000c, 4); h.writeUInt32LE(lcs.length, 16); h.writeUInt32LE(body.length, 20);
  return Buffer.concat([h, body, crypto.randomBytes(256)]);
}

function makeIpa({ plist, macho, extra = [] } = {}) {
  return makeZip([
    { name: 'Payload/', data: Buffer.alloc(0), store: true },
    { name: 'Payload/Hello.app/Info.plist', data: plist || infoPlistXml() },
    { name: 'Payload/Hello.app/Hello', data: macho || fakeMachO() },
    ...extra,
  ]);
}

module.exports = { makeZip, makeIpa, infoPlistXml, fakeMachO };
