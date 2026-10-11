/**
 * Tiny dependency-free ZIP reader for IPA validation. Reads the central directory
 * from a file on disk (no whole-file buffering) and can inflate single entries.
 * ZIP64 is supported for the central directory locator only as far as IPAs need.
 */
const fs = require('fs');
const zlib = require('zlib');

function readAt(fd, pos, len) {
  const b = Buffer.alloc(len);
  let off = 0;
  while (off < len) {
    const n = fs.readSync(fd, b, off, len - off, pos + off);
    if (n === 0) break;
    off += n;
  }
  return off === len ? b : b.slice(0, off);
}

function listEntries(path, { maxEntries = 50000 } = {}) {
  const fd = fs.openSync(path, 'r');
  try {
    const size = fs.fstatSync(fd).size;
    if (size < 22) throw new Error('not_a_zip');
    const tailLen = Math.min(size, 65535 + 22 + 20);
    const tail = readAt(fd, size - tailLen, tailLen);
    let eocd = -1;
    for (let i = tail.length - 22; i >= 0; i--) {
      if (tail.readUInt32LE(i) === 0x06054b50) {
        eocd = i;
        break;
      }
    }
    if (eocd < 0) throw new Error('not_a_zip');
    let count = tail.readUInt16LE(eocd + 10);
    let cdSize = tail.readUInt32LE(eocd + 12);
    let cdOff = tail.readUInt32LE(eocd + 16);
    if (count === 0xffff || cdSize === 0xffffffff || cdOff === 0xffffffff) {
      // ZIP64
      const locPos = eocd - 20;
      if (locPos < 0 || tail.readUInt32LE(locPos) !== 0x07064b50) throw new Error('bad_zip64');
      const z64Off = Number(tail.readBigUInt64LE(locPos + 8));
      const z64 = readAt(fd, z64Off, 56);
      if (z64.readUInt32LE(0) !== 0x06064b50) throw new Error('bad_zip64');
      count = Number(z64.readBigUInt64LE(32));
      cdSize = Number(z64.readBigUInt64LE(40));
      cdOff = Number(z64.readBigUInt64LE(48));
    }
    if (count > maxEntries) throw new Error('too_many_entries');
    if (cdOff + cdSize > size) throw new Error('bad_central_directory');
    const cd = readAt(fd, cdOff, cdSize);
    const entries = [];
    let p = 0;
    for (let i = 0; i < count; i++) {
      if (p + 46 > cd.length || cd.readUInt32LE(p) !== 0x02014b50) throw new Error('bad_central_directory');
      const flags = cd.readUInt16LE(p + 8);
      const method = cd.readUInt16LE(p + 10);
      let csize = cd.readUInt32LE(p + 20);
      let usize = cd.readUInt32LE(p + 24);
      const nlen = cd.readUInt16LE(p + 28);
      const elen = cd.readUInt16LE(p + 30);
      const clen = cd.readUInt16LE(p + 32);
      let lho = cd.readUInt32LE(p + 42);
      const name = cd.slice(p + 46, p + 46 + nlen).toString(flags & 0x800 ? 'utf8' : 'latin1');
      // zip64 extra
      const extra = cd.slice(p + 46 + nlen, p + 46 + nlen + elen);
      for (let e = 0; e + 4 <= extra.length; ) {
        const id = extra.readUInt16LE(e);
        const sz = extra.readUInt16LE(e + 2);
        if (id === 1) {
          let q = e + 4;
          if (usize === 0xffffffff) { usize = Number(extra.readBigUInt64LE(q)); q += 8; }
          if (csize === 0xffffffff) { csize = Number(extra.readBigUInt64LE(q)); q += 8; }
          if (lho === 0xffffffff) { lho = Number(extra.readBigUInt64LE(q)); q += 8; }
        }
        e += 4 + sz;
      }
      entries.push({ name, method, csize, usize, lho, encrypted: Boolean(flags & 1) });
      p += 46 + nlen + elen + clen;
    }
    return entries;
  } finally {
    fs.closeSync(fd);
  }
}

/** Unsafe if absolute, contains .. segments, backslashes or NULs (zip-slip). */
function isSafeName(name) {
  if (!name || name.includes('\0') || name.includes('\\')) return false;
  if (name.startsWith('/') || /^[A-Za-z]:/.test(name)) return false;
  return !name.split('/').some((seg) => seg === '..');
}

/**
 * Read up to `limit` bytes of an entry's uncompressed data (prefix read; stops early).
 * @returns {Promise<Buffer>}
 */
async function readEntry(path, entry, limit = 16 * 1024 * 1024) {
  if (entry.encrypted) throw new Error('encrypted_entry');
  const fd = fs.openSync(path, 'r');
  let dataStart;
  try {
    const lh = readAt(fd, entry.lho, 30);
    if (lh.length < 30 || lh.readUInt32LE(0) !== 0x04034b50) throw new Error('bad_local_header');
    dataStart = entry.lho + 30 + lh.readUInt16LE(26) + lh.readUInt16LE(28);
  } finally {
    fs.closeSync(fd);
  }
  if (entry.method !== 0 && entry.method !== 8) throw new Error('unsupported_compression');
  if (entry.csize === 0) return Buffer.alloc(0);
  const src = fs.createReadStream(path, { start: dataStart, end: dataStart + entry.csize - 1 });
  const stream = entry.method === 8 ? src.pipe(zlib.createInflateRaw()) : src;
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let done = false;
    const finish = (err) => {
      if (done) return;
      done = true;
      src.destroy();
      if (stream !== src) stream.destroy();
      if (err) return reject(err);
      resolve(Buffer.concat(chunks).slice(0, limit));
    };
    stream.on('data', (c) => {
      chunks.push(c);
      total += c.length;
      if (total >= limit) finish();
    });
    stream.on('end', () => finish());
    stream.on('error', (e) => finish(e));
    src.on('error', (e) => finish(e));
  });
}

module.exports = { listEntries, readEntry, isSafeName };
