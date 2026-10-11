/** Minimal dependency-free plist reader (XML + binary bplist00) and XML writer. */

function parsePlist(buf) {
  if (typeof buf === 'string') buf = Buffer.from(buf, 'utf8');
  if (buf.length >= 8 && buf.slice(0, 6).toString('latin1') === 'bplist') return parseBinary(buf);
  return parseXml(buf.toString('utf8'));
}

/* ---------------- XML ---------------- */

function unescapeXml(s) {
  return s
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function parseXml(xml) {
  const body = xml.replace(/<\?xml[^>]*\?>/, '').replace(/<!DOCTYPE[^>]*>/, '').replace(/<!--[\s\S]*?-->/g, '');
  const tokenRe = /<(\/?)([A-Za-z]+)(?:\s[^>]*?)?(\/?)>|([^<]+)/g;
  const tokens = [];
  let m;
  while ((m = tokenRe.exec(body))) {
    if (m[4] !== undefined) tokens.push({ t: 'text', v: m[4] });
    else tokens.push({ t: m[1] ? 'close' : m[3] ? 'empty' : 'open', n: m[2] });
  }
  let i = 0;
  const skipWs = () => {
    while (i < tokens.length && tokens[i].t === 'text' && !tokens[i].v.trim()) i++;
  };
  function readValue() {
    skipWs();
    const tk = tokens[i++];
    if (!tk) throw new Error('plist: unexpected end');
    if (tk.t === 'empty') {
      if (tk.n === 'true') return true;
      if (tk.n === 'false') return false;
      if (tk.n === 'string') return '';
      if (tk.n === 'array') return [];
      if (tk.n === 'dict') return {};
      if (tk.n === 'data') return Buffer.alloc(0);
      throw new Error('plist: bad empty tag ' + tk.n);
    }
    if (tk.t !== 'open') throw new Error('plist: expected open tag');
    let result;
    switch (tk.n) {
      case 'plist':
        result = readValue();
        break;
      case 'dict': {
        result = {};
        for (;;) {
          skipWs();
          if (tokens[i].t === 'close') break;
          const k = tokens[i++];
          if (k.n !== 'key') throw new Error('plist: expected key');
          const kv = tokens[i].t === 'text' ? unescapeXml(tokens[i++].v) : '';
          if (tokens[i].t === 'close') i++;
          result[kv] = readValue();
        }
        break;
      }
      case 'array': {
        result = [];
        for (;;) {
          skipWs();
          if (tokens[i].t === 'close') break;
          result.push(readValue());
        }
        break;
      }
      default: {
        let text = '';
        if (tokens[i] && tokens[i].t === 'text') text = tokens[i++].v;
        if (tk.n === 'string') result = unescapeXml(text);
        else if (tk.n === 'integer') result = Number(text.trim());
        else if (tk.n === 'real') result = parseFloat(text.trim());
        else if (tk.n === 'date') result = new Date(text.trim());
        else if (tk.n === 'data') result = Buffer.from(text.replace(/\s+/g, ''), 'base64');
        else result = unescapeXml(text);
      }
    }
    if (tokens[i] && tokens[i].t === 'close') i++;
    return result;
  }
  return readValue();
}

/* ---------------- binary ---------------- */

function parseBinary(buf) {
  if (buf.length < 40) throw new Error('bplist: too short');
  const trailer = buf.length - 32;
  const offSize = buf[trailer + 6];
  const refSize = buf[trailer + 7];
  const numObjects = Number(buf.readBigUInt64BE(trailer + 8));
  const topObject = Number(buf.readBigUInt64BE(trailer + 16));
  const offTable = Number(buf.readBigUInt64BE(trailer + 24));
  if (numObjects > 1e6 || offSize < 1 || offSize > 8 || refSize < 1 || refSize > 8) {
    throw new Error('bplist: bad trailer');
  }
  const readUInt = (pos, size) => {
    let v = 0n;
    for (let k = 0; k < size; k++) v = (v << 8n) | BigInt(buf[pos + k]);
    return Number(v);
  };
  const offsetOf = (idx) => readUInt(offTable + idx * offSize, offSize);
  const depthLimit = 64;
  function parseObj(idx, depth) {
    if (depth > depthLimit) throw new Error('bplist: too deep');
    let pos = offsetOf(idx);
    const marker = buf[pos];
    const hi = marker >> 4;
    const lo = marker & 0x0f;
    const readLen = () => {
      if (lo !== 0x0f) return { len: lo, start: pos + 1 };
      const sz = 1 << (buf[pos + 1] & 0x0f);
      return { len: readUInt(pos + 2, sz), start: pos + 2 + sz };
    };
    switch (hi) {
      case 0x0:
        return lo === 0x8 ? false : lo === 0x9 ? true : null;
      case 0x1: {
        const sz = 1 << lo;
        if (sz > 8) return Number(readUInt(pos + 1, sz));
        return readUInt(pos + 1, sz);
      }
      case 0x2:
        return lo === 2 ? buf.readFloatBE(pos + 1) : buf.readDoubleBE(pos + 1);
      case 0x3:
        return new Date(Date.UTC(2001, 0, 1) + buf.readDoubleBE(pos + 1) * 1000);
      case 0x4: {
        const { len, start } = readLen();
        return Buffer.from(buf.slice(start, start + len));
      }
      case 0x5: {
        const { len, start } = readLen();
        return buf.slice(start, start + len).toString('latin1');
      }
      case 0x6: {
        const { len, start } = readLen();
        const b = Buffer.from(buf.slice(start, start + len * 2));
        for (let k = 0; k + 1 < b.length; k += 2) {
          const t = b[k];
          b[k] = b[k + 1];
          b[k + 1] = t;
        }
        return b.toString('utf16le');
      }
      case 0x8:
        return { UID: readUInt(pos + 1, lo + 1) };
      case 0xa:
      case 0xc: {
        const { len, start } = readLen();
        const out = [];
        for (let k = 0; k < len; k++) out.push(parseObj(readUInt(start + k * refSize, refSize), depth + 1));
        return out;
      }
      case 0xd: {
        const { len, start } = readLen();
        const out = {};
        for (let k = 0; k < len; k++) {
          const key = parseObj(readUInt(start + k * refSize, refSize), depth + 1);
          const val = parseObj(readUInt(start + (len + k) * refSize, refSize), depth + 1);
          out[String(key)] = val;
        }
        return out;
      }
      default:
        throw new Error('bplist: unsupported marker 0x' + marker.toString(16));
    }
  }
  return parseObj(topObject, 0);
}

/* ---------------- writer ---------------- */

function escapeXml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function writeValue(v, indent) {
  const pad = '\t'.repeat(indent);
  if (typeof v === 'string') return `${pad}<string>${escapeXml(v)}</string>\n`;
  if (typeof v === 'boolean') return `${pad}<${v}/>\n`;
  if (typeof v === 'number') return Number.isInteger(v) ? `${pad}<integer>${v}</integer>\n` : `${pad}<real>${v}</real>\n`;
  if (Array.isArray(v)) {
    return `${pad}<array>\n${v.map((x) => writeValue(x, indent + 1)).join('')}${pad}</array>\n`;
  }
  if (v && typeof v === 'object') {
    let out = `${pad}<dict>\n`;
    for (const [k, val] of Object.entries(v)) {
      out += `${pad}\t<key>${escapeXml(k)}</key>\n${writeValue(val, indent + 1)}`;
    }
    return out + `${pad}</dict>\n`;
  }
  throw new Error('plist: cannot serialise value');
}

function buildXmlPlist(obj) {
  return (
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n' +
    '<plist version="1.0">\n' +
    writeValue(obj, 0) +
    '</plist>\n'
  );
}

module.exports = { parsePlist, parseXml, parseBinary, buildXmlPlist, escapeXml };
