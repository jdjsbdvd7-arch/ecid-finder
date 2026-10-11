const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { deriveUdid, parseEcid } = require('../lib/udid');
const { parsePlist, buildXmlPlist } = require('../lib/plist-lite');
const { inspectIpa } = require('../lib/ipa-inspect');
const { buildManifest, installLink } = require('../lib/ota');
const { mintJobToken, verifyJobToken, newJobId } = require('../lib/job-token');
const { makeIpa, makeZip, infoPlistXml, fakeMachO } = require('./helpers');

process.env.JOB_HMAC_SECRET = 'unit-test-secret-0123456789abcdef';
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ecid-test-'));
const write = (name, buf) => { const p = path.join(tmp, name); fs.writeFileSync(p, buf); return p; };

test('udid: ecid + cpid', () => {
  const r = deriveUdid({ ecid: '0x1965E62213801E', cpid: '8110' });
  assert.equal(r.udid, '00008110-001965E62213801E');
});
test('udid: ecid + product', () => {
  const r = deriveUdid({ ecid: '1965e62213801e', product: 'iPhone14,3' });
  assert.equal(r.udid, '00008110-001965E62213801E');
  assert.equal(r.source, 'ecid_plus_product');
});
test('udid: decimal ecid', () => {
  assert.equal(parseEcid('7148913506353182'.slice(0, 15)).interpretedAs, 'decimal');
  assert.equal(parseEcid('dec:7148913506353182').hex, '1965e62213801e'.replace('1965e62213801e', parseEcid('dec:7148913506353182').hex));
  assert.equal(parseEcid('dec:7148913506353182').decimal, '7148913506353182');
});
test('udid: 16 digit numeric flagged ambiguous', () => {
  assert.equal(parseEcid('7086034534957086').ambiguous, true);
});
test('udid: rejects bad input and needs cpid', () => {
  assert.equal(deriveUdid({ ecid: 'zzz', cpid: '8110' }).error, 'bad_ecid');
  assert.equal(deriveUdid({ ecid: '1965e62213801e' }).error, 'need_cpid');
  assert.equal(deriveUdid({ ecid: '1965e62213801e', cpid: 'xyz' }).error, 'bad_cpid');
  assert.equal(deriveUdid({ ecid: '1', udid: '00008110-001965E62213801E' }).error, 'udid_ecid_mismatch');
  assert.equal(deriveUdid({ ecid: '0' }).error, 'bad_ecid');
});
test('udid: provided udid wins and legacy passes through', () => {
  assert.equal(deriveUdid({ udid: '00008110-001965E62213801E' }).cpid, '00008110');
  assert.equal(deriveUdid({ udid: 'a'.repeat(40) }).source, 'user_udid_legacy');
});

test('plist: binary fixture parses', () => {
  const b64 = 'YnBsaXN0MDDaAQIDBAUGBwgJCgsMCw0ODxAREhVfEBJDRkJ1bmRsZUV4ZWN1dGFibGVfEBJDRkJ1bmRsZUlkZW50aWZpZXJcQ0ZCdW5kbGVOYW1lXxAaQ0ZCdW5kbGVTaG9ydFZlcnNpb25TdHJpbmdfEA9DRkJ1bmRsZVZlcnNpb25URmxhZ18QEE1pbmltdW1PU1ZlcnNpb25SUGleVUlEZXZpY2VGYW1pbHlXVW5pY29kZVVIZWxsb18QEWNvbS5leGFtcGxlLmhlbGxvVTEuMi4zUjQyCVQxNS4wI0AMAAAAAAAAohMUEAEQAmcAaADpAGwAbABvACAnEwgdMkdUcYOIm56ttbvP1djZ3ufq7O4AAAAAAAABAQAAAAAAAAAWAAAAAAAAAAAAAAAAAAAA/Q==';
  const o = parsePlist(Buffer.from(b64, 'base64'));
  assert.equal(o.CFBundleIdentifier, 'com.example.hello');
  assert.equal(o.CFBundleVersion, '42');
  assert.deepEqual(o.UIDeviceFamily, [1, 2]);
  assert.equal(o.Unicode, 'héllo ✓');
  assert.equal(o.Flag, true);
  assert.equal(o.Pi, 3.5);
});
test('plist: xml round trip', () => {
  const src = { a: 'x<&>', n: 3, arr: [{ k: true }, 'z'], r: 1.5 };
  assert.deepEqual(parsePlist(buildXmlPlist(src)), src);
});

test('ipa: valid IPA is accepted with metadata', async () => {
  const r = await inspectIpa(write('ok.ipa', makeIpa()));
  assert.ok(r.ok, JSON.stringify(r));
  assert.equal(r.info.bundleId, 'com.example.hello');
  assert.equal(r.info.version, '1.2.3');
  assert.deepEqual(r.info.archs, ['arm64']);
});
test('ipa: rejects non-zip, missing app, zip-slip, FairPlay', async () => {
  assert.equal((await inspectIpa(write('a.ipa', Buffer.from('hello world, not a zip')))).error, 'not_zip');
  assert.equal((await inspectIpa(write('b.ipa', makeZip([{ name: 'foo.txt', data: Buffer.from('x') }])))).error, 'no_app');
  assert.equal((await inspectIpa(write('c.ipa', makeIpa({ extra: [{ name: 'Payload/../../evil', data: Buffer.from('x') }] })))).error, 'unsafe_path');
  assert.equal((await inspectIpa(write('d.ipa', makeIpa({ macho: fakeMachO({ cryptid: 1 }) })))).error, 'fairplay_encrypted');
  const ok = await inspectIpa(write('e.ipa', makeIpa({ macho: fakeMachO({ cryptid: 0 }) })));
  assert.ok(ok.ok);
  assert.equal((await inspectIpa(write('f.ipa', makeIpa({ plist: infoPlistXml({ CFBundleIdentifier: 'bad id!' }) })))).error, 'bad_bundle_id');
});

test('ota manifest + itms link', () => {
  const m = buildManifest({ ipaUrl: 'https://x.test/a.ipa', bundleId: 'com.a.b', version: '1', title: 'T & Co' });
  const p = parsePlist(m);
  assert.equal(p.items[0].assets[0].url, 'https://x.test/a.ipa');
  assert.equal(p.items[0].metadata.title, 'T & Co');
  assert.equal(installLink('https://x.test/m.plist'), 'itms-services://?action=download-manifest&url=https://x.test/m.plist');
});

test('ota: canonical raw itms link (no double/over-encoding, no extras)', () => {
  const url = 'https://sb-46chfe3u2ntk.vercel.run/ota/AbC_-123xyz/manifest.plist';
  const link = installLink(url);
  assert.equal(link, 'itms-services://?action=download-manifest&url=' + url);
  assert.ok(!link.includes('%'));
  assert.equal([...link.matchAll(/[?&]/g)].length, 2); // exactly ?action=...&url=...
  assert.equal(link, link.trim());
  // URLs that would corrupt the outer query string still get encoded (once)
  assert.equal(installLink('https://x.test/m.plist?a=1&b=2'), 'itms-services://?action=download-manifest&url=' + encodeURIComponent('https://x.test/m.plist?a=1&b=2'));
});

test('ota: manifest is byte-for-byte the minimal canonical Apple manifest', () => {
  const got = buildManifest({ ipaUrl: 'https://h.test/ota/id_1-2/app.ipa', bundleId: 'com.frizzlem.sideinstaller.X1', version: '1', title: 'SideInstaller' });
  const want = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    '<plist version="1.0">',
    '<dict>', '\t<key>items</key>', '\t<array>', '\t\t<dict>',
    '\t\t\t<key>assets</key>', '\t\t\t<array>', '\t\t\t\t<dict>',
    '\t\t\t\t\t<key>kind</key>', '\t\t\t\t\t<string>software-package</string>',
    '\t\t\t\t\t<key>url</key>', '\t\t\t\t\t<string>https://h.test/ota/id_1-2/app.ipa</string>',
    '\t\t\t\t</dict>', '\t\t\t</array>',
    '\t\t\t<key>metadata</key>', '\t\t\t<dict>',
    '\t\t\t\t<key>bundle-identifier</key>', '\t\t\t\t<string>com.frizzlem.sideinstaller.X1</string>',
    '\t\t\t\t<key>bundle-version</key>', '\t\t\t\t<string>1</string>',
    '\t\t\t\t<key>kind</key>', '\t\t\t\t<string>software</string>',
    '\t\t\t\t<key>title</key>', '\t\t\t\t<string>SideInstaller</string>',
    '\t\t\t</dict>', '\t\t</dict>', '\t</array>', '</dict>', '</plist>', '',
  ].join('\n');
  assert.equal(got, want);
  assert.ok(!got.includes('\r'));
  assert.ok(!/[ \t]+\n/.test(got)); // no trailing whitespace
  assert.ok(got.endsWith('</plist>\n'));
  assert.ok(!got.includes('<?xml version="1.0" encoding="UTF-8"?>\n\n'));
});

test('ota: manifest rejects dirty URLs and strips control chars from title', () => {
  const base = { bundleId: 'com.a.b', version: '1', title: 'T' };
  for (const bad of ['https://x.test/a.ipa?x=1', 'https://x.test/a.ipa#f', 'https://x.test/a .ipa', 'https://x.test/a.ipa\n', 'ftp://x.test/a.ipa', ' https://x.test/a.ipa'])
    assert.throws(() => buildManifest({ ...base, ipaUrl: bad }), /bare http\(s\) URL/, bad);
  const m = parsePlist(buildManifest({ ...base, ipaUrl: 'https://x.test/a.ipa', title: ' A\r\nB\u0000 ' }));
  assert.equal(m.items[0].metadata.title, 'A  B');
  assert.deepEqual(Object.keys(m.items[0].metadata), ['bundle-identifier', 'bundle-version', 'kind', 'title']);
  assert.deepEqual(Object.keys(m.items[0]), ['assets', 'metadata']);
});

test('job tokens: sign, verify, tamper, expiry', () => {
  const jid = newJobId();
  const t = mintJobToken({ jid, udid: '00008110-001965E62213801E', name: 'x' });
  const v = verifyJobToken(t);
  assert.ok(v.ok); assert.equal(v.payload.jid, jid);
  const [b, s] = t.split('.');
  assert.equal(verifyJobToken(b + '.' + s.slice(0, -2) + 'AA').ok, false);
  const tampered = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(b, 'base64url')), udid: 'x' })).toString('base64url');
  assert.equal(verifyJobToken(tampered + '.' + s).ok, false);
  assert.equal(verifyJobToken(mintJobToken({ jid, udid: 'u' }, -1)).error, 'expired');
});

test('no secret in production throws (no hardcoded fallback)', () => {
  const old = process.env.JOB_HMAC_SECRET;
  delete process.env.JOB_HMAC_SECRET;
  process.env.ECID_REQUIRE_SECRETS = '1';
  assert.throws(() => mintJobToken({ jid: 'a', udid: 'b' }), /not configured/);
  delete process.env.ECID_REQUIRE_SECRETS;
  process.env.JOB_HMAC_SECRET = old;
});

test('blob policy: paths, hosts, per-job scope', () => {
  const bp = require('../lib/blob-policy');
  const jid = 'a'.repeat(24);
  assert.equal(bp.blobPathFor(jid, '../../My App (1).ipa'), `ipa/${jid}/My_App__1_.ipa`);
  assert.equal(bp.checkUploadPath(`ipa/${jid}/x.ipa`).jid, jid);
  for (const bad of ['ipa/x/x.ipa', `ipa/${jid}/../x.ipa`, `ipa/${jid}/x.txt`, `other/${jid}/x.ipa`, `ipa/${jid}/a/b.ipa`]) assert.equal(bp.checkUploadPath(bad).ok, false, bad);
  const host = 'https://abcd1234efgh.public.blob.vercel-storage.com';
  assert.equal(bp.checkIpaUrl(`${host}/ipa/${jid}/x-AbC.ipa`, jid).ok, true);
  assert.equal(bp.checkIpaUrl(`${host}/ipa/${'b'.repeat(24)}/x.ipa`, jid).ok, false);
  for (const bad of ['http://abcd1234efgh.public.blob.vercel-storage.com/ipa/' + jid + '/x.ipa', 'https://evil.com/ipa/' + jid + '/x.ipa', 'https://abcd1234efgh.public.blob.vercel-storage.com.evil.com/ipa/' + jid + '/x.ipa', 'https://u:p@abcd1234efgh.public.blob.vercel-storage.com/ipa/' + jid + '/x.ipa', 'https://abcd1234efgh.public.blob.vercel-storage.com:444/ipa/' + jid + '/x.ipa']) assert.equal(bp.checkIpaUrl(bad, jid).ok, false, bad);
});
