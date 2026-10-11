#!/usr/bin/env node
/**
 * Interactive CLI for the signer — use this on the box when you do not want to type Apple
 * credentials into a web form. Prompts for Apple ID, password (hidden) and 2FA in the terminal.
 *
 *   node worker/cli.js sign --ipa ./MyApp.ipa --ecid 0x1965E62213801E --cpid 8110 \
 *        [--product iPhone14,3] [--udid 00008110-...] [--name "My iPhone"] [--out signed.ipa] \
 *        [--publish] [--revoke-certs]
 *
 * --publish registers the signed IPA with the worker's data dir so a running `worker/server.js`
 * (same ECID_WORKER_DATA, PUBLIC_BASE_URL=https://…) serves the OTA manifest + install page.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

const { deriveUdid } = require('../lib/udid');
const { inspectIpa } = require('../lib/ipa-inspect');
const { installLink } = require('../lib/ota');
const { runSigner, signerAvailable, signerBinary } = require('./signer-runner');

function arg(name, def) {
  const i = process.argv.indexOf('--' + name);
  if (i < 0) return def;
  const v = process.argv[i + 1];
  return v && !v.startsWith('--') ? v : true;
}

function ask(q, { hidden = false } = {}) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    if (hidden) {
      rl._writeToOutput = (s) => { if (s.includes(q)) process.stdout.write(s); else if (s.includes('\n') || s.includes('\r')) process.stdout.write('\n'); };
    }
    rl.question(q, (a) => { rl.close(); resolve(a); });
  });
}

async function main() {
  if (process.argv[2] !== 'sign') {
    console.log('usage: node worker/cli.js sign --ipa FILE --ecid ECID [--cpid 8110 | --product iPhone14,3 | --udid UDID] [--name NAME] [--out FILE] [--publish] [--revoke-certs]');
    process.exit(1);
  }
  if (!signerAvailable()) {
    console.error(`ecid-signer not found at ${signerBinary()}.\nBuild it: cd worker/signer && cargo build --release  (Rust >= 1.88; see README)`);
    process.exit(1);
  }
  const ipa = arg('ipa');
  if (!ipa || ipa === true || !fs.existsSync(ipa)) { console.error('--ipa FILE is required (your own IPA).'); process.exit(1); }
  const d = deriveUdid({ ecid: arg('ecid'), cpid: arg('cpid'), udid: arg('udid'), product: arg('product') });
  if (!d.ok) { console.error(d.message); process.exit(1); }
  console.log('UDID:', d.udid);
  const insp = await inspectIpa(ipa);
  if (!insp.ok) { console.error('IPA rejected:', insp.message); process.exit(1); }
  console.log(`IPA: ${insp.info.name} (${insp.info.bundleId}) ${insp.info.version}`);
  insp.warnings.forEach((w) => console.log('  warning:', w));

  console.log('\nYour Apple ID and password are sent only to Apple (via the local signer process, held in memory).');
  console.log('Nothing is written to disk. Use YOUR OWN account and YOUR OWN IPA.\n');
  const email = (await ask('Apple ID: ')).trim();
  const password = await ask('Password (hidden): ', { hidden: true });

  const out = path.resolve(arg('out', 'signed.ipa') === true ? 'signed.ipa' : arg('out', 'signed.ipa'));
  const stateDir = path.join(process.env.ECID_WORKER_DATA || path.join(__dirname, 'data'), 'anisette');
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  let result = null;
  let err = null;
  const runner = runSigner(
    { email, password, udid: d.udid, deviceName: String(arg('name', 'ECID Finder device')), ipa: path.resolve(ipa), out, maxCerts: arg('revoke-certs') ? 'revoke' : 'error', anisetteUrl: process.env.ANISETTE_URL || undefined, stateDir },
    async (ev) => {
      if (ev.event === 'stage') console.log('→', ev.stage);
      else if (ev.event === 'team') console.log('  team:', ev.name, ev.teamId);
      else if (ev.event === 'device_registered') console.log('  device registered on your team');
      else if (ev.event === 'progress') process.stdout.write(`  ${(ev.value * 100).toFixed(0)}%\r`);
      else if (ev.event === 'need_2fa') {
        console.log('\nTwo-factor authentication required.');
        const p = ev.params || {};
        if (p.lastError) console.log('  last error:', p.lastError);
        const code = (await ask('6-digit code (or "sms" / "resend"): ')).trim();
        if (code === 'sms') runner.write({ action: 'sms', id: (p.numbers && p.numbers[0] && p.numbers[0].id) || 1 });
        else if (code === 'resend') runner.write({ action: 'resend' });
        else runner.write({ action: 'code', code });
      } else if (ev.event === 'error') err = ev;
      else if (ev.event === 'done') result = ev;
    }
  );
  await runner.done;
  if (!result) { console.error('\nFailed:', err ? `${err.code}: ${err.message}` : 'signer exited without result'); process.exit(2); }
  const signed = await inspectIpa(out);
  console.log('\nSigned IPA:', out, signed.ok ? `(${signed.info.bundleId})` : '');
  if (arg('publish')) {
    const jobs = require('./jobs');
    const jid = crypto.randomBytes(12).toString('hex');
    const dir = jobs.jobDir(jid);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.copyFileSync(out, path.join(dir, 'signed.ipa'));
    const iid = jobs.newInstallId();
    jobs.saveJob({ jid, udid: d.udid, deviceName: String(arg('name', 'device')), status: 'ready', stage: 'ready', createdAt: Date.now(), readyAt: Date.now(), installId: iid, signedBundleId: signed.info.bundleId, signedVersion: signed.info.build || signed.info.version, signedTitle: signed.info.name, expiresAt: Date.now() + 3 * 3600e3, ipa: insp.info, team: { id: result.teamId, name: '' } });
    const base = (process.env.PUBLIC_BASE_URL || 'https://YOUR-HTTPS-HOST').replace(/\/+$/, '');
    console.log('\nOpen on the device (Safari):', `${base}/i/${iid}`);
    console.log('Direct link:', installLink(`${base}/ota/${iid}/manifest.plist`));
    if (!process.env.PUBLIC_BASE_URL) console.log('(set PUBLIC_BASE_URL=https://… when running worker/server.js; iOS needs valid HTTPS)');
  }
}

main().catch((e) => { console.error(e && e.message); process.exit(1); });
