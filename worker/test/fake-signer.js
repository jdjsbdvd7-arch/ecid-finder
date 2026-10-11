#!/usr/bin/env node
/**
 * TEST-ONLY stand-in that speaks the same JSON-lines protocol as `ecid-signer`.
 * It does NOT talk to Apple and does NOT sign anything (it copies the IPA). It exists so the
 * worker's upload → login → 2FA → ready → OTA pipeline can be tested without Apple credentials.
 * Accepts password "test-password" and 2FA code "123456" only.
 */
const fs = require('fs');
const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin });
const lines = [];
let waiter = null;
rl.on('line', (l) => { if (waiter) { const w = waiter; waiter = null; w(l); } else lines.push(l); });
const next = () => new Promise((r) => (lines.length ? r(lines.shift()) : (waiter = r)));
const emit = (o) => console.log(JSON.stringify(o));
(async () => {
  const start = JSON.parse(await next());
  const insp = await require('../../lib/ipa-inspect').inspectIpa(start.ipa);
  const origId = insp.ok ? insp.info.bundleId : '';
  if (start.bundleId) emit({ event: 'bundle_rewrite', from: origId, to: start.bundleId, reason: 'override' });
  else if (/^com\.apple(\.|$)/i.test(origId)) emit({ event: 'bundle_rewrite', from: origId, to: 'com.ecidfinder.x.000000', reason: 'reserved' });
  emit({ event: 'stage', stage: 'apple_login' });
  if (start.password !== 'test-password') { emit({ event: 'error', code: 'apple_login_failed', message: 'bad password ' + start.password }); process.exit(2); }
  emit({ event: 'need_2fa', params: { unknown: false, sms: false, numbers: [] } });
  const r = JSON.parse(await next());
  if (r.action !== 'code' || r.code !== '123456') { emit({ event: 'error', code: 'apple_login_failed', message: 'bad 2fa' }); process.exit(2); }
  emit({ event: 'stage', stage: 'apple_logged_in' });
  emit({ event: 'team', teamId: 'TESTTEAM00', name: 'Test Personal Team' });
  emit({ event: 'stage', stage: 'register_device' });
  emit({ event: 'device_registered', udid: start.udid });
  emit({ event: 'stage', stage: 'sign' });
  emit({ event: 'progress', value: 0.5 });
  fs.copyFileSync(start.ipa, start.out);
  emit({ event: 'done', out: start.out, teamId: 'TESTTEAM00' });
  process.exit(0);
})();
