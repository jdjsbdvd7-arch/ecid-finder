/**
 * Drives the `ecid-signer` binary over its JSON-lines protocol.
 * Credentials are written to the child's stdin only; never to argv, env, disk or logs.
 */
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

function signerBinary() {
  if (process.env.ECID_SIGNER_BIN) return process.env.ECID_SIGNER_BIN;
  return path.join(__dirname, 'signer', 'target', 'release', 'ecid-signer');
}

function signerAvailable() {
  try {
    fs.accessSync(signerBinary(), fs.constants.X_OK);
    return true;
  } catch (_) {
    return false;
  }
}

/**
 * @param {object} start  {email,password,udid,deviceName,ipa,out,maxCerts,anisetteUrl,stateDir}
 * @param {(ev:object)=>void} onEvent
 * @param {{timeoutMs?:number}} opts
 * @returns {{write:(obj)=>void, kill:()=>void, done:Promise<{code:number|null}>}}
 */
function runSigner(start, onEvent, opts = {}) {
  const child = spawn(signerBinary(), [], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { PATH: process.env.PATH, HOME: process.env.HOME || '/tmp', TMPDIR: process.env.ECID_TMPDIR || process.env.TMPDIR || '/tmp' }, // no inherited secrets
  });
  const rl = readline.createInterface({ input: child.stdout });
  rl.on('line', (line) => {
    let ev;
    try {
      ev = JSON.parse(line);
    } catch (_) {
      return; // ignore non-JSON noise
    }
    onEvent(ev);
    if (ev.event === 'done' || ev.event === 'error') {
      // Terminal event: close stdin and make sure the child cannot linger holding secrets.
      try { child.stdin.end(); } catch (_) {}
      setTimeout(() => child.kill('SIGKILL'), 3000).unref();
    }
  });
  child.stderr.on('data', () => {}); // never surface raw stderr (could echo identifiers)
  const timer = setTimeout(() => {
    onEvent({ event: 'error', code: 'timeout', message: 'Signing timed out.' });
    child.kill('SIGKILL');
  }, opts.timeoutMs || 15 * 60 * 1000);
  const done = new Promise((resolve) => {
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code });
    });
    child.on('error', (e) => {
      clearTimeout(timer);
      onEvent({ event: 'error', code: 'spawn_failed', message: e.message });
      resolve({ code: -1 });
    });
  });
  const write = (obj) => {
    if (!child.stdin.destroyed) child.stdin.write(JSON.stringify(obj) + '\n');
  };
  write(start);
  return { write, kill: () => child.kill('SIGKILL'), done };
}

module.exports = { runSigner, signerAvailable, signerBinary };
