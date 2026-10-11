(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const show = (el, on = true) => { el.hidden = !on; };
  const unlock = (id) => $(id).classList.remove('locked');

  let cfg = { workerConfigured: false, workerUrl: '', blobEnabled: false, maxIpaBytes: 600 * 1024 * 1024 };
  let job = null; // { jobId, token, udid, workerUrl }
  let pollTimer = null;

  const STAGES = [
    ['anisette', 'تهيئة Anisette · Anisette setup'],
    ['apple_login', 'تسجيل الدخول إلى Apple · Apple sign-in'],
    ['need_2fa', 'التحقق بخطوتين · Two-factor'],
    ['apple_logged_in', 'تم الدخول · Signed in'],
    ['team', 'فريق المطوّر (Personal Team) · Developer team'],
    ['register_device', 'تسجيل الجهاز (UDID) · Register device'],
    ['sign', 'الشهادة + App ID + الملف + التوقيع · Cert + App ID + profile + sign'],
    ['package', 'تجهيز IPA · Package IPA'],
    ['ready', 'جاهز للتثبيت · Ready to install'],
  ];

  // Render "عربي · English" text nodes as two lines so bidi mixing stays readable.
  function splitBi(root) {
    const sel = 'h1,h2,label.label,button,a.btn,.check,.timeline li,.drop span,.notice strong,.meta dt';
    const els = root.matches && root.matches(sel) ? [root] : Array.from(root.querySelectorAll(sel));
    for (const el of els) {
      for (const n of Array.from(el.childNodes)) {
        if (n.nodeType !== 3) continue;
        const m = /^(\s*[^\x00-\x7f][^]*?)\s·\s+([A-Za-z(][^]*)$/.exec(n.nodeValue);
        if (!m) continue;
        const ar = document.createElement('span'); ar.textContent = m[1].trim();
        const en = document.createElement('span'); en.className = 'en'; en.dir = 'ltr'; en.textContent = m[2].trim();
        if (el.classList.contains('check')) {
          const w = document.createElement('span'); w.className = 'txt'; w.append(ar, en); n.replaceWith(w);
        } else n.replaceWith(ar, en);
      }
    }
  }

  const base = () => (job && job.workerUrl) || '';
  const authHeaders = () => ({ Authorization: 'Bearer ' + job.token });

  async function api(method, path, body) {
    const r = await fetch(base() + path, {
      method,
      headers: { ...authHeaders(), ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
      cache: 'no-store',
      credentials: 'omit',
    });
    let j = {};
    try { j = await r.json(); } catch (_) {}
    return { status: r.status, json: j };
  }

  /* ---------- config ---------- */
  async function loadConfig() {
    try {
      const r = await fetch('/api/config', { cache: 'no-store' });
      cfg = { ...cfg, ...(await r.json()) };
    } catch (_) {}
    const b = $('workerBanner');
    if (!cfg.workerConfigured) {
      b.className = 'notice bad';
      b.textContent = 'عامل التوقيع غير متصل بهذا الموقع بعد، لذلك لا يمكن رفع IPA أو تسجيل الدخول هنا. شغّل العامل محلياً (انظر README ← Signing worker) أو اربطه عبر WORKER_PUBLIC_URL. · No signing worker is connected to this deployment yet, so upload / Apple sign-in are disabled here. Run the worker locally (README → Signing worker) or connect one via WORKER_PUBLIC_URL.';
      show(b);
    } else if (cfg.signerBuilt === false) {
      b.className = 'notice bad';
      b.textContent = 'العامل يعمل لكن ecid-signer لم يُبنَ بعد (cargo build --release في worker/signer). · Worker is up but ecid-signer is not built yet.';
      show(b);
    }
  }

  /* ---------- step 1 ---------- */
  let chipsLoaded = false;
  let previewTimer = null;
  async function preview() {
    const ecid = $('ecid').value.trim();
    const udidIn = $('udidIn').value.trim();
    const qs = new URLSearchParams({ ecid, cpid: $('cpid').value, product: $('product').value.trim(), udid: udidIn });
    let j;
    try { j = await (await fetch('/api/udid?' + qs, { cache: 'no-store' })).json(); } catch (_) { return null; }
    if (!chipsLoaded && j.chips) {
      for (const c of j.chips) {
        const o = document.createElement('option');
        o.value = c.cpid; o.textContent = `${c.name} (${c.cpid})`;
        $('cpid').appendChild(o);
      }
      chipsLoaded = true;
    }
    const msg = $('udidMsg');
    const note = $('ecidNote');
    show(note, false);
    if (j.ok) {
      $('udidPreview').textContent = j.udid;
      show(msg, false);
      if (j.ambiguous) {
        note.textContent = 'رقم من 16 خانة: فُسِّر كـ hex. إن كان عشرياً اكتب dec: قبله. · 16 digits: read as hex. Prefix with dec: if it is decimal.';
        show(note);
      }
    } else {
      $('udidPreview').textContent = '—';
      if (ecid || udidIn) { msg.textContent = j.message || j.error || ''; show(msg, Boolean(msg.textContent)); }
      else show(msg, false);
    }
    $('reportLink').href = '/manual.html';
    return j;
  }
  for (const id of ['ecid', 'product', 'cpid', 'udidIn']) {
    $(id).addEventListener('input', () => { clearTimeout(previewTimer); previewTimer = setTimeout(preview, 250); });
  }

  $('deviceForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const j = await preview();
    if (!j || !j.ok) return;
    const r = await fetch('/api/jobs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ecid: $('ecid').value.trim(), cpid: $('cpid').value, product: $('product').value.trim(), udid: $('udidIn').value.trim(), deviceName: $('devName').value }),
    });
    const m = await r.json().catch(() => ({}));
    if (!r.ok || !m.ok) {
      const msg = $('udidMsg');
      msg.textContent = m.message || m.error || 'فشل إنشاء الجلسة · Could not create session';
      show(msg);
      return;
    }
    job = { jobId: m.jobId, token: m.token, udid: m.udid, workerUrl: m.workerUrl || '' };
    sessionStorage.setItem('ecidJob', JSON.stringify(job)); // capability token only; never Apple credentials
    $('reportLink').href = '/report.html?' + new URLSearchParams({ manual: '1', udid: m.udid, ecidHex: m.ecid.hex, ecidDecimal: m.ecid.decimal, product: $('product').value.trim() });
    $('createJob').textContent = 'تم · Done ✓';
    unlock('s2');
    $('s2').scrollIntoView({ behavior: 'smooth' });
  });

  /* ---------- step 2: upload ---------- */
  function fmt(n) { return n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : (n / 1024).toFixed(0) + ' KB'; }
  function setText(el, t) { el.textContent = t; }

  function renderMeta(ipa, warnings) {
    const dl = $('ipaMeta');
    dl.textContent = '';
    const rows = [['Name', ipa.name], ['Bundle ID', ipa.bundleId], ['Version', `${ipa.version} (${ipa.build})`], ['Min iOS', ipa.minOS || '—'], ['Arch', (ipa.archs || []).join(', ') || '—'], ['Size', fmt(ipa.size)], ['SHA-256', ipa.sha256 ? ipa.sha256.slice(0, 16) + '…' : '—']];
    for (const [k, v] of rows) {
      const dt = document.createElement('dt'); dt.textContent = k;
      const dd = document.createElement('dd'); dd.textContent = v;
      dl.append(dt, dd);
    }
    show(dl);
    const ul = $('ipaWarn'); ul.textContent = '';
    for (const w of warnings || []) { const li = document.createElement('li'); li.textContent = w; ul.appendChild(li); }
    show(ul, (warnings || []).length > 0);
  }

  function safeName(n) {
    const stem = String(n).split(/[\\/]/).pop().replace(/\.ipa$/i, '').replace(/[^A-Za-z0-9._-]/g, '_').replace(/^\.+/, '').slice(0, 80) || 'app';
    return stem + '.ipa';
  }

  function ipaAccepted(j) {
    const msg = $('upMsg');
    setText(msg, 'تم التحقق من الملف ✓ · IPA validated ✓');
    renderMeta(j.job.ipa, j.job.warnings);
    unlock('s3');
  }

  // Preferred path: browser -> Vercel Blob (direct), worker downloads it from Blob, Blob copy is deleted.
  async function uploadViaBlob(file) {
    const msg = $('upMsg');
    show($('upBar')); $('upFill').style.width = '0';
    setText(msg, 'جاري الرفع إلى التخزين المؤقت · Uploading to temporary storage…'); show(msg);
    let blob;
    try {
      blob = await window.EcidBlob.upload(`ipa/${job.jobId}/${safeName(file.name)}`, file, {
        access: 'public',
        handleUploadUrl: '/api/blob-upload',
        headers: { Authorization: 'Bearer ' + job.token },
        contentType: 'application/octet-stream',
        multipart: file.size > 50 * 1024 * 1024,
        onUploadProgress: (p) => { $('upFill').style.width = Math.min(60, p.percentage * 0.6).toFixed(1) + '%'; },
      });
    } catch (e) {
      setText(msg, '✕ فشل الرفع · Upload failed: ' + String((e && e.message) || e).slice(0, 200));
      return;
    }
    setText(msg, 'العامل يجلب الملف ويتحقق منه · Worker is fetching and validating the IPA…');
    $('upFill').style.width = '80%';
    const r = await api('POST', `/jobs/${job.jobId}/ingest`, { ipaUrl: blob.url }).catch(() => null);
    // The temporary Blob copy is no longer needed whatever the outcome.
    fetch('/api/blob-delete', { method: 'POST', headers: authHeaders(), cache: 'no-store', credentials: 'omit' }).catch(() => {});
    $('upFill').style.width = '100%';
    if (!r) { setText(msg, 'تعذّر الاتصال بعامل التوقيع (CORS/HTTPS؟) · Cannot reach the signing worker (CORS / HTTPS?)'); return; }
    if (r.status === 200 && r.json.ok) ipaAccepted(r.json);
    else setText(msg, '✕ ' + (r.json.message || r.json.error || 'HTTP ' + r.status));
  }

  // Fallback (worker serving this page itself / no Blob store): PUT the file straight to the worker.
  function uploadDirect(file) {
    const msg = $('upMsg');
    const xhr = new XMLHttpRequest();
    xhr.open('PUT', base() + `/jobs/${job.jobId}/ipa`);
    xhr.setRequestHeader('Authorization', 'Bearer ' + job.token);
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    show($('upBar')); $('upFill').style.width = '0';
    setText(msg, 'جاري الرفع · Uploading…'); show(msg);
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) $('upFill').style.width = (e.loaded / e.total * 100).toFixed(1) + '%'; };
    xhr.onerror = () => { setText(msg, 'تعذّر الاتصال بعامل التوقيع (CORS/HTTPS؟) · Cannot reach the signing worker (CORS / HTTPS?)'); };
    xhr.onload = () => {
      let j = {};
      try { j = JSON.parse(xhr.responseText); } catch (_) {}
      if (xhr.status === 200 && j.ok) ipaAccepted(j);
      else setText(msg, '✕ ' + (j.message || j.error || 'HTTP ' + xhr.status));
    };
    xhr.send(file);
  }

  function upload(file) {
    if (!job) return;
    const msg = $('upMsg');
    show($('ipaMeta'), false); show($('ipaWarn'), false);
    if (!/\.ipa$/i.test(file.name)) { setText(msg, 'يجب أن يكون الملف .ipa · File must be .ipa'); show(msg); return; }
    if (file.size > cfg.maxIpaBytes) { setText(msg, `الملف أكبر من الحد (${fmt(cfg.maxIpaBytes)}) · File exceeds limit`); show(msg); return; }
    if (cfg.blobEnabled && window.EcidBlob) uploadViaBlob(file);
    else uploadDirect(file);
  }
  $('ipaFile').addEventListener('change', (e) => { if (e.target.files[0]) upload(e.target.files[0]); });
  const drop = $('drop');
  ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', (e) => { if (e.dataTransfer.files[0]) upload(e.dataTransfer.files[0]); });

  /* ---------- step 3: sign ---------- */
  function renderTimeline(j) {
    const ol = $('timeline'); ol.textContent = '';
    show(ol);
    const cur = j.stage;
    const idx = STAGES.findIndex(([k]) => k === cur);
    STAGES.forEach(([k, label], i) => {
      if (k === 'need_2fa' && idx < 2 && cur !== 'need_2fa') return;
      const li = document.createElement('li');
      li.textContent = label;
      if (j.status === 'error' && i === Math.max(idx, 0)) li.className = 'fail';
      else if (j.status === 'ready' || i < idx) li.className = 'done';
      else if (i === idx) li.className = 'active';
      ol.appendChild(li);
      splitBi(li);
    });
    show($('signBar'), j.status === 'signing');
    $('signFill').style.width = Math.round((j.progress || 0) * 100) + '%';
  }

  function describeError(err) {
    const t = {
      apple_login_failed: 'فشل تسجيل الدخول (كلمة المرور/الرمز/تقييد Apple) · Apple sign-in failed (password, code, or Apple restriction).',
      team_failed: 'لا يوجد فريق مطوّر لهذا الحساب · No developer team on this account.',
      register_device_failed: 'تعذّر تسجيل الجهاز (الحد 3 أجهزة؟ UDID غير صحيح؟) · Could not register the device (3-device limit? wrong UDID?).',
      sign_failed: 'فشل إنشاء الشهادة/App ID/التوقيع (حد الشهادات؟ حد App IDs؟) · Certificate / App ID / signing failed (cert or App ID limit?).',
      bad_bundle_id: 'معرّف الحزمة المخصص غير صالح أو محجوز (com.apple.* غير مسموح) · The custom bundle ID is invalid or reserved (com.apple.* is not allowed).',
      rewrite_failed: 'تعذّر تغيير معرّف الحزمة داخل الـ IPA · Could not rewrite the bundle ID inside the IPA.',
      anisette_init: 'تعذّر الوصول لخادم Anisette · Anisette server unreachable.',
    }[err.code];
    const appIdTaken = err.code === 'sign_failed' && /9400|is not available/.test(err.message || '')
      ? 'معرّف التطبيق (App ID) غير متاح لحسابك. جرّب إعادة التوقيع (سيُختار معرّف جديد تلقائياً) أو اكتب Bundle ID خاصاً بك في الخانة أعلاه. · The App ID is not available to your account. Retry (a new unique ID is picked automatically) or enter your own bundle ID above.\n'
      : '';
    return appIdTaken + (t && !appIdTaken ? t + '\n' : '') + (err.message ? '[' + err.code + '] ' + err.message : '');
  }

  function renderRewrite(j) {
    const el = $('rewriteNote');
    const r = j.bundleRewrite;
    if (!r || !r.to) { show(el, false); return; }
    const why = {
      reserved: ['معرّف التطبيق محجوز لشركة Apple (com.apple.*) ولا يمكن تسجيله في حساب مجاني، فغيّرناه تلقائياً.', 'The app\'s ID is reserved by Apple (com.apple.*) and cannot be registered on a free account, so it was changed automatically.'],
      unavailable: ['Apple رفضت معرّف التطبيق (غير متاح)، فجرّبنا معرّفاً فريداً آخر.', 'Apple rejected the app ID (not available), so another unique ID was tried.'],
      override: ['تم توقيع التطبيق بالمعرّف الذي اخترته.', 'The app is being signed with the bundle ID you chose.'],
    }[r.reason] || ['تم تغيير معرّف التطبيق.', 'The app ID was changed.'];
    setText(el, `${why[0]} · ${why[1]}\n${r.from} → ${r.to}\nقد لا تعمل بعض الميزات المرتبطة بالمعرّف الأصلي (App Groups، Keychain المشترك). · Features tied to the original ID (app groups, shared keychain) may not work.`);
    el.style.whiteSpace = 'pre-wrap';
    show(el);
  }

  function apply(j) {
    renderTimeline(j);
    renderRewrite(j);
    const err = $('signErr');
    if (j.status === 'error' && j.error) { setText(err, describeError(j.error)); err.style.whiteSpace = 'pre-wrap'; show(err); $('signBtn').disabled = false; stopPoll(); show($('tfaForm'), false); }
    else show(err, false);
    if (j.stage === 'need_2fa' && j.twofa) {
      show($('tfaForm'));
      const p = j.twofa;
      setText($('tfaInfo'), (p.lastError ? p.lastError + ' — ' : '') + (p.sms ? 'أُرسل رمز SMS · SMS code sent.' : 'أدخل الرمز المعروض على أجهزة Apple الموثوقة · Enter the code shown on your trusted Apple device.'));
      $('tfaSms').hidden = !(p.numbers && p.numbers.length);
      $('tfaSms').dataset.id = p.numbers && p.numbers[0] ? p.numbers[0].id : '1';
    } else if (j.stage !== 'need_2fa') show($('tfaForm'), false);
    if (j.status === 'ready' && j.install) {
      stopPoll(); showInstall(j);
    }
  }

  function stopPoll() { clearInterval(pollTimer); pollTimer = null; }
  function startPoll() {
    stopPoll();
    pollTimer = setInterval(async () => {
      const r = await api('GET', `/jobs/${job.jobId}`).catch(() => null);
      if (r && r.json && r.json.job) apply(r.json.job);
    }, 1500);
  }

  $('appleForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!job) return;
    const email = $('appleId').value.trim();
    const password = $('applePw').value;
    $('signBtn').disabled = true;
    show($('signErr'), false);
    const r = await api('POST', `/jobs/${job.jobId}/sign`, { email, password, confirm: $('ownConfirm').checked, maxCerts: $('revokeOk').checked ? 'revoke' : 'error', bundleId: $('bundleIdIn').value.trim() || undefined });
    $('applePw').value = ''; // do not keep the password in the DOM
    if (r.status !== 202) {
      const msg = { signer_not_built: 'عامل التوقيع غير مبني (ecid-signer) · Signer binary not built on the worker.', busy: 'العامل مشغول · Worker busy', rate_limited: 'محاولات كثيرة · Too many attempts', confirm_required: 'أكّد الملكية أولاً · Confirm ownership first', no_ipa: 'ارفع IPA أولاً · Upload an IPA first', bad_bundle_id: 'معرّف الحزمة غير صالح أو محجوز · Invalid or reserved bundle ID' }[r.json.error] || r.json.message || r.json.error || 'HTTP ' + r.status;
      setText($('signErr'), msg); show($('signErr')); $('signBtn').disabled = false;
      return;
    }
    apply(r.json.job);
    startPoll();
  });

  $('tfaForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const code = $('tfaCode').value.trim();
    if (!/^\d{4,8}$/.test(code)) return;
    await api('POST', `/jobs/${job.jobId}/2fa`, { action: 'code', code });
    $('tfaCode').value = '';
    show($('tfaForm'), false);
  });
  $('tfaSms').addEventListener('click', async () => { await api('POST', `/jobs/${job.jobId}/2fa`, { action: 'sms', id: Number($('tfaSms').dataset.id) }); });
  $('tfaResend').addEventListener('click', async () => { await api('POST', `/jobs/${job.jobId}/2fa`, { action: 'resend' }); });

  /* ---------- step 4 ---------- */
  function showInstall(j) {
    unlock('s4');
    show($('installBox'));
    const i = j.install;
    $('itmsBtn').href = i.itms;
    setText($('installPage'), i.pageUrl);
    const w = $('installWarn');
    if (!i.https) { setText(w, 'العامل لا يعمل عبر HTTPS صالح، وiOS سيرفض التثبيت. ضعه خلف HTTPS (README). · The worker is not on valid HTTPS; iOS will refuse. See README.'); show(w); } else show(w, false);
    setText($('installExp'), `${i.signedBundleId} — الرابط ينتهي: ${new Date(i.expiresAt).toLocaleString()} · link expires`);
    $('s4').scrollIntoView({ behavior: 'smooth' });
  }
  $('copyInstall').addEventListener('click', () => navigator.clipboard && navigator.clipboard.writeText($('installPage').textContent));
  $('wipeBtn').addEventListener('click', async () => {
    if (!job) return;
    await api('DELETE', `/jobs/${job.jobId}`);
    if (cfg.blobEnabled) await fetch('/api/blob-delete', { method: 'POST', headers: authHeaders(), cache: 'no-store', credentials: 'omit' }).catch(() => {});
    sessionStorage.removeItem('ecidJob');
    location.reload();
  });

  /* ---------- resume after reload ---------- */
  async function resume() {
    let saved = null;
    try { saved = JSON.parse(sessionStorage.getItem('ecidJob') || 'null'); } catch (_) {}
    if (!saved || !cfg.workerConfigured) return;
    job = saved;
    const r = await api('GET', `/jobs/${job.jobId}`).catch(() => null);
    if (!r || r.status !== 200) { sessionStorage.removeItem('ecidJob'); job = null; return; }
    const j = r.json.job;
    $('ecid').value = job.udid.split('-')[1] ? '0x' + job.udid.split('-')[1] : '';
    $('udidIn').value = job.udid.includes('-') ? job.udid : '';
    preview();
    unlock('s2');
    if (j.ipa) { renderMeta(j.ipa, j.warnings); unlock('s3'); }
    if (['signing', 'error', 'ready'].includes(j.status)) { unlock('s3'); apply(j); if (j.status === 'signing') startPoll(); }
  }

  splitBi(document);
  loadConfig().then(() => { preview(); resume(); });
})();
