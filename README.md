# ECID Finder

Safari-only tool that uses Apple’s public **OTA Profile Service** flow to read a few device attributes (ECID, UDID, PRODUCT, VERSION) without a computer or jailbreak.

Inspired by the general idea of classic get-ecid / getudid-style sites. **Original implementation** — not a copy of those sites’ assets or code.

## How it works

1. Open the site in **Safari** on iPhone/iPad.
2. Download a temporary `.mobileconfig` (`PayloadType` = `Profile Service`).
3. The profile asks only for: `ECID`, `UDID`, `PRODUCT`, `VERSION` (no IMEI / ICCID / SERIAL).
4. The device POSTs a signed response to `/api/retrieve`.
5. The server extracts the embedded plist, signs a short-lived HMAC token, and redirects to `/result.html`.

No database: attributes travel in a signed query token (≈10 minutes TTL).

## Deploy (Vercel)

Required env:

- `RESULT_HMAC_SECRET` — long random secret (`openssl rand -hex 32`)
- Optional: `PUBLIC_BASE_URL` — absolute `https://…` if host detection is wrong

```bash
vercel env add RESULT_HMAC_SECRET
vercel --prod
```

## Privacy & safety

- Use Safari; other browsers often cannot install configuration profiles.
- Remove the profile after use: **Settings → General → VPN & Device Management**.
- The profile is typically **unsigned** (unsigned warning is expected) unless you add your own signing cert.
- Intended for personal / research use on devices you own.
- Do not use this to collect identifiers from others without clear consent.

## Local notes

- `api/profile.js` serves `application/x-apple-aspen-config`.
- `api/retrieve.js` disables body parsing so the PKCS#7 body is read raw; XML plist is sliced from the CMS blob (common public pattern).
- Companion converter UI may live separately in [ecid-tool](https://github.com/jdjsbdvd7-arch/ecid-tool).

## License

MIT

## Profile Service notes (iOS)

1. Enrollment profile (`/profile`) is unsigned XML — Safari shows a warning; that is expected.
2. On Install, iOS POSTs CMS (`application/pkcs7-signature`) to `/retrieve`.
3. `/retrieve` **must** return a Configuration `.mobileconfig` (WebClip to the result page). Plain-text 400/500 causes «فشل تثبيت ملف التعريف / حاول العملية مرة أخرى».
4. Body is read via Web Handler `request.arrayBuffer()` so Vercel helper parsing cannot destroy PKCS#7 bytes.
5. Delete the temporary profiles afterward: Settings → General → VPN & Device Management.

If install still fails before any result shortcut appears, check Stolen Device Protection and that the site is opened in **Safari** (not in-app browsers).

## How it works (Profile Service)

1. Safari downloads an unsigned **Profile Service** `.mobileconfig` (`PayloadContent` is a **dict** with `DeviceAttributes` then `URL` — same shape as getudid.co / Apple OTA Phase 1).
2. On Install, iOS POSTs a CMS-signed plist to `/retrieve`.
3. The server parses nested/flat dict keys (`UDID`, `ECID`, `CHALLENGE`, …) and responds with **HTTP 301** to `/result.html?t=…`.
   Returning HTML/text or an unsigned WebClip Configuration causes «ملف التعريف غير صالح / Invalid Profile».

## Why ECID may be empty from Profile Service

On many modern iOS builds, the Profile Service response includes `UDID`, `PRODUCT`, and `VERSION` but **omits** `ECID` even when it was listed in `DeviceAttributes`. Public libraries (e.g. udid-tools/core) document UDID/PRODUCT/VERSION/SERIAL/… and often not ECID.

For devices using the post-2018 UDID format `XXXXXXXX-YYYYYYYYYYYYYYYY` (8 hex ChipID + hyphen + 16 hex ECID), this tool derives ECID from the UDID suffix when the attribute is missing — the same approach used by working ECID/UDID helper sites and documented on The iPhone Wiki.

## Device Report (post-ECID)

After a successful extract, `/result.html` loads a **Device Report**:

- Marketing name (e.g. `iPhone14,3` → iPhone 13 Pro Max)
- Chip from modern UDID prefix (`00008110` → A15 Bionic / T8110)
- Build-id heuristics (`24B5089g` → likely Beta/Seed on iOS ~27.x B-train)
- **Currently signed** restore firmwares via proxied [ipsw.me API](https://api.ipsw.me) (`/api/firmwares`, `/api/device-report`)
- Practical bilingual tips (delete temp profile, beta instability, empty signing list)

Demo without Profile Service token: [`/report.html`](https://ecid-finder.vercel.app/report.html) (defaults to a sample iPhone14,3).

**Not included:** SHSH/TSS blob saving (nonce entanglement makes Safari-only SHSH weak on modern chips), iOS SDK downloads, or exploit tooling. Signing status is a research helper from a third-party API — not Apple-official advice.

## Manual ECID report

- `/manual.html`: type an ECID (decimal / hex / `0x…`) + optional model identifier; it opens `/report.html` with query params. Stateless — nothing is stored server-side.
- ECID alone carries no live device state. Signed-firmware status needs the model identifier (`iPhoneN,M`); live attributes (build, product) only come from the one-time Profile Service flow.
- The Profile Service request asks only for `UDID`, `VERSION`, `PRODUCT`, `ECID` (no IMEI / serial).

---

# Wireless install of your own IPA (`/sideload.html`)

An Expo-style flow (same *class* as sign.expo.dev: your own Apple account, temporary session, your own team), but for **an IPA you upload yourself**:

1. **Device** – you type the ECID (+ chip/model so we can form the modern UDID `CPID-ECID`, e.g. `00008110-001965E62213801E`). A12+ devices only: older devices have a 40-hex UDID that cannot be derived from an ECID (paste the UDID instead).
2. **IPA** – you upload *your own* `.ipa`. The site never hosts or supplies IPAs. It is validated (ZIP/Info.plist/Mach-O checks, zip-slip, size cap, FairPlay-encrypted App Store IPAs are rejected) and auto-deleted.
3. **Apple account** – you sign in with your Apple ID (+ 2FA). Session-only: the password goes **browser → signing worker → Apple**, is held in memory of a short-lived child process, is never written to disk/logs/env/argv, and never touches Vercel.
4. **Register + sign** – the worker registers the UDID on your free Personal Team, creates/fetches the development certificate, App ID(s) and provisioning profile, and signs the IPA.
5. **OTA** – the worker serves `manifest.plist` + the signed IPA over HTTPS; you open the install page on the iPhone and tap *Install* (`itms-services://`).
6. **Device status** – the manual ECID report (chip, signed firmwares) stays available.

Explicitly **not** included: SideInstaller-style DNS profiles, third-party certificate pools, TSS/SHSH downgrades, exploits, SRD/trust bypasses, hosting of IPAs.

## Architecture

```
Browser ──(1) POST /api/jobs {ecid,cpid,…}──▶ Vercel (static UI + stateless APIs)
   │            ◀── jobId + HMAC job token (JOB_HMAC_SECRET), workerUrl ──
   │
   ├─(2) PUT  {worker}/jobs/:id/ipa  (raw IPA, Bearer token) ─┐
   ├─(3) POST {worker}/jobs/:id/sign {email,password}         │  Signing worker (Node, zero deps)
   ├─(3b) POST {worker}/jobs/:id/2fa {code}                   │   └─ spawns `ecid-signer` (Rust, isideload)
   ├─ GET  {worker}/jobs/:id  (poll status)                   │        stdin JSON-lines: creds only in memory
   └─(5) iPhone Safari → {worker}/i/:installId → itms-services://…/ota/:installId/manifest.plist
```

| Piece | Path | Runs on |
|---|---|---|
| Wizard UI | `public/sideload.html`, `public/sideload.js` | Vercel or worker |
| ECID→UDID, job tokens, IPA inspection, OTA manifest | `lib/udid.js`, `lib/job-token.js`, `lib/ipa-inspect.js`, `lib/zip-lite.js`, `lib/plist-lite.js`, `lib/ota.js` | both |
| Stateless APIs | `api/jobs.js` (mints job token), `api/udid.js`, `api/config.js` | Vercel (also served by the worker) |
| Worker HTTP server | `worker/server.js` | your Linux box / VPS / Docker |
| Interactive CLI (no web form) | `worker/cli.js` | same box |
| Apple signer | `worker/signer/` (Rust, wraps [`isideload`](https://crates.io/crates/isideload) 0.4.4: GrandSlam SRP login, 2FA, developer-services API, `apple-codesign`) | same box |
| Docker | `worker/Dockerfile` | any Docker host |

Security properties: no hardcoded secrets (`JOB_HMAC_SECRET` / `RESULT_HMAC_SECRET` must be set; outside production a random per-process secret is used); job tokens are HMAC-SHA256, 2 h TTL, bound to jobId + UDID; CORS allow-list (`ALLOWED_ORIGINS`) and the worker URL comes only from server config (never from the URL) so a crafted link cannot point the form at someone else's server; upload size cap (`MAX_IPA_BYTES`, default 600 MB, enforced on `Content-Length` and while streaming); per-IP rate limits, ≤5 sign attempts per job, concurrency cap; certificate private key kept in memory only; originals deleted right after signing, signed IPAs after `SIGNED_TTL_MS` (3 h) or on *Delete now*; `sideload.html` ships a strict CSP and `no-referrer`.

## What works where (honest status)

| | Status |
|---|---|
| ECID → UDID, validation, ambiguity warnings | ✅ works, unit-tested |
| IPA upload endpoint, validation, size limits, zip-slip / FairPlay rejection | ✅ works, unit + e2e tested |
| Job tokens, rate limits, CORS, session-only credential handling | ✅ tested (credentials asserted absent from disk and error output) |
| OTA manifest + Range-capable IPA serving + install page | ✅ tested over HTTP; **iOS needs valid HTTPS** (see below) |
| Wizard UI (Arabic/English) incl. upload, Apple form, 2FA step, timeline, install step | ✅ driven end-to-end with a headless browser against the worker using the **test signer** |
| Rust `ecid-signer` builds and speaks the protocol | ✅ builds (Rust ≥ 1.88); protocol/validation errors verified |
| **Real Apple login, device registration, cert/profile creation, signing** | ⚠️ **Implemented through `isideload`, but NOT exercised against live Apple in this repo's CI/box**: the build box cannot reach `gsa.apple.com` (TLS-intercepted), and no real Apple credentials were used. First live run must be done by the account owner (CLI recommended). Treat as *unverified until you run it once*. |
| On-device wireless install | ⚠️ Not tested on a physical device. Requires: Developer Mode (iOS 16+), valid public HTTPS cert, device UDID in the profile, trusting the developer profile after install. Free accounts: 7-day profile, 3 apps, 10 App IDs/week, 3 devices. |
| Vercel deployment alone | ✅ UI, UDID derivation, device report, job-token minting. ❌ Cannot upload/sign by itself: Vercel functions cap request bodies at ~4.5 MB, have no long-running processes and no Rust signer — that is why a worker exists. Without `WORKER_PUBLIC_URL` the wizard shows a clear "worker not connected" banner. |

### Needs infrastructure / interaction
- **Anisette**: Apple requires "anisette" device headers. The signer uses `isideload`'s remote v3 provider (default `https://ani.stikstore.app`, a community server) — fine for personal use, but for anything serious self-host [`anisette-v3-server`](https://github.com/Dadoum/anisette-v3-server) and set `ANISETTE_URL`.
- **Apple ID + 2FA**: a human must enter the password and the 2FA code each session (web form or terminal). There is no unattended mode and none should be added.
- **Signing worker host**: Linux with outbound access to `gsa.apple.com`, `developerservices2.apple.com`, the anisette server, plus public HTTPS (reverse proxy, or a tunnel such as `cloudflared tunnel --url http://127.0.0.1:8787`) for the iPhone.
- **Certificate limit**: free teams hold only a couple of development certificates. If you hit it, the signer fails with a clear error unless you ticked *allow revoking existing dev certificates* (that can invalidate apps installed with AltStore/SideStore).

## Run it

Everything below assumes Node ≥ 18. Run tests: `npm test`.

### A. Standalone on a box (worker serves the whole site)

```bash
# 1. build the signer (Rust >= 1.88; `curl https://sh.rustup.rs | sh` if needed)
(cd worker/signer && cargo build --release)

# 2. run the worker (serves public/ + API + OTA)
export JOB_HMAC_SECRET=$(openssl rand -hex 32)
export PUBLIC_BASE_URL=https://your-tunnel-or-domain.example   # must be valid HTTPS for iOS
export TRUST_PROXY=1                                            # if behind a proxy/tunnel
node worker/server.js          # http://127.0.0.1:8787/sideload.html
```

### B. Vercel site + remote worker

```bash
# worker host (as above) plus:
export ALLOWED_ORIGINS=https://ecid-finder.vercel.app
# Vercel project env:
vercel env add JOB_HMAC_SECRET        # SAME value as the worker
vercel env add WORKER_PUBLIC_URL      # https://worker.example.com
vercel --prod
```

### C. No web form for credentials (recommended for the first live test)

```bash
node worker/cli.js sign --ipa ./MyApp.ipa --ecid 0x1965E62213801E --cpid 8110 \
     --name "My iPhone" --publish
# prompts Apple ID, hidden password, 2FA code in the terminal; writes signed.ipa and
# (with --publish) registers it so a running worker serves /i/<id> for the iPhone.
```

### Docker

```bash
docker build -f worker/Dockerfile -t ecid-worker .
docker run -p 8787:8787 -e JOB_HMAC_SECRET=... -e PUBLIC_BASE_URL=https://… -e TRUST_PROXY=1 \
  -e ALLOWED_ORIGINS=https://ecid-finder.vercel.app -v ecid-data:/data ecid-worker
```

### How to test without Apple credentials

`worker/test/fake-signer.js` is a **test-only** stand-in for `ecid-signer` (it copies the IPA; accepts password `test-password` and 2FA `123456`; it never contacts Apple). Use it to try the whole UI/pipeline:

```bash
JOB_HMAC_SECRET=dev-secret-0123456789abcdef ECID_SIGNER_BIN=$PWD/worker/test/fake-signer.js node worker/server.js
# open http://127.0.0.1:8787/sideload.html  → ECID 0x1965E62213801E, model iPhone14,3 → upload any IPA
```

## Environment variables

See `.env.example`. Key ones: `JOB_HMAC_SECRET` (both sides), `RESULT_HMAC_SECRET` (Vercel), `WORKER_PUBLIC_URL` (Vercel), `PUBLIC_BASE_URL`, `ALLOWED_ORIGINS`, `TRUST_PROXY`, `MAX_IPA_BYTES`, `ANISETTE_URL`, `ECID_WORKER_DATA`, `ECID_SIGNER_BIN`.

## Signer protocol (for contributors)

`ecid-signer` reads one JSON line on stdin — `{email,password,udid,deviceName,ipa,out,maxCerts,anisetteUrl,stateDir}` — and prints JSON-line events (`stage`, `need_2fa`, `team`, `device_registered`, `progress`, `done`, `error`). 2FA replies are JSON lines on stdin: `{"action":"code","code":"123456"}` | `sms` | `devices` | `resend`. Only anisette device state is written to `stateDir`; no tokens, passwords or keys.

## Legal / responsible use

Use your own Apple account, your own devices and an IPA you are entitled to sign. Free-account limits are Apple's. This project is not affiliated with Apple; it drives the same developer-services endpoints Xcode uses (undocumented and subject to change) through open-source libraries (`isideload`, `apple-codesign`).
