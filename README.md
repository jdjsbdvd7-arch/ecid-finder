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
2. **IPA** – you upload *your own* `.ipa`. The site never hosts or supplies IPAs. With a Vercel Blob store connected, the browser uploads it **directly to Blob** (client upload, short-lived path-scoped token), the signing worker downloads it once from that Blob URL, validates it (ZIP/Info.plist/Mach-O checks, zip-slip, size cap, FairPlay-encrypted App Store IPAs are rejected) and the Blob copy is deleted immediately (plus a daily sweep). Without Blob, the browser PUTs the file straight to the worker.
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
   ├─(2a) Vercel Blob client upload → /api/blob-upload (job token → scoped client token)
   ├─(2b) POST {worker}/jobs/:id/ingest {ipaUrl: <Blob URL>}  (worker downloads, validates)
   │      then POST /api/blob-delete (deletes ipa/<jobId>/*)      [fallback: PUT {worker}/jobs/:id/ipa]  ─┐
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
| Blob hand-off | `api/blob-upload.js` (token handler), `api/blob-delete.js`, `api/blob-sweep.js` (daily cron), `lib/blob-policy.js`, `public/vendor/blob-client.js` (bundled `@vercel/blob/client`, rebuild with `npm run build:client`) | Vercel |
| Worker HTTP server | `worker/server.js` | your Linux box / VPS / Docker |
| Interactive CLI (no web form) | `worker/cli.js` | same box |
| Apple signer | `worker/signer/` (Rust, wraps [`isideload`](https://crates.io/crates/isideload) 0.4.4: GrandSlam SRP login, 2FA, developer-services API, `apple-codesign`) | same box |
| Docker | `worker/Dockerfile` | any Docker host |

Security properties: no hardcoded secrets (`JOB_HMAC_SECRET` / `RESULT_HMAC_SECRET` must be set; outside production a random per-process secret is used); job tokens are HMAC-SHA256, 2 h TTL, bound to jobId + UDID; CORS allow-list (`ALLOWED_ORIGINS`) and the worker URL comes only from server config (never from the URL) so a crafted link cannot point the form at someone else's server; upload size cap (`MAX_IPA_BYTES`, default 600 MB, enforced on `Content-Length` and while streaming); per-IP rate limits, ≤5 sign attempts per job, concurrency cap; certificate private key kept in memory only; originals deleted right after signing, signed IPAs after `SIGNED_TTL_MS` (3 h) or on *Delete now*; `sideload.html` ships a strict CSP and `no-referrer`.

## Vercel Blob hand-off (how the IPA moves)

```
browser ──upload()──▶ Vercel Blob  ipa/<jobId>/<name>-<random>.ipa      (client upload; bytes never touch a function)
   ▲ token: POST /api/blob-upload  (Authorization: Bearer <job token>)
   │   • path must be ipa/<this job's id>/<file>.ipa   • content-type octet-stream/zip   • ≤ MAX_IPA_BYTES
   │   • token valid 30 min, addRandomSuffix, no overwrite
worker ◀── POST /jobs/:id/ingest {ipaUrl}   • https only, host must be <store>.public.blob.vercel-storage.com
                                            • path must be inside THIS job's prefix (no SSRF), no redirects, size-capped stream
browser ──▶ POST /api/blob-delete  → deletes everything under ipa/<jobId>/   (also on "Delete now")
cron    ──▶ /api/blob-sweep (daily, CRON_SECRET) → deletes ipa/* older than 3 h (abandoned uploads)
```

Honest notes: the store is **public** (URLs are unguessable — 96-bit job id + random suffix — but anyone who has the URL can read the file until it is deleted, normally seconds after the upload). A private store with presigned reads is a possible hardening. Blob client uploads are also why a quick tunnel is fine: the worker pulls the file outbound, so a tunnel's request-size limit never applies.

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
| Vercel Blob upload (browser → Blob → worker ingest → delete) | ✅ token route, path/size/type limits, ingest SSRF allow-list, size cap and validation are tested; deployed route verified with a real job token (see "Live deployment checks" below). Not yet exercised with a multi-hundred-MB IPA from a real browser. |
| Vercel deployment alone | ✅ UI, UDID derivation, device report, job-token minting, Blob token route. ❌ Cannot sign by itself: Vercel functions have no long-running processes and no Rust signer — that is why a worker exists. Without `WORKER_PUBLIC_URL` the wizard shows a clear "worker not connected" banner. |
| Worker on a **Vercel Sandbox** | ✅ Evaluated and works as a *temporary* host: Firecracker microVM (Ubuntu, Node), a public HTTPS URL for an exposed port (valid cert → iOS accepts the OTA link), outbound internet. The prebuilt `ecid-signer` binary runs there, and a probe with a dummy non-existent Apple ID got a real answer from Apple's GrandSlam (`-20101 account information entered incorrectly`) — i.e. anisette provisioning + TLS to Apple work from there. ⚠️ Limits: a sandbox has a hard lifetime (45 min here; 5 h max on higher plans), the URL changes every time, state is wiped, so it suits a test session, not a permanent service. Use a VPS/Docker for something durable. |

### Live deployment checks (2026-10-11)

Run against https://ecid-finder.vercel.app with the worker hosted in a Vercel Sandbox:

- `/sideload.html` and `/api/config` respond (`blobEnabled: true`, `workerConfigured: true`).
- `/api/blob-upload`: 401 without/with a tampered job token, 403 for another job's path / wrong extension / path outside `ipa/`, 405 for GET, 200 + client token for `ipa/<jobId>/<file>.ipa`. A real client upload succeeded; a `text/html` upload was refused by the Blob token.
- Worker `/jobs/:id/ingest` pulled that Blob (HTTP 200, IPA validated, CORS header for the site origin); a non-Blob URL was refused (`host_not_allowed`).
- `/api/blob-delete` removed the blob (public URL → 404 afterwards); `/api/blob-sweep` rejects calls without `CRON_SECRET`.
- Headless Chrome drove the real wizard: ECID → job → file chosen → Blob upload → worker ingest → "IPA validated".
- **Not verified:** an actual Apple ID login/2FA, device registration, signing and the on-device install (needs the account owner's Apple ID and an iPhone). A dummy-account probe only proves the signer reaches Apple's login endpoint through anisette.

### Needs infrastructure / interaction
- **Anisette**: Apple requires "anisette" device headers. The signer uses `isideload`'s remote v3 provider. `isideload`'s own default (`https://ani.stikstore.app`) sits behind a Cloudflare challenge for datacenter IPs and failed from a Vercel Sandbox, so this repo defaults to the community server `https://ani.sidestore.io` (worked there). Community servers can disappear or throttle — for anything serious self-host [`anisette-v3-server`](https://github.com/Dadoum/anisette-v3-server) and set `ANISETTE_URL`. Note: a third-party anisette server sees your device-ID-like anisette provisioning traffic but never your Apple ID password (that goes to Apple only).
- **Apple ID + 2FA**: a human must enter the password and the 2FA code each session (web form or terminal). There is no unattended mode and none should be added.
- **Signing worker host**: Linux with outbound access to `gsa.apple.com`, `developerservices2.apple.com`, the anisette server, plus public HTTPS (reverse proxy, a tunnel such as `cloudflared tunnel --url http://127.0.0.1:8787` — quick tunnels are ephemeral and need outbound TCP/UDP 7844, which some sandboxes block — or a Vercel Sandbox for a short test) for the iPhone.
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
vercel env add CRON_SECRET            # authorises /api/blob-sweep
vercel blob store add ecid-finder-ipa --access public   # or Dashboard → Storage → Blob; connect to the project
                                      #   (adds BLOB_READ_WRITE_TOKEN; its presence turns the Blob upload path on)
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

See `.env.example`. Key ones: `JOB_HMAC_SECRET` (both sides), `RESULT_HMAC_SECRET` (Vercel), `WORKER_PUBLIC_URL` (Vercel), `BLOB_READ_WRITE_TOKEN` (Vercel, from the connected Blob store), `CRON_SECRET` (Vercel), `PUBLIC_BASE_URL`, `ALLOWED_ORIGINS`, `TRUST_PROXY`, `MAX_IPA_BYTES`, `ANISETTE_URL`, `ECID_WORKER_DATA`, `ECID_SIGNER_BIN`.

## Signer protocol (for contributors)

`ecid-signer` reads one JSON line on stdin — `{email,password,udid,deviceName,ipa,out,maxCerts,anisetteUrl,stateDir,bundleId?}` — and prints JSON-line events (`stage`, `bundle_rewrite`, `need_2fa`, `team`, `device_registered`, `progress`, `done`, `error`). 2FA replies are JSON lines on stdin: `{"action":"code","code":"123456"}` | `sms` | `devices` | `resend`. Only anisette device state is written to `stateDir`; no tokens, passwords or keys.

## Legal / responsible use

Use your own Apple account, your own devices and an IPA you are entitled to sign. Free-account limits are Apple's. This project is not affiliated with Apple; it drives the same developer-services endpoints Xcode uses (undocumented and subject to change) through open-source libraries (`isideload`, `apple-codesign`).


## App ID / bundle identifier handling (Apple error 9400)

isideload registers the App ID `<CFBundleIdentifier>.<TEAMID>` on the user's free Personal Team. If the IPA's identifier is in a namespace the team cannot own (`com.apple.*`, e.g. `com.apple.mobile.MobileHouseArrest`), Apple answers `DeveloperError(9400, "An App ID with Identifier '…' is not available")`. This is **unrelated to Apple root CAs / cdhash** — nothing is injected into the app for this.

`ecid-signer` therefore rewrites the identifier **before** signing (the standard AltStore/SideStore approach): main app, app extensions and Watch app `Info.plist`s are changed consistently (`com.apple.mobile.Foo` → `com.ecidfinder.foo.<6 hex>`, deterministic so re-signing the same IPA reuses the same App ID instead of burning one of the 10 weekly App IDs). It also retries with another unique id if Apple still answers 9400/"not available". The user can force their own id with the optional *Custom bundle ID* field (`bundleId` in `/jobs/:id/sign`; `com.apple.*` is refused). The worker exposes the change as `job.bundleRewrite {from,to,reason}` (`reserved`/`unavailable`/`override`) and the wizard shows it in Arabic + English; the OTA manifest uses the signed IPA's final bundle id.
