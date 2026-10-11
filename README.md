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
