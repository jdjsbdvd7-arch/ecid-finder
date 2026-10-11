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

## How it works (fixed flow)

1. Safari downloads a **Profile Service** `.mobileconfig` (`PayloadType = Profile Service`).
2. On Install, iOS POSTs a CMS-signed attribute plist to `/retrieve`.
3. The server parses the embedded XML and returns a **Configuration** profile with a removable **WebClip** to `/result.html?t=...` (not a bare HTML redirect — that caused *Invalid Profile*).
4. Open the WebClip, copy ECID, then delete both profiles from Settings.

Unsigned profiles are structurally valid; iOS only warns. Signing is optional polish.
