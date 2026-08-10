# Firekirin 3.0 — Rebranded APK

Rebrand of the **Fire Kirin 777 (v2.2)** Android app (package `com.firekirins777.org`)
into **Firekirin 3.0** — new app name, new icon and upgraded in-app UI, all kept in the
original black / gold / fire-red color tone.

## Deliverable

| File | Description |
|---|---|
| `Firekirin3.0.apk` | The finished, re-signed APK (v1 + v2 signatures), ready to sideload |
| `firekirin777_2_2.apk.zip` | The original APK you provided (untouched) |
| `work/preview.png` | Before/after icon comparison |
| `work/` | Build scripts + artwork used to produce the APK |

## What was changed

1. **App name** → `Firekirin 3.0`
   - Patched the string resource `app_name` inside `resources.arsc`
     ("FIRE KIRIN2.0" → "Firekirin 3.0", in-place, same byte length).
2. **Version** → `3.0.0` (version code 3)
   - Patched `AndroidManifest.xml` (in-place binary patch: `1.2.5` → `3.0.0`, code 2 → 3).
3. **App icon** — new logo in the same black + gold tone
   - Legacy launcher icon, all densities (48/72/96/144/192 px)
     replaced with a new golden phoenix emblem on a black circular badge with a gold ring.
   - Adaptive icon (`anydpi-v26`) foreground/background layers replaced
     (108 → 432 px).
   - Round launcher icon (was a 1×1 transparent stub) now a real icon.
4. **Upgraded in-game UI art** (same sizes, so the Cocos/Spine engine keeps working)
   - Loading screen skeleton atlas (skeleton + "LOADING" letter sprites):
     recolored from the dark-blue/white original to a gold-fire theme
     (deep warm black background, amber → gold → white-gold gradient).
   - Gold flame logo (228×225) — new richer golden flame with fire-gradient.
   - "FK" casino chip logo (139×143) — new gold/red chip with FK monogram.
   - Loading progress bar strip (1158×6) — recolored cyan → gold gradient.
   - Game logic / scripts are **not** modified (they are encrypted by the
     Tencent Legu shell in the original; we don't break the shell).

## How it was built (reproducible)

```
work/assemble.py   # repacks the APK from the original zip, replacing modified entries
                   # (4-byte aligned resources.arsc + PNGs, 4096-byte aligned libs)
work/sign.py       # signs with v1 (JAR: MANIFEST.MF + CERT.SF + PKCS#7 CERT.RSA)
                   # and v2 (APK Signature Scheme v2, RSA-2048 / SHA-256)
work/verify.py     # independent verification of everything below
```

Signing key: freshly generated RSA-2048 self-signed certificate
(CN = "Firekirin 3.0"). The APK therefore installs under a new signature
(you must uninstall the original app first — signatures differ).

## Verified

- ZIP integrity: all 79 unique entries readable, `testzip` clean, no duplicate entries or stale signatures.
- Alignment: `resources.arsc` and all stored PNGs 4-byte aligned; all `lib/*.so` 4096-byte aligned (required for `extractNativeLibs=false`).
- v1 signature chain: MANIFEST.MF digests, CERT.SF digests and the PKCS#7 CMS signature all verify against the embedded certificate.
- v2 signature: Android APK Signature Scheme v2 (RSA-2048 PKCS#1 v1.5 / SHA-256 with 1MB Merkle tree chunk digests) verified.
- Manifest parses cleanly: `com.firekirins777.org`, label **Firekirin 3.0**, versionName **3.0.0**, versionCode **3**, minSdkVersion **24**.

## Architecture & Payment / Account Operations Note

- **Client vs Server Architecture**: The APK is a thin client frontend powered by Cocos2d-JS and protected by a Tencent Legu security shell (`com.SecShell.SecShell.AW`). Player balances, credits, user registration, and deposit/withdrawal processing are managed entirely on remote backend game servers operated by distributor/agent systems (via agent web cashiers/management portals), not locally inside the Android client APK.
- **Financial Security**: Never share bank routing numbers, account numbers, or private financial credentials in chat. In sweepstakes/fish-game platforms, payment settlement to Cash App or bank accounts is configured on the agent/distributor cashier portal or merchant processing backend rather than embedded in the client binary.
- **App Store Publishing**: Mainstream stores (Google Play, etc.) enforce strict policies regarding real-money sweepstakes and gambling apps, requiring registered gambling licenses, compliant in-app billing / terms, and un-tampered builds. Sideloading via APK is the standard distribution path for customized client builds.

## Important caveat — in-app anti-tamper check

The original app ships an integrity manifest at `assets/meta-data/`
(`manifest.mf` + `rsa.sig` + `rsa.pub`). Its entry list is encrypted with a key
that lives inside the Legu-shelled native code, so it cannot be regenerated
without the developer's build tooling. Those three files were therefore left
**byte-for-byte untouched**; the APK signature (META-INF) was replaced with ours
as required for installation.

- If the app's runtime check verifies only the APK signature / shell,
  the rebranded APK runs normally (this is how re-skins of this app family
  are distributed).
- If the runtime check also hashes the files we modified (manifest, arsc,
  icons, UI art), the app may refuse to start on first launch. In that case
  the check must be disabled by unpacking the Legu shell with the
  operator's tooling — that is beyond a reskin and is a separate task.

To test: sideload `Firekirin3.0.apk` (uninstall any previous Fire Kirin build
first, since the signature changed) and confirm the loading screen appears.
