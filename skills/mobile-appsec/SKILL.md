---
name: mobile-appsec
description: Static security review of Android and iOS apps you own or are authorized to test, mapped to OWASP MASVS v2.1 and MASTG 2.0. Audits AndroidManifest.xml (debuggable, allowBackup, cleartext traffic, exported components without permissions, weak custom permissions, deep links and App Links autoVerify, network security config with user CAs and pinning, Google Play target API level, task hijacking, sharedUserId) and iOS Info.plist, entitlements and PrivacyInfo.xcprivacy (App Transport Security exceptions, custom URL schemes, empty purpose strings, hard-coded keys, get-task-allow, tracking domains, required reason API codes). Use whenever someone shares a manifest, Info.plist, privacy manifest or a decoded APK/IPA, asks "is my app secure", prepares a mobile pentest, MASVS assessment, App Store or Play review (ITMS-91053, target API rejection), or wants a mobile release checklist, even for one platform.
---

# Mobile AppSec

Find the configuration mistakes that ship in real Android and iOS apps, straight from the manifest, plist and privacy manifest, and map each one to OWASP MASVS v2.1 (current; MASTG 2.0 and MASWE 1.0 hold the tests and weaknesses).

## When to use

- "Review my AndroidManifest.xml / Info.plist for security"
- Pre-release checklist for a mobile app, or answering a store review question (ATS justification, Play permissions declaration)
- Scoping or starting a mobile pentest or MASVS assessment
- After decoding an APK (apktool) or unzipping an IPA you are allowed to test
- A finding mentions cleartext traffic, exported components, deep links, backups or debug builds
- Play rejected an update for its target API level, or App Store Connect sent ITMS-91053 (missing required reason API declaration)

## Ground rules

- Only test apps the user owns or has written permission to assess. Decoding someone else's app to hunt bugs is out of scope without that permission
- Both scripts are static and offline: they read files, never install, run, patch or re-sign an app
- No bypass work: do not write pinning bypasses, root/jailbreak detection bypasses or Frida hooks. The testing workflow reference names where dynamic testing fits and leaves the how to the authorized tester's own tooling
- Hard-coded secrets are shown masked (first 4 characters then "..."). Tell the user to rotate anything real that shipped; never repeat the full value
- A manifest is only part of the app. A clean result here does not cover code, storage, crypto or server APIs. Say so

## Workflow

1. Get the inputs: `AndroidManifest.xml` (source or apktool output, plus `res/xml/` for the network security config), `Info.plist`, the entitlements (`.entitlements` file, or `codesign -d --entitlements :- App.app`) and `PrivacyInfo.xcprivacy`. Ask for targetSdk/minSdk if the manifest comes from Gradle source (it is in `build.gradle`; apktool puts it in `apktool.yml`)
2. Run the scripts below
3. Group findings by MASVS category (the `masvs` field) and rank by severity
4. Check context before calling something a bug: an exported activity may be meant to be launched by partners; `NSAllowsLocalNetworking` is normal for apps that talk to LAN devices
5. Use `references/masvs-checklist.md` to list what the static pass could not cover and what to check next
6. For a full assessment, follow `references/mobile-testing-workflow.md`

## Tools

### android_manifest_audit.py

```bash
python3 scripts/android_manifest_audit.py app/src/main/AndroidManifest.xml --target-sdk 36 --min-sdk 26
python3 scripts/android_manifest_audit.py decoded/AndroidManifest.xml --json
python3 scripts/android_manifest_audit.py AndroidManifest.xml --nsc other/network_security_config.xml
python3 scripts/android_manifest_audit.py wear/AndroidManifest.xml --required-target-sdk 35
```

Checks:
- AND-001 `debuggable="true"` (high); AND-004 `testOnly="true"`
- AND-002 `allowBackup="true"` with no backup rules; AND-003 allowBackup not set (defaults to true)
- AND-010 `usesCleartextTraffic="true"`; AND-011 cleartext allowed by default (targetSdk below 28)
- Network security config, auto-loaded from `res/xml/<name>.xml` next to the manifest: AND-012 base-config cleartext (high), AND-013 domain cleartext, AND-014 user CAs trusted outside `debug-overrides` (high), AND-015 no pin-set (info), AND-016 minSdk below 24 (user CAs trusted on Android 6 and lower), AND-017 config referenced but not found
- Exported components without a permission: AND-020 provider (high), AND-021 service, AND-022 receiver, AND-023 activity. Applies the implicit defaults (intent-filter means exported before targetSdk 31; providers exported by default only at SDK 16 or lower). Launcher and deep-link-only activities are skipped. AND-024 intent-filter without `android:exported` at targetSdk 31+
- AND-030 runtime permissions (info), AND-031 special permissions such as SYSTEM_ALERT_WINDOW or MANAGE_EXTERNAL_STORAGE, AND-032 custom permissions with protectionLevel normal/dangerous (and components guarded by them)
- Deep links: AND-040 custom scheme, AND-041 http(s) link without `autoVerify`, AND-042 plain `http`
- AND-051 targetSdk below Google Play's rule: since 2026-08-31 new apps and updates need API 36 (low at 35), existing apps below 35 are hidden from new users (medium). `--required-target-sdk` sets the bar (35 for Wear OS and Automotive, 34 for TV); apps outside Play can treat it as hygiene
- AND-052 `allowTaskReparenting="true"` (task hijacking, StrandHogg; medium when minSdk is below 30, the release with the OS fix)
- AND-053 `sharedUserId` without `sharedUserMaxSdkVersion` (deprecated, shares files and permissions between apps)
- AND-050 targetSdk unknown (pass `--target-sdk`)

Binary AXML (straight from an APK) and XML with a DTD are refused with exit 2: decode with `apktool d` first.
JSON keys: `manifest`, `package`, `target_sdk`, `min_sdk`, `network_security_config`, `findings`.

### ios_plist_audit.py

```bash
python3 scripts/ios_plist_audit.py App/Info.plist
python3 scripts/ios_plist_audit.py Payload/App.app/Info.plist --entitlements ent.plist --json
python3 scripts/ios_plist_audit.py App/Info.plist --privacy-manifest App/PrivacyInfo.xcprivacy
```

Reads XML or binary plists. `PrivacyInfo.xcprivacy` next to the Info.plist is picked up on its own. Checks:
- ATS: IOS-001 `NSAllowsArbitraryLoads` (high; low when iOS 10+ ignores it because `NSAllowsArbitraryLoadsInWebContent`, `...ForMedia` or `NSAllowsLocalNetworking` is present), IOS-002 web content, IOS-003 media, IOS-007 local networking (info)
- Exception domains: IOS-004 insecure HTTP, IOS-005 minimum TLS 1.0/1.1, IOS-006 forward secrecy off
- IOS-010 custom URL schemes; IOS-020 empty or placeholder `*UsageDescription`; IOS-021 `UIFileSharingEnabled`; IOS-022 more than 50 `LSApplicationQueriesSchemes`
- IOS-030 hard-coded secrets (known key formats, or secret-named keys with secret-looking values; masked); IOS-031 debug flags set to true
- Entitlements: IOS-040 `get-task-allow` true (high), IOS-041 `aps-environment` development, IOS-042 associated domains with `?mode=developer`
- Privacy manifest: IOS-050 `NSPrivacyTracking` true with no `NSPrivacyTrackingDomains` (or domains with tracking false), IOS-051 a collected data type used for tracking while the app says it does not track (medium) or missing linked/tracking/purposes keys (low), IOS-052 required reason API with an unknown category, no reason, or a reason code from another category (App Store Connect rejects these, ITMS-91053), IOS-053 a `.app` bundle with no privacy manifest (info)

JSON keys: `plist`, `bundle_id`, `minimum_os`, `entitlements_checked`, `privacy_manifest_checked`, `findings`.

Both tools: findings carry `id`, `severity`, `title`, `detail`, `fix`, optional `location` and `masvs` (category, e.g. `MASVS-NETWORK`). `--json`, `--fail-on` (default `high`), exit `0` clean, `1` findings at or above the threshold, `2` unreadable or invalid input.

## Output

One line first: app, platform(s), inputs reviewed and the high/critical count. Then a table:

| Severity | ID | MASVS | Issue | Fix |
|---|---|---|---|---|

Close with "Not covered by this static pass" (code, local storage, crypto use, runtime behavior, backend APIs) and the next steps from the workflow reference.

## References

- `references/masvs-checklist.md` every MASVS v2 control, what to check on Android and iOS, and which script finding maps to it
- `references/mobile-testing-workflow.md` the order of a full assessment, from scoping to retest, with the static/dynamic split
