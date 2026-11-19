---
name: mobile-appsec
description: Static security review of Android and iOS apps you own or are authorized to test, mapped to OWASP MASVS v2. Audits AndroidManifest.xml (debuggable, allowBackup, cleartext traffic, exported activities/services/receivers/providers without permissions, weak custom permissions, deep links and App Links autoVerify, network security config with user CAs and pinning) and iOS Info.plist plus entitlements (App Transport Security exceptions, custom URL schemes, empty permission purpose strings, shared Documents folder, hard-coded keys, get-task-allow, push and associated-domains config). Use whenever someone shares a manifest, Info.plist, APK/IPA they decoded, asks "is my app secure", prepares a mobile pentest, MASVS/MASTG assessment, App Store or Play review, or wants a mobile release security checklist, even if they only mention one platform.
---

# Mobile AppSec

Find the configuration mistakes that ship in real Android and iOS apps, straight from the manifest and plist, and map each one to OWASP MASVS v2.

## When to use

- "Review my AndroidManifest.xml / Info.plist for security"
- Pre-release checklist for a mobile app, or answering a store review question (ATS justification, Play permissions declaration)
- Scoping or starting a mobile pentest or MASVS assessment
- After decoding an APK (apktool) or unzipping an IPA you are allowed to test
- A finding mentions cleartext traffic, exported components, deep links, backups or debug builds

## Ground rules

- Only test apps the user owns or has written permission to assess. Decoding someone else's app to hunt bugs is out of scope without that permission
- Both scripts are static and offline: they read files, never install, run, patch or re-sign an app
- No bypass work: do not write pinning bypasses, root/jailbreak detection bypasses or Frida hooks. The testing workflow reference names where dynamic testing fits and leaves the how to the authorized tester's own tooling
- Hard-coded secrets are shown masked (first 4 characters then "..."). Tell the user to rotate anything real that shipped; never repeat the full value
- A manifest is only part of the app. A clean result here does not cover code, storage, crypto or server APIs. Say so

## Workflow

1. Get the inputs: `AndroidManifest.xml` (source or apktool output, plus `res/xml/` for the network security config), `Info.plist` and the entitlements (`.entitlements` file, or `codesign -d --entitlements :- App.app`). Ask for targetSdk/minSdk if the manifest comes from Gradle source (it is in `build.gradle`)
2. Run the scripts below
3. Group findings by MASVS category (the `masvs` field) and rank by severity
4. Check context before calling something a bug: an exported activity may be meant to be launched by partners; `NSAllowsLocalNetworking` is normal for apps that talk to LAN devices
5. Use `references/masvs-checklist.md` to list what the static pass could not cover and what to check next
6. For a full assessment, follow `references/mobile-testing-workflow.md`

## Tools

### android_manifest_audit.py

```bash
python3 scripts/android_manifest_audit.py app/src/main/AndroidManifest.xml --target-sdk 34 --min-sdk 26
python3 scripts/android_manifest_audit.py decoded/AndroidManifest.xml --json
python3 scripts/android_manifest_audit.py AndroidManifest.xml --nsc other/network_security_config.xml
```

Checks:
- AND-001 `debuggable="true"` (high); AND-004 `testOnly="true"`
- AND-002 `allowBackup="true"` with no backup rules; AND-003 allowBackup not set (defaults to true)
- AND-010 `usesCleartextTraffic="true"`; AND-011 cleartext allowed by default (targetSdk below 28)
- Network security config, auto-loaded from `res/xml/<name>.xml` next to the manifest: AND-012 base-config cleartext (high), AND-013 domain cleartext, AND-014 user CAs trusted outside `debug-overrides` (high), AND-015 no pin-set (info), AND-016 minSdk below 24 (user CAs trusted on Android 6 and lower), AND-017 config referenced but not found
- Exported components without a permission: AND-020 provider (high), AND-021 service, AND-022 receiver, AND-023 activity. Applies the implicit defaults (intent-filter means exported before targetSdk 31; providers exported by default only at SDK 16 or lower). Launcher and deep-link-only activities are skipped. AND-024 intent-filter without `android:exported` at targetSdk 31+
- AND-030 runtime permissions (info), AND-031 special permissions such as SYSTEM_ALERT_WINDOW or MANAGE_EXTERNAL_STORAGE, AND-032 custom permissions with protectionLevel normal/dangerous (and components guarded by them)
- Deep links: AND-040 custom scheme, AND-041 http(s) link without `autoVerify`, AND-042 plain `http`
- AND-050 targetSdk unknown (pass `--target-sdk`)

Binary AXML (straight from an APK) and XML with a DTD are refused with exit 2: decode with `apktool d` first.
JSON keys: `manifest`, `package`, `target_sdk`, `min_sdk`, `network_security_config`, `findings`.

### ios_plist_audit.py

```bash
python3 scripts/ios_plist_audit.py App/Info.plist
python3 scripts/ios_plist_audit.py Payload/App.app/Info.plist --entitlements ent.plist --json
```

Reads XML or binary plists. Checks:
- ATS: IOS-001 `NSAllowsArbitraryLoads` (high; low when iOS 10+ ignores it because `NSAllowsArbitraryLoadsInWebContent`, `...ForMedia` or `NSAllowsLocalNetworking` is present), IOS-002 web content, IOS-003 media, IOS-007 local networking (info)
- Exception domains: IOS-004 insecure HTTP, IOS-005 minimum TLS 1.0/1.1, IOS-006 forward secrecy off
- IOS-010 custom URL schemes; IOS-020 empty or placeholder `*UsageDescription`; IOS-021 `UIFileSharingEnabled`; IOS-022 more than 50 `LSApplicationQueriesSchemes`
- IOS-030 hard-coded secrets (known key formats, or secret-named keys with secret-looking values; masked); IOS-031 debug flags set to true
- Entitlements: IOS-040 `get-task-allow` true (high), IOS-041 `aps-environment` development, IOS-042 associated domains with `?mode=developer`

JSON keys: `plist`, `bundle_id`, `minimum_os`, `entitlements_checked`, `findings`.

Both tools: findings carry `id`, `severity`, `title`, `detail`, `fix`, optional `location` and `masvs` (category, e.g. `MASVS-NETWORK`). `--json`, `--fail-on` (default `high`), exit `0` clean, `1` findings at or above the threshold, `2` unreadable or invalid input.

## Output

One line first: app, platform(s), inputs reviewed and the high/critical count. Then a table:

| Severity | ID | MASVS | Issue | Fix |
|---|---|---|---|---|

Close with "Not covered by this static pass" (code, local storage, crypto use, runtime behavior, backend APIs) and the next steps from the workflow reference.

## References

- `references/masvs-checklist.md` every MASVS v2 control, what to check on Android and iOS, and which script finding maps to it
- `references/mobile-testing-workflow.md` the order of a full assessment, from scoping to retest, with the static/dynamic split
