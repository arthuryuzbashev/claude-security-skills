# Mobile app security testing workflow

A practical order for assessing an app you own or are authorized to test. Each phase lists what to collect and what it answers. Tool names are the common open-source ones; use what your team already runs.

## 0. Scope and permission

- Written authorization naming the app(s), versions, environments (staging vs production APIs) and test accounts
- The risk profile: plain app (MAS-L1), sensitive data (MAS-L2), or also anti-tampering (MAS-R). This picks the MASVS controls in `masvs-checklist.md`
- Rules for production backends: rate limits, no destructive actions, no real customer data
- A contact for stop-the-test events

## 1. Get the build

- Prefer source access plus a release-configured build. Testing only a debug build misses release settings and over-reports debug ones
- Android: the APK/AAB from the team; `bundletool build-apks` for an AAB
- iOS: an IPA signed for your test devices (Ad Hoc or development profile from the team)
- Note version, build number, targetSdk/minSdk, MinimumOSVersion

## 2. Static: configuration (this skill)

Android:
```bash
apktool d app.apk -o decoded/
python3 scripts/android_manifest_audit.py decoded/AndroidManifest.xml --json > android.json
```
iOS:
```bash
unzip -q App.ipa -d ipa/
python3 scripts/ios_plist_audit.py ipa/Payload/App.app/Info.plist --json > ios.json
codesign -d --entitlements :- ipa/Payload/App.app > ent.plist
python3 scripts/ios_plist_audit.py ipa/Payload/App.app/Info.plist --entitlements ent.plist
```
`codesign` runs on macOS only. The iOS script also reads `PrivacyInfo.xcprivacy` from the `.app` folder (or `--privacy-manifest` for a source tree); frameworks under `App.app/Frameworks/` carry their own manifests, so run it once per SDK bundle you care about. Answers: debug builds, backup, transport security, IPC surface, deep links, permissions, entitlements, Play target API level, privacy manifest gaps.

## 3. Static: code and bundle

- Secrets and crypto misuse: grep the decompiled code or source (jadx for Android, the source or a disassembler for iOS); run the crypto-tls skill's `crypto_review.py` on source
- Third-party SDKs and versions: dependency manifests (Gradle lock files, `Podfile.lock`, `Package.resolved`); check advisories
- WebView setup: JavaScript enabled, JS bridges, file access, URL allow-lists
- IPC handlers: what each exported component and deep link does with its input
- Local storage code paths: what is written to SharedPreferences, plists, SQLite, files, logs
- iOS privacy manifest (`PrivacyInfo.xcprivacy`) and required-reason APIs

## 4. Dynamic: on a test device

Use a dedicated test device or emulator/simulator with test accounts only.

- Traffic: route through an intercepting proxy you control. If the app pins, ask the team for a build with pinning switched off for testing rather than defeating it
- Storage after use: inspect the app sandbox (Android `run-as` works on debuggable test builds; iOS via a development-signed build) for tokens, PII, caches, screenshots
- Backups: create a device backup and look for the app's sensitive files
- IPC: launch exported components and deep links with unexpected input (`adb shell am start -W -a android.intent.action.VIEW -d "app://path?x=1"`, `xcrun simctl openurl booted "app://path?x=1"`)
- Auth and session: logout invalidates tokens server-side, tokens expire, step-up auth on sensitive actions, biometric unlock bound to a key
- UI: sensitive screens in the app switcher, copy/paste of secrets, keyboard caching
- Logs: `adb logcat` / Console.app while using sensitive features

## 5. Backend APIs

Most real mobile breaches are API bugs. Test the endpoints the app calls with the same rigor as a web API: object-level authorization (change IDs), mass assignment, rate limits, verbose errors. The web-appsec skill covers the HTTP side.

## 6. Resilience (only for MAS-R scope)

Check that integrity signals (Play Integrity, App Attest) are verified server-side, release builds are obfuscated and not debuggable, and the app behaves sensibly on rooted/jailbroken devices per the agreed policy. Report gaps against the threat model; do not ship bypass tooling in the report.

## 7. Report

For each finding: MASVS control, severity, evidence (file and line, request/response with secrets masked), impact in plain words, fix, and a retest note. Lead with the release blockers from the checklist's quick gate. List what was out of scope or not tested.

## 8. Retest

Re-run both scripts on the fixed build and diff the JSON (`id` + `location`). Retest dynamic findings by hand. Close only what is verified fixed on a release-configured build.
