# OWASP MASVS v2 checklist

MASVS v2 has 8 categories and 24 controls. The MASTG (testing guide) holds the test cases; the MAS testing profiles (L1, L2, R) say which controls apply to which app. Check the current MASVS release on mas.owasp.org for any wording changes; the control IDs below are stable in v2.

Columns: what to look at on each platform, and which script finding points at the control (category-level tags in the `masvs` field).

## MASVS-STORAGE

| Control | Check | Script |
|---|---|---|
| STORAGE-1: the app securely stores sensitive data | Tokens and keys in Keystore/Keychain, not SharedPreferences, plists, SQLite or files in plain form. iOS file protection class (`NSFileProtectionComplete` where possible) | IOS-021 |
| STORAGE-2: the app prevents leakage of sensitive data | Backups (Android `allowBackup` and extraction rules, iOS files excluded from backup), logs, screenshots in app switcher, keyboard cache, clipboard, shared Documents | AND-002, AND-003, IOS-021 |

## MASVS-CRYPTO

| Control | Check | Script |
|---|---|---|
| CRYPTO-1: current strong cryptography used per best practice | No DES/RC4/ECB/MD5 for security, random IVs, AEAD modes (see the crypto-tls skill) | crypto-tls `crypto_review.py` on the source |
| CRYPTO-2: key management per best practice | No hard-coded keys, keys in Keystore/Secure Enclave, server secrets never in the app | IOS-030 |

## MASVS-AUTH

| Control | Check | Script |
|---|---|---|
| AUTH-1: secure authentication and authorization protocols | OAuth with PKCE in the system browser (Custom Tabs, ASWebAuthenticationSession), server-side session checks, token expiry | AND-040, IOS-010 (auth codes in custom schemes) |
| AUTH-2: local authentication done per platform best practice | Biometrics bound to a Keystore/Keychain key (CryptoObject, `kSecAccessControl...`), not a bare boolean callback | none |
| AUTH-3: sensitive operations need extra authentication | Step-up auth for payments, password change, device binding | none |

## MASVS-NETWORK

| Control | Check | Script |
|---|---|---|
| NETWORK-1: all network traffic secured per best practice | HTTPS only, TLS 1.2+, no user CA trust in release, no custom trust managers or hostname verifiers that accept everything | AND-010..016, AND-042, IOS-001..007 |
| NETWORK-2: identity pinning for endpoints the developer controls | Pin-set or pinning library for own APIs, with backup pins and an expiry/rotation plan (higher-risk profiles) | AND-015 |

## MASVS-PLATFORM

| Control | Check | Script |
|---|---|---|
| PLATFORM-1: IPC mechanisms used securely | Exported components, permissions with signature level, pending intents immutable, deep link parameter validation, URL schemes, universal links/App Links verification | AND-020..024, AND-032, AND-040, AND-041, IOS-010, IOS-042 |
| PLATFORM-2: WebViews used securely | JavaScript only when needed, no `addJavascriptInterface` / message handlers exposed to untrusted pages, file access off, HTTPS content only | IOS-002 |
| PLATFORM-3: user interface used securely | Sensitive screens hidden from screenshots/app switcher (`FLAG_SECURE`), tapjacking protection, masked input | AND-031 (overlay permission) |

## MASVS-CODE

| Control | Check | Script |
|---|---|---|
| CODE-1: requires an up-to-date platform version | Reasonable minSdk / MinimumOSVersion, current targetSdk | AND-016, AND-050 |
| CODE-2: mechanism to enforce app updates | Server-side minimum version, in-app update prompt | none |
| CODE-3: only components without known vulnerabilities | Dependency inventory and advisories (Gradle, CocoaPods, SPM) | none |
| CODE-4: validates and sanitizes all untrusted input | Intent extras, deep link params, IPC, file imports, SQL, WebView URLs | AND-020..023 detail text |

Release-build hygiene (testOnly, debug profiles, debug flags) is grouped here too: AND-004, IOS-031, IOS-041.

## MASVS-RESILIENCE

Applies when the threat model includes tampering or reverse engineering (MAS-R profile): banking, DRM, games with economies, high-value fraud targets.

| Control | Check | Script |
|---|---|---|
| RESILIENCE-1: validates the integrity of the platform | Root/jailbreak and emulator signals, Play Integrity / App Attest server-side | none |
| RESILIENCE-2: anti-tampering mechanisms | Signature and integrity checks, server-side attestation | none |
| RESILIENCE-3: anti-static analysis mechanisms | Obfuscation (R8/ProGuard rules), stripped symbols | none |
| RESILIENCE-4: anti-dynamic analysis techniques | Debugger detection; a release build must not be debuggable | AND-001, IOS-040 |

## MASVS-PRIVACY

| Control | Check | Script |
|---|---|---|
| PRIVACY-1: minimizes access to sensitive data and resources | Only needed permissions, coarse instead of fine location, photo picker instead of storage | AND-030, AND-031, IOS-022 |
| PRIVACY-2: prevents identification of the user | No stable device IDs for tracking without consent, ATT on iOS where required | none |
| PRIVACY-3: transparent about data collection and usage | Clear purpose strings, Play Data safety form and App Store privacy labels match behavior, privacy manifest (`PrivacyInfo.xcprivacy`) | IOS-020 |
| PRIVACY-4: offers user control over their data | Account and data deletion, consent withdrawal | none |

## Quick release gate

Block a release on any of: debuggable / get-task-allow, ATS fully off or base-config cleartext, user CAs trusted in release, an exported provider without permission, a live secret in the bundle. Everything else goes on the fix list with an owner and a date.
