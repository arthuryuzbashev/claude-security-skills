#!/usr/bin/env python3
"""Static audit of an iOS Info.plist (XML or binary) and, optionally, the app's entitlements.

Usage:
  ios_plist_audit.py App/Info.plist
  ios_plist_audit.py Payload/App.app/Info.plist --entitlements app.entitlements --json
  ios_plist_audit.py App/Info.plist --privacy-manifest App/PrivacyInfo.xcprivacy
  codesign -d --entitlements :- App.app > ent.plist && ios_plist_audit.py Info.plist --entitlements ent.plist
  cat Info.plist | ios_plist_audit.py -
"""
from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import sys
from typing import Dict, List, Optional

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
ATS_OVERRIDES = ("NSAllowsArbitraryLoadsInWebContent", "NSAllowsArbitraryLoadsForMedia", "NSAllowsLocalNetworking")
OLD_TLS = {"TLSv1.0", "TLSv1.1"}
QUERY_SCHEME_LIMIT = 50  # apps linked on iOS 15+ are limited to 50 entries
PLACEHOLDER = re.compile(r"^\s*(todo|tbd|fixme|test|placeholder|description|usage description|xxx+|\.+|-+|\$\(.*\))?\s*$", re.I)

SECRET_PATTERNS = [
    # (regex on value, severity, label)
    (re.compile(r"^sk_live_[0-9A-Za-z]{10,}$"), "high", "Stripe live secret key"),
    (re.compile(r"^AKIA[0-9A-Z]{16}$"), "high", "AWS access key ID"),
    (re.compile(r"^xox[abpr]-[0-9A-Za-z-]{10,}$"), "high", "Slack token"),
    (re.compile(r"^gh[pousr]_[0-9A-Za-z]{30,}$"), "high", "GitHub token"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "critical", "private key"),
    (re.compile(r"^AIza[0-9A-Za-z_-]{35}$"), "low", "Google API key"),
]
SECRET_KEY_NAME = re.compile(r"(secret|password|passwd|private[_-]?key|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)", re.I)
DEBUG_KEY_NAME = re.compile(r"(debug|staging|verbose[_-]?log|dev[_-]?mode|disable[_-]?ssl|allow[_-]?insecure)", re.I)

# Required reason API categories and their approved reason codes (Apple "NSPrivacyAccessedAPIType",
# verified 2026-11-19). App Store Connect rejects uploads that use these APIs without a declared reason.
REQUIRED_REASONS = {
    "NSPrivacyAccessedAPICategoryFileTimestamp": {"DDA9.1", "C617.1", "3B52.1", "0A2A.1"},
    "NSPrivacyAccessedAPICategorySystemBootTime": {"35F9.1", "8FFB.1", "3D61.1"},
    "NSPrivacyAccessedAPICategoryDiskSpace": {"85F4.1", "E174.1", "7D9E.1", "B728.1"},
    "NSPrivacyAccessedAPICategoryActiveKeyboards": {"3EC4.1", "54BD.1"},
    "NSPrivacyAccessedAPICategoryUserDefaults": {"CA92.1", "1C8F.1", "C56D.1", "AC6B.1"},
}
PRIVACY_MANIFEST_NAME = "PrivacyInfo.xcprivacy"


class AuditError(Exception):
    """Input that cannot be audited (exit code 2)."""


def finding(fid, severity, title, detail, fix, location=None, masvs=None):
    f = {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}
    if location:
        f["location"] = location
    if masvs:
        f["masvs"] = masvs
    return f


def mask(value: str) -> str:
    return value[:4] + "..." if len(value) > 4 else "..."


def load_plist(data: bytes, label: str) -> dict:
    if b"<!ENTITY" in data[:4096]:
        raise AuditError(f"{label} declares XML entities; refusing to parse it.")
    try:
        obj = plistlib.loads(data)
    except Exception as exc:  # plistlib raises several types (InvalidFileException, ExpatError, ValueError)
        raise AuditError(f"{label} is not a valid plist: {exc}") from None
    if not isinstance(obj, dict):
        raise AuditError(f"{label} is a plist but not a dictionary")
    return obj


# ---------------------------------------------------------------- ATS

def audit_ats(plist: dict) -> List[Dict]:
    out = []
    ats = plist.get("NSAppTransportSecurity")
    if not isinstance(ats, dict):
        return out
    loc = "NSAppTransportSecurity"
    overrides = [k for k in ATS_OVERRIDES if k in ats]
    if ats.get("NSAllowsArbitraryLoads") is True:
        if overrides:
            out.append(finding("IOS-001", "low", "NSAllowsArbitraryLoads is on, but ignored on iOS 10+",
                               f"Because {', '.join(overrides)} is also present, iOS 10 and later ignore "
                               "NSAllowsArbitraryLoads; it only weakens ATS on iOS 9.",
                               "Remove NSAllowsArbitraryLoads to avoid confusion and App Review questions.", loc, "MASVS-NETWORK"))
        else:
            out.append(finding("IOS-001", "high", "App Transport Security is off for all connections",
                               "NSAllowsArbitraryLoads = true lets the app load any plain-HTTP or weak-TLS URL.",
                               "Remove it. Use NSExceptionDomains for the specific hosts that cannot do TLS 1.2+, "
                               "and expect App Review to ask for a justification.", loc, "MASVS-NETWORK"))
    if ats.get("NSAllowsArbitraryLoadsInWebContent") is True:
        out.append(finding("IOS-002", "medium", "ATS off for web views",
                           "NSAllowsArbitraryLoadsInWebContent = true lets WKWebView load plain-HTTP pages, which "
                           "an attacker on the network can rewrite (including any JavaScript bridge they reach).",
                           "Remove it if the web content is yours; load only HTTPS in web views.", loc, "MASVS-NETWORK"))
    if ats.get("NSAllowsArbitraryLoadsForMedia") is True:
        out.append(finding("IOS-003", "low", "ATS off for AVFoundation media",
                           "NSAllowsArbitraryLoadsForMedia = true allows media over plain HTTP.",
                           "Serve media over HTTPS and remove the key.", loc, "MASVS-NETWORK"))
    if ats.get("NSAllowsLocalNetworking") is True:
        out.append(finding("IOS-007", "info", "ATS allows unqualified local hosts",
                           "NSAllowsLocalNetworking = true allows HTTP to .local names and unqualified hosts. Normal for "
                           "apps that talk to devices on the LAN.",
                           "Keep only if the app needs local devices.", loc, "MASVS-NETWORK"))
    domains = ats.get("NSExceptionDomains")
    if isinstance(domains, dict):
        for domain, cfg in sorted(domains.items()):
            if not isinstance(cfg, dict):
                continue
            where = f"NSExceptionDomains/{domain}"
            sub = " and its subdomains" if cfg.get("NSIncludesSubdomains") is True else ""
            if cfg.get("NSExceptionAllowsInsecureHTTPLoads") is True or cfg.get("NSThirdPartyExceptionAllowsInsecureHTTPLoads") is True:
                out.append(finding("IOS-004", "medium", f"Plain HTTP allowed for {domain}",
                                   f"Traffic to {domain}{sub} can go over HTTP and be read or changed on the network.",
                                   f"Move {domain} to HTTPS and drop the exception.", where, "MASVS-NETWORK"))
            min_tls = cfg.get("NSExceptionMinimumTLSVersion") or cfg.get("NSThirdPartyExceptionMinimumTLSVersion")
            if isinstance(min_tls, str) and min_tls in OLD_TLS:
                out.append(finding("IOS-005", "medium", f"{domain} allows {min_tls}",
                                   "TLS 1.0 and 1.1 are deprecated (RFC 8996).",
                                   f"Upgrade {domain} to TLS 1.2+ and remove NSExceptionMinimumTLSVersion.", where, "MASVS-NETWORK"))
            if cfg.get("NSExceptionRequiresForwardSecrecy") is False or cfg.get("NSThirdPartyExceptionRequiresForwardSecrecy") is False:
                out.append(finding("IOS-006", "low", f"Forward secrecy not required for {domain}",
                                   "Recorded traffic can be decrypted later if the server's key leaks.",
                                   f"Enable ECDHE cipher suites on {domain} and remove the exception.", where, "MASVS-NETWORK"))
    return out


# ---------------------------------------------------------------- other Info.plist keys

def audit_info(plist: dict) -> List[Dict]:
    out = []
    schemes = []
    for url_type in plist.get("CFBundleURLTypes") or []:
        if isinstance(url_type, dict):
            schemes += [s for s in url_type.get("CFBundleURLSchemes") or [] if isinstance(s, str)]
    if schemes:
        out.append(finding("IOS-010", "low", f"Custom URL scheme(s): {', '.join(s + '://' for s in sorted(set(schemes)))}",
                           "Any app can register the same scheme, so links (and any code or token in them) can be "
                           "intercepted; parameters arrive from untrusted sources.",
                           "Use universal links for anything sensitive (OAuth uses ASWebAuthenticationSession with PKCE); "
                           "validate every parameter.", "CFBundleURLTypes", "MASVS-PLATFORM"))

    for key in sorted(k for k in plist if k.endswith("UsageDescription")):
        value = plist[key]
        if not isinstance(value, str) or PLACEHOLDER.match(value) or len(value.strip()) < 8:
            out.append(finding("IOS-020", "low", f"{key} is empty or a placeholder",
                               f"The permission prompt will show {value!r}. Users cannot tell why the app asks, and App "
                               "Review rejects vague purpose strings.",
                               "Write a specific sentence saying what the data is used for.", key, "MASVS-PRIVACY"))

    if plist.get("UIFileSharingEnabled") is True:
        both = plist.get("LSSupportsOpeningDocumentsInPlace") is True
        out.append(finding("IOS-021", "low", "App Documents folder is shared",
                           "UIFileSharingEnabled exposes the Documents directory in Finder" +
                           (" and the Files app (LSSupportsOpeningDocumentsInPlace is on too)" if both else "") +
                           ". Anything stored there (databases, exports, logs) is readable by whoever holds the unlocked device.",
                           "Keep sensitive files in Library/Application Support or the keychain, or turn the key off.",
                           "UIFileSharingEnabled", "MASVS-STORAGE"))

    queries = plist.get("LSApplicationQueriesSchemes") or []
    if isinstance(queries, list) and len(queries) > QUERY_SCHEME_LIMIT:
        out.append(finding("IOS-022", "low", f"LSApplicationQueriesSchemes lists {len(queries)} schemes",
                           "Apps linked on iOS 15+ can query at most 50; the rest silently fail. Long lists also look like "
                           "fingerprinting which other apps are installed.",
                           "Trim to the schemes the app needs.", "LSApplicationQueriesSchemes", "MASVS-PRIVACY"))

    out += audit_values(plist)
    return out


def walk(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk(v, f"{path}/{k}" if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk(v, f"{path}[{i}]")
    else:
        yield path, obj


def audit_values(plist: dict) -> List[Dict]:
    out = []
    for path, value in walk(plist):
        leaf = path.rsplit("/", 1)[-1]
        if isinstance(value, str):
            v = value.strip()
            hit = None
            for rx, sev, label in SECRET_PATTERNS:
                if rx.search(v):
                    hit = (sev, label)
                    break
            if hit is None and SECRET_KEY_NAME.search(leaf) and looks_secret(v):
                hit = ("medium", "secret-looking value")
            if hit:
                sev, label = hit
                note = (" Google API keys ship in apps by design; restrict it by bundle ID and API in the Cloud console."
                        if label == "Google API key" else " Anything in Info.plist is readable by anyone with the IPA.")
                out.append(finding("IOS-030", sev, f"Hard-coded {label} in {leaf}",
                                   f"Value {mask(v)} found in the plist.{note}",
                                   "Move secrets server-side; ship only public, scoped client IDs. Rotate any key "
                                   "that was released.", path, "MASVS-CRYPTO"))
        elif value is True and DEBUG_KEY_NAME.search(leaf) and not leaf.startswith("NS"):
            out.append(finding("IOS-031", "low", f"Debug flag {leaf} is on",
                               "A debug or staging switch is enabled in the shipped plist.",
                               "Set debug flags per build configuration so release builds never carry them.",
                               path, "MASVS-CODE"))
    return out


def looks_secret(v: str) -> bool:
    if len(v) < 16 or " " in v or v.startswith(("$(", "http://", "https://")):
        return False
    if re.search(r"(example|changeme|placeholder|your[_-]?)", v, re.I):
        return False
    classes = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]"))
    return classes >= 2


# ---------------------------------------------------------------- entitlements

def audit_entitlements(ent: dict) -> List[Dict]:
    out = []
    if ent.get("get-task-allow") is True:
        out.append(finding("IOS-040", "high", "get-task-allow is true (development signing)",
                           "Debuggers can attach to the app and read its memory, keys and tokens. App Store builds never "
                           "have this; seeing it means a development or ad-hoc debug build.",
                           "Ship with an App Store or Ad Hoc distribution profile (get-task-allow false).",
                           "get-task-allow", "MASVS-RESILIENCE"))
    if ent.get("aps-environment") == "development":
        out.append(finding("IOS-041", "low", "Push environment is development",
                           "aps-environment = development: a debug profile. Push from the production APNs server will "
                           "not reach this build.",
                           "Use a distribution profile (aps-environment production) for release.",
                           "aps-environment", "MASVS-CODE"))
    domains = ent.get("com.apple.developer.associated-domains") or []
    if isinstance(domains, list):
        dev = [d for d in domains if isinstance(d, str) and "mode=developer" in d]
        if dev:
            out.append(finding("IOS-042", "low", "Associated domains in developer mode",
                               f"{', '.join(dev)}: developer mode skips Apple's CDN and only works on devices with "
                               "developer mode on; not meant for release.",
                               "Remove ?mode=developer before release.", "com.apple.developer.associated-domains",
                               "MASVS-PLATFORM"))
    return out


# ---------------------------------------------------------------- privacy manifest (PrivacyInfo.xcprivacy)

def audit_privacy_manifest(pm: dict) -> List[Dict]:
    out = []
    loc = PRIVACY_MANIFEST_NAME
    tracking = pm.get("NSPrivacyTracking") is True
    domains = [d for d in pm.get("NSPrivacyTrackingDomains") or [] if isinstance(d, str) and d.strip()]
    if tracking and not domains:
        out.append(finding("IOS-050", "medium", "NSPrivacyTracking is true but no tracking domains are listed",
                           "iOS blocks requests to declared tracking domains until the user allows tracking (App "
                           "Tracking Transparency). With no domains listed, tracking traffic is not covered by that "
                           "block, and the declaration does not match what the app does.",
                           "List every domain that tracks in NSPrivacyTrackingDomains, or set NSPrivacyTracking false "
                           "if the app does not track.", loc + "/NSPrivacyTrackingDomains", "MASVS-PRIVACY"))
    elif domains and not tracking:
        out.append(finding("IOS-050", "medium", "Tracking domains listed but NSPrivacyTracking is not true",
                           f"{', '.join(sorted(domains)[:5])}: Apple reads NSPrivacyTrackingDomains only when "
                           "NSPrivacyTracking is true, so the app declares that it does not track while naming "
                           "tracking hosts.",
                           "Set NSPrivacyTracking true (and ask for ATT permission), or remove the domains if they "
                           "do not track.", loc + "/NSPrivacyTracking", "MASVS-PRIVACY"))

    collected = pm.get("NSPrivacyCollectedDataTypes")
    if isinstance(collected, list):
        for i, entry in enumerate(collected):
            if not isinstance(entry, dict):
                continue
            kind = entry.get("NSPrivacyCollectedDataType") or f"entry {i}"
            where = f"{loc}/NSPrivacyCollectedDataTypes[{i}]"
            if entry.get("NSPrivacyCollectedDataTypeTracking") is True and not tracking:
                out.append(finding("IOS-051", "medium", f"{kind} is used for tracking but NSPrivacyTracking is not true",
                                   "The collected data entry says the data is used to track the user, while the "
                                   "top-level flag says the app does not track. The privacy report and the App Store "
                                   "privacy label will contradict each other.",
                                   "Make NSPrivacyTracking true and list the tracking domains, or fix the entry.",
                                   where, "MASVS-PRIVACY"))
            missing = [k for k in ("NSPrivacyCollectedDataType", "NSPrivacyCollectedDataTypeLinked",
                                   "NSPrivacyCollectedDataTypeTracking", "NSPrivacyCollectedDataTypePurposes")
                       if k not in entry]
            if missing:
                out.append(finding("IOS-051", "low", f"Collected data entry {kind} is incomplete",
                                   f"Missing {', '.join(missing)}. Xcode cannot build a correct privacy report from it.",
                                   "Fill in the type, linked, tracking and purposes keys with Apple's listed values.",
                                   where, "MASVS-PRIVACY"))

    accessed = pm.get("NSPrivacyAccessedAPITypes")
    if isinstance(accessed, list):
        for i, entry in enumerate(accessed):
            if not isinstance(entry, dict):
                continue
            cat = entry.get("NSPrivacyAccessedAPIType")
            reasons = [r for r in entry.get("NSPrivacyAccessedAPITypeReasons") or [] if isinstance(r, str)]
            where = f"{loc}/NSPrivacyAccessedAPITypes[{i}]"
            if cat not in REQUIRED_REASONS:
                out.append(finding("IOS-052", "medium", f"Unknown required reason API category {cat!r}",
                                   "App Store Connect only accepts Apple's listed categories; a typo here means the "
                                   "API use counts as undeclared and the upload is rejected.",
                                   "Use one of: " + ", ".join(sorted(REQUIRED_REASONS)) + ".", where, "MASVS-PRIVACY"))
                continue
            short_cat = cat[len("NSPrivacyAccessedAPICategory"):]
            if not reasons:
                out.append(finding("IOS-052", "medium", f"{short_cat} API declared with no reason",
                                   "Required reason APIs need at least one approved reason code; App Store Connect "
                                   "rejects uploads without one.",
                                   "Add the reason code(s) that match how the app uses the API: "
                                   + ", ".join(sorted(REQUIRED_REASONS[cat])) + ".", where, "MASVS-PRIVACY"))
                continue
            wrong = [r for r in reasons if r not in REQUIRED_REASONS[cat]]
            if wrong:
                out.append(finding("IOS-052", "medium", f"{short_cat} API declares reason(s) that do not belong to it",
                                   f"{', '.join(wrong)} is not an approved reason for {short_cat}. The declaration is "
                                   "invalid and the API use counts as undeclared.",
                                   "Valid codes for this category: " + ", ".join(sorted(REQUIRED_REASONS[cat])) + ".",
                                   where, "MASVS-PRIVACY"))
    return out


def find_privacy_manifest(plist_path: Optional[str]) -> Optional[str]:
    if not plist_path or plist_path == "-":
        return None
    candidate = os.path.join(os.path.dirname(os.path.abspath(plist_path)), PRIVACY_MANIFEST_NAME)
    return candidate if os.path.isfile(candidate) else None


def in_app_bundle(plist_path: Optional[str]) -> bool:
    if not plist_path or plist_path == "-":
        return False
    return os.path.dirname(os.path.abspath(plist_path)).endswith(".app")


def audit(plist: dict, entitlements: Optional[dict] = None, privacy_manifest: Optional[dict] = None,
          bundle_without_manifest: bool = False) -> Dict[str, object]:
    out = audit_ats(plist) + audit_info(plist)
    if entitlements is not None:
        out += audit_entitlements(entitlements)
    if privacy_manifest is not None:
        out += audit_privacy_manifest(privacy_manifest)
    elif bundle_without_manifest:
        out.append(finding("IOS-053", "info", "No PrivacyInfo.xcprivacy in the app bundle",
                           "Apps that use required reason APIs (UserDefaults, file timestamps, disk space, boot time, "
                           "active keyboards) need a privacy manifest; App Store Connect has rejected uploads without "
                           "one since May 1, 2024. Most apps touch UserDefaults through their own code or an SDK.",
                           "Add PrivacyInfo.xcprivacy to the app target (Xcode: File > New File > App Privacy) and "
                           "declare the APIs, data types and tracking domains.", PRIVACY_MANIFEST_NAME, "MASVS-PRIVACY"))
    out.sort(key=lambda f: -SEVERITY_ORDER.index(f["severity"]))
    return {
        "bundle_id": plist.get("CFBundleIdentifier"),
        "minimum_os": plist.get("MinimumOSVersion") or plist.get("LSMinimumSystemVersion"),
        "entitlements_checked": entitlements is not None,
        "privacy_manifest_checked": privacy_manifest is not None,
        "findings": out,
    }


def render_text(res, path) -> str:
    lines = [f"iOS plist audit: {path}",
             f"bundle {res['bundle_id'] or '?'}, minimum OS {res['minimum_os'] or '?'}, "
             f"entitlements {'checked' if res['entitlements_checked'] else 'not given'}, "
             f"privacy manifest {'checked' if res['privacy_manifest_checked'] else 'not given'}, "
             f"{len(res['findings'])} finding(s)", ""]
    if not res["findings"]:
        lines.append("No issues found.")
    for f in res["findings"]:
        loc = f"  ({f['location']})" if f.get("location") else ""
        lines.append(f"[{f['severity'].upper():8}] {f['id']}  {f['title']}{loc}")
        lines.append(f"           {f['detail']}")
        lines.append(f"           fix: {f['fix']}")
    return "\n".join(lines)


def read_bytes(path: str) -> bytes:
    if path == "-":
        stream = sys.stdin
        return stream.buffer.read() if hasattr(stream, "buffer") else stream.read().encode()
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as exc:
        raise AuditError(f"cannot read {path}: {exc.strerror}") from None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Static audit of an iOS Info.plist and entitlements.")
    ap.add_argument("plist", help="Info.plist (XML or binary), or - for stdin")
    ap.add_argument("--entitlements", help="entitlements plist (.entitlements or `codesign -d --entitlements :-` output)")
    ap.add_argument("--privacy-manifest",
                    help="PrivacyInfo.xcprivacy to audit (default: the one next to the Info.plist, if any)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)
    try:
        plist = load_plist(read_bytes(args.plist), args.plist)
        ent = load_plist(read_bytes(args.entitlements), args.entitlements) if args.entitlements else None
        pm_path = args.privacy_manifest or find_privacy_manifest(args.plist)
        pm = load_plist(read_bytes(pm_path), pm_path) if pm_path else None
    except AuditError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    res = audit(plist, ent, pm, bundle_without_manifest=pm is None and in_app_bundle(args.plist))
    if args.json:
        print(json.dumps({"plist": args.plist, **res}, indent=2, default=str))
    else:
        print(render_text(res, args.plist))
    if args.fail_on != "never":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= threshold for f in res["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
