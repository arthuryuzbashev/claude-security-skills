#!/usr/bin/env python3
"""Static audit of a decoded AndroidManifest.xml (plus its network security config).

Works on a source manifest (src/main/AndroidManifest.xml) or apktool output. Binary AXML straight
out of an APK is refused: decode it first (apktool d app.apk, or aapt2 dump xmltree).

Usage:
  android_manifest_audit.py app/src/main/AndroidManifest.xml
  android_manifest_audit.py decoded/AndroidManifest.xml --target-sdk 36 --json
  android_manifest_audit.py wear/AndroidManifest.xml --required-target-sdk 35
  android_manifest_audit.py AndroidManifest.xml --nsc res/xml/network_security_config.xml
  cat AndroidManifest.xml | android_manifest_audit.py -
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
A = "{http://schemas.android.com/apk/res/android}"

# Runtime ("dangerous") permissions: the user is asked at runtime.
DANGEROUS = {
    "READ_CALENDAR", "WRITE_CALENDAR", "CAMERA", "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "RECORD_AUDIO",
    "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE", "ANSWER_PHONE_CALLS", "READ_CALL_LOG",
    "WRITE_CALL_LOG", "ADD_VOICEMAIL", "USE_SIP", "PROCESS_OUTGOING_CALLS", "BODY_SENSORS",
    "BODY_SENSORS_BACKGROUND", "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_WAP_PUSH", "RECEIVE_MMS",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO",
    "READ_MEDIA_AUDIO", "READ_MEDIA_VISUAL_USER_SELECTED", "ACTIVITY_RECOGNITION", "BLUETOOTH_SCAN",
    "BLUETOOTH_CONNECT", "BLUETOOTH_ADVERTISE", "NEARBY_WIFI_DEVICES", "UWB_RANGING", "POST_NOTIFICATIONS",
    "ACCEPT_HANDOVER",
}
# Special / sensitive permissions that need a settings screen or draw Play policy review.
SPECIAL = {
    "SYSTEM_ALERT_WINDOW": "can draw over other apps (overlay and tapjacking risk)",
    "WRITE_SETTINGS": "can change system settings",
    "MANAGE_EXTERNAL_STORAGE": "all-files access to shared storage (Play policy restricted)",
    "REQUEST_INSTALL_PACKAGES": "can prompt to install other APKs (Play policy restricted)",
    "PACKAGE_USAGE_STATS": "can read which apps the user runs",
    "QUERY_ALL_PACKAGES": "sees every installed app (Play policy restricted)",
    "SCHEDULE_EXACT_ALARM": "exact alarms (Play policy restricted for most apps)",
    "READ_LOGS": "system log access (not granted to normal apps; a leftover from debugging)",
    "BIND_ACCESSIBILITY_SERVICE": "accessibility service can read and drive the whole UI",
    "BIND_DEVICE_ADMIN": "device admin can lock or wipe the device",
}
# Google Play target API level rules (verified 2026-11-19, support.google.com/googleplay/android-developer/answer/11926878):
# since 2026-08-31 new apps and updates (phone, tablet) must target API 36; existing apps below API 35 stop being
# discoverable to users on newer Android versions. Wear OS and Automotive need 35, Android TV 34.
PLAY_REQUIRED_TARGET = 36
PLAY_FLOOR_TARGET = 35

COMPONENTS = {
    # tag: (id, severity when exported without permission)
    "provider": ("AND-020", "high"),
    "service": ("AND-021", "medium"),
    "receiver": ("AND-022", "medium"),
    "activity": ("AND-023", "low"),
    "activity-alias": ("AND-023", "low"),
}


class AuditError(Exception):
    """Input that cannot be audited (exit code 2)."""


def finding(fid, severity, title, detail, fix, location=None, masvs=None):
    f = {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}
    if location:
        f["location"] = location
    if masvs:
        f["masvs"] = masvs
    return f


def attr(el, name: str) -> Optional[str]:
    return el.get(A + name)


def is_true(value: Optional[str]) -> bool:
    return value is not None and value.strip().lower() == "true"


def is_false(value: Optional[str]) -> bool:
    return value is not None and value.strip().lower() == "false"


def short(name: Optional[str]) -> str:
    return (name or "").rsplit(".", 1)[-1]


def parse_xml(data: bytes, label: str) -> ET.Element:
    if data[:4] in (b"\x03\x00\x08\x00", b"\x00\x00\x08\x00"):
        raise AuditError(f"{label} is binary AXML. Decode it first: apktool d app.apk (or aapt2 dump xmltree).")
    head = data[:4096].decode("utf-8", errors="replace")
    if "<!DOCTYPE" in head or "<!ENTITY" in head:
        raise AuditError(f"{label} contains a DTD; refusing to parse it (manifests never need one).")
    try:
        return ET.fromstring(data)
    except ET.ParseError as exc:
        raise AuditError(f"{label} is not valid XML: {exc}") from None


# ---------------------------------------------------------------- network security config

def audit_nsc(root: ET.Element, target_sdk: Optional[int] = None) -> List[Dict]:
    out = []
    base = root.find("base-config")
    base_attr = base.get("cleartextTrafficPermitted") if base is not None else None
    if base_attr is None and target_sdk is not None and target_sdk < 28:
        out.append(finding("AND-011", "medium", f"Cleartext allowed by default (targetSdk {target_sdk})",
                           "The network security config does not set cleartextTrafficPermitted in base-config, and "
                           "before targetSdk 28 the default is to allow plain HTTP.",
                           "Add <base-config cleartextTrafficPermitted=\"false\"/> or raise targetSdk.",
                           "base-config", "MASVS-NETWORK"))
    if base is not None and is_true(base.get("cleartextTrafficPermitted")):
        out.append(finding("AND-012", "high", "Network security config allows cleartext for all traffic",
                           "base-config cleartextTrafficPermitted=\"true\" lets every connection use plain HTTP, "
                           "readable and changeable by anyone on the network path.",
                           "Set cleartextTrafficPermitted=\"false\" in base-config; allow cleartext only for named "
                           "domains that cannot do TLS.", "base-config", "MASVS-NETWORK"))
    for dc in root.iter("domain-config"):
        domains = [d.text.strip() for d in dc.findall("domain") if d.text]
        where = "domain-config " + ", ".join(domains) if domains else "domain-config"
        if is_true(dc.get("cleartextTrafficPermitted")):
            out.append(finding("AND-013", "medium", "Cleartext HTTP allowed for some domains",
                               f"Plain HTTP is allowed for: {', '.join(domains) or '(no domain listed)'}.",
                               "Move these hosts to HTTPS and drop the cleartext exception.", where, "MASVS-NETWORK"))
    # user-installed CAs outside debug-overrides
    for section in [base] + list(root.iter("domain-config")):
        if section is None:
            continue
        for cert in section.findall("trust-anchors/certificates"):
            if (cert.get("src") or "").strip() == "user":
                name = "base-config" if section is base else "domain-config"
                out.append(finding("AND-014", "high", "App trusts user-installed CA certificates",
                                   f"{name} trusts src=\"user\". Any CA the user (or malware, or an MDM) installs can "
                                   "intercept this app's TLS traffic.",
                                   "Remove <certificates src=\"user\"/> from release config; put it under "
                                   "<debug-overrides> if testers need a proxy.", name, "MASVS-NETWORK"))
    if root.find(".//pin-set") is None:
        out.append(finding("AND-015", "info", "No certificate pinning configured",
                           "No <pin-set> in the network security config. Fine for most apps; banking, health and "
                           "high-risk apps usually pin their own API hosts.",
                           "Consider a <pin-set> with a backup pin and an expiration date for your own API domains.",
                           None, "MASVS-NETWORK"))
    return out


def find_nsc(manifest_path: Optional[str], ref: Optional[str]) -> Optional[str]:
    if not manifest_path or not ref or not ref.startswith("@xml/"):
        return None
    base = os.path.dirname(os.path.abspath(manifest_path))
    candidate = os.path.join(base, "res", "xml", ref[len("@xml/"):] + ".xml")
    return candidate if os.path.isfile(candidate) else None


# ---------------------------------------------------------------- manifest

def int_or_none(value) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def intent_info(comp: ET.Element) -> Tuple[bool, bool, List[ET.Element]]:
    """(has intent-filter, is launcher, filters)."""
    filters = comp.findall("intent-filter")
    launcher = False
    for f in filters:
        actions = {attr(a, "name") for a in f.findall("action")}
        cats = {attr(c, "name") for c in f.findall("category")}
        if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in cats:
            launcher = True
    return bool(filters), launcher, filters


def is_browsable(f: ET.Element) -> bool:
    actions = {attr(a, "name") for a in f.findall("action")}
    cats = {attr(c, "name") for c in f.findall("category")}
    return "android.intent.action.VIEW" in actions and "android.intent.category.BROWSABLE" in cats


def audit_components(app: ET.Element, target_sdk: Optional[int], min_sdk: Optional[int],
                     weak_perms: Dict[str, str]) -> List[Dict]:
    out = []
    for tag, (fid, sev) in COMPONENTS.items():
        for comp in app.findall(tag):
            name = attr(comp, "name") or "(unnamed)"
            exported_attr = attr(comp, "exported")
            has_filter, launcher, _ = intent_info(comp)
            if exported_attr is None and has_filter and tag != "provider" and target_sdk is not None and target_sdk >= 31:
                out.append(finding("AND-024", "low", f"{tag} {short(name)} has an intent-filter but no android:exported",
                                   "From targetSdk 31 (Android 12) this is an install error; the attribute must be explicit.",
                                   "Add android:exported=\"false\" (or \"true\" if other apps must start it, with a permission).",
                                   name, "MASVS-PLATFORM"))
                continue
            if exported_attr is not None:
                exported, how = is_true(exported_attr), "exported"
            elif tag == "provider":
                old = (target_sdk is not None and target_sdk <= 16) or (min_sdk is not None and min_sdk <= 16)
                exported, how = old, "exported by default (SDK 16 or lower)"
            else:
                exported, how = has_filter, "exported by default (has an intent-filter)"
            if not exported or launcher:
                continue
            if tag.startswith("activity") and has_filter and all(is_browsable(f) for f in comp.findall("intent-filter")):
                continue  # deep link handlers must be exported; audit_deep_links covers them
            perm = attr(comp, "permission")
            if tag == "provider":
                perm = perm or (attr(comp, "readPermission") and attr(comp, "writePermission") and "read/write")
                if not perm and (attr(comp, "readPermission") or attr(comp, "writePermission")):
                    out.append(finding("AND-020", "medium", f"Provider {short(name)} protects only reads or only writes",
                                       "One of readPermission / writePermission is missing, so the other direction is open to every app.",
                                       "Set both readPermission and writePermission (signature-level), or android:permission.",
                                       name, "MASVS-PLATFORM"))
                    continue
            if perm:
                if perm in weak_perms:
                    out.append(finding("AND-032", "medium", f"{tag} {short(name)} is guarded by a {weak_perms[perm]} permission",
                                       f"{perm} has protectionLevel {weak_perms[perm]}, so any app can request it and get in.",
                                       "Use protectionLevel=\"signature\" for permissions that guard your own components.",
                                       name, "MASVS-PLATFORM"))
                continue
            what = {"provider": "Any app can query or change its data",
                    "service": "Any app can bind to or start it",
                    "receiver": "Any app can send it broadcasts",
                    "activity": "Any app can launch it, with any extras",
                    "activity-alias": "Any app can launch it, with any extras"}[tag]
            out.append(finding(fid, sev, f"{tag} {short(name)} is {how} with no permission",
                               f"{what}. Inputs from intents must be treated as untrusted.",
                               "Set android:exported=\"false\" if only this app uses it; otherwise add "
                               "android:permission with a signature-level permission and validate every extra.",
                               name, "MASVS-PLATFORM"))
    return out


def audit_deep_links(app: ET.Element) -> List[Dict]:
    out = []
    for comp in list(app.findall("activity")) + list(app.findall("activity-alias")):
        name = attr(comp, "name") or "(unnamed)"
        for f in comp.findall("intent-filter"):
            if not is_browsable(f):
                continue
            schemes = sorted({attr(d, "scheme") for d in f.findall("data") if attr(d, "scheme")})
            hosts = sorted({attr(d, "host") for d in f.findall("data") if attr(d, "host")})
            custom = [s for s in schemes if s not in ("http", "https")]
            if custom:
                out.append(finding("AND-040", "low", f"Custom URL scheme deep link: {', '.join(s + '://' for s in custom)}",
                                   "Any app can claim the same scheme, so links (and any token in them) can be "
                                   "intercepted. Parameters arrive from untrusted pages.",
                                   "Prefer verified https App Links; never put auth codes or tokens in custom-scheme links; "
                                   "validate every parameter.", name, "MASVS-PLATFORM"))
            web = [s for s in schemes if s in ("http", "https")]
            if web and not is_true(attr(f, "autoVerify")):
                out.append(finding("AND-041", "low", f"Web deep link without autoVerify ({', '.join(hosts) or 'any host'})",
                                   "Without android:autoVerify=\"true\" and a Digital Asset Links file, the link is not a "
                                   "verified App Link and other apps can offer to handle it.",
                                   "Add android:autoVerify=\"true\" and host /.well-known/assetlinks.json on each domain.",
                                   name, "MASVS-PLATFORM"))
            if "http" in schemes:
                out.append(finding("AND-042", "low", "Deep link accepts plain http://",
                                   "Links can be opened from cleartext pages that an attacker on the network can rewrite.",
                                   "Accept https only.", name, "MASVS-NETWORK"))
    return out


def audit_permissions(root: ET.Element) -> Tuple[List[Dict], Dict[str, str]]:
    out = []
    used = []
    for tag in ("uses-permission", "uses-permission-sdk-23"):
        used += [attr(p, "name") or "" for p in root.findall(tag)]
    dangerous = sorted({p.rsplit(".", 1)[-1] for p in used
                        if p.startswith("android.permission.") and p.rsplit(".", 1)[-1] in DANGEROUS})
    if dangerous:
        out.append(finding("AND-030", "info", f"{len(dangerous)} runtime (dangerous) permission(s) requested",
                           ", ".join(dangerous) + ". Each needs a clear user-facing reason and should be asked in context.",
                           "Remove any the app does not need; ask at the moment of use; prefer photo picker / coarse "
                           "location where possible.", None, "MASVS-PRIVACY"))
    for p in sorted(set(used)):
        short_name = p.rsplit(".", 1)[-1]
        if p.startswith("android.permission.") and short_name in SPECIAL:
            out.append(finding("AND-031", "low", f"Sensitive permission {short_name}",
                               f"{short_name}: {SPECIAL[short_name]}.",
                               "Keep it only if a core feature needs it, and document why for Play review.",
                               p, "MASVS-PRIVACY"))
    weak = {}
    for perm in root.findall("permission"):
        level = (attr(perm, "protectionLevel") or "normal").strip()
        name = attr(perm, "name") or "(unnamed)"
        base_level = level.split("|")[0]
        if base_level in ("normal", "dangerous"):
            weak[name] = base_level
            out.append(finding("AND-032", "low", f"Custom permission {short(name)} has protectionLevel {base_level}",
                               "Any installed app can request it" + (" (the user only sees a prompt)" if base_level == "dangerous" else "")
                               + ", so it does not keep other apps out.",
                               "Use protectionLevel=\"signature\" for permissions shared only between your own apps.",
                               name, "MASVS-PLATFORM"))
    return out, weak


def audit_target_sdk(target_sdk: Optional[int], required: int = PLAY_REQUIRED_TARGET) -> List[Dict]:
    if target_sdk is None or target_sdk >= required:
        return []
    floor = min(PLAY_FLOOR_TARGET, required - 1)
    if target_sdk < floor:
        return [finding("AND-051", "medium", f"targetSdk {target_sdk} is below Google Play's floor (API {floor})",
                        f"Google Play rejects new apps and updates below API {required}, and existing apps below API "
                        f"{floor} are hidden from users on newer Android versions. Old targets also keep legacy, "
                        "weaker platform defaults (implicit exports, cleartext, storage and intent rules).",
                        f"Raise targetSdkVersion to {required} and retest the behavior changes of each skipped level. "
                        "Wear OS and Automotive need 35, Android TV 34; apps outside Play can judge this as hygiene.",
                        "uses-sdk", "MASVS-CODE")]
    return [finding("AND-051", "low", f"targetSdk {target_sdk}: new apps and updates need API {required} on Google Play",
                    f"Since 2026-08-31 Google Play only accepts new apps and updates that target API {required}. The "
                    "current build stays listed, but the next release must raise it.",
                    f"Raise targetSdkVersion to {required} before the next release.", "uses-sdk", "MASVS-CODE")]


def audit_tasks(root: ET.Element, app: ET.Element, min_sdk: Optional[int]) -> List[Dict]:
    out = []
    old = min_sdk is None or min_sdk < 30
    where = []
    if is_true(attr(app, "allowTaskReparenting")):
        where.append("application")
    for tag in ("activity", "activity-alias"):
        for comp in app.findall(tag):
            if is_true(attr(comp, "allowTaskReparenting")):
                where.append(attr(comp, "name") or "(unnamed)")
    if where:
        out.append(finding("AND-052", "medium" if old else "low",
                           "allowTaskReparenting=\"true\" (task hijacking surface)",
                           "Activities can move into another task with the same affinity. This is the mechanism behind "
                           "task hijacking (StrandHogg): another app can put its own screen on top of yours and phish "
                           "for credentials." + (" Android 10 and lower (minSdk below 30) lack the OS fixes." if old else ""),
                           "Remove allowTaskReparenting unless a feature needs it; raise minSdk to 30 where possible.",
                           ", ".join(where), "MASVS-PLATFORM"))
    shared = attr(root, "sharedUserId")
    if shared and attr(root, "sharedUserMaxSdkVersion") is None:
        out.append(finding("AND-053", "low", f"sharedUserId {shared} (deprecated)",
                           "Apps signed with the same key share one Linux user ID, so they share private files and "
                           "permissions: a bug in one app exposes the other. Deprecated since API 29.",
                           "Move shared data to a signature-protected provider or service, then set "
                           "android:sharedUserMaxSdkVersion=\"32\" so new installs (Android 13+) drop the shared UID.",
                           "manifest", "MASVS-PLATFORM"))
    return out


def audit_manifest(root: ET.Element, nsc_root: Optional[ET.Element] = None, target_sdk: Optional[int] = None,
                   min_sdk: Optional[int] = None, required_target: int = PLAY_REQUIRED_TARGET) -> Dict[str, object]:
    if root.tag != "manifest":
        raise AuditError("root element is not <manifest>; is this an AndroidManifest.xml?")
    sdk = root.find("uses-sdk")
    if sdk is not None:
        target_sdk = target_sdk if target_sdk is not None else int_or_none(attr(sdk, "targetSdkVersion"))
        min_sdk = min_sdk if min_sdk is not None else int_or_none(attr(sdk, "minSdkVersion"))
    app = root.find("application")
    if app is None:
        app = ET.Element("application")
    out = []

    debuggable = is_true(attr(app, "debuggable"))
    if debuggable:
        out.append(finding("AND-001", "high", "android:debuggable=\"true\"",
                           "Anyone with USB access can attach a debugger, run code as the app (run-as) and read its private files.",
                           "Remove the attribute; the build system sets it for debug builds only.",
                           "application", "MASVS-RESILIENCE"))
    if is_true(attr(app, "testOnly")):
        out.append(finding("AND-004", "medium", "android:testOnly=\"true\"",
                           "A test-only build is in a release manifest. It installs only via adb and signals a non-release build.",
                           "Remove android:testOnly from release builds.", "application", "MASVS-CODE"))

    backup = attr(app, "allowBackup")
    rules = attr(app, "fullBackupContent") or attr(app, "dataExtractionRules")
    if is_true(backup) and not rules:
        out.append(finding("AND-002", "medium", "android:allowBackup=\"true\" with no backup rules",
                           "App data (tokens, databases, shared prefs) goes into cloud backups and device-to-device transfers.",
                           "Set allowBackup=\"false\", or add dataExtractionRules (Android 12+) and fullBackupContent "
                           "that exclude secrets.", "application", "MASVS-STORAGE"))
    elif backup is None and not rules:
        out.append(finding("AND-003", "low", "android:allowBackup not set (defaults to true)",
                           "Without the attribute, backup is on and all app data is included.",
                           "Set allowBackup explicitly and add backup rules that exclude tokens and keys.",
                           "application", "MASVS-STORAGE"))

    nsc_ref = attr(app, "networkSecurityConfig")
    cleartext = attr(app, "usesCleartextTraffic")
    if nsc_root is not None:
        out += audit_nsc(nsc_root, target_sdk)
    elif nsc_ref:
        out.append(finding("AND-017", "info", f"Network security config {nsc_ref} not found",
                           "The manifest references it but the file was not next to the manifest (res/xml/).",
                           "Pass it with --nsc to include it in the audit.", nsc_ref, "MASVS-NETWORK"))
    else:
        if is_true(cleartext):
            out.append(finding("AND-010", "high", "android:usesCleartextTraffic=\"true\"",
                               "Plain HTTP is allowed to every host, readable and changeable on the network path.",
                               "Set it to false; use a network security config to allow cleartext for specific hosts only.",
                               "application", "MASVS-NETWORK"))
        elif cleartext is None and target_sdk is not None and target_sdk < 28:
            out.append(finding("AND-011", "medium", f"Cleartext allowed by default (targetSdk {target_sdk})",
                               "Before targetSdk 28 cleartext HTTP is allowed unless turned off.",
                               "Set android:usesCleartextTraffic=\"false\" or raise targetSdk.",
                               "application", "MASVS-NETWORK"))
    if min_sdk is not None and min_sdk < 24:
        out.append(finding("AND-016", "low", f"minSdk {min_sdk}: user CAs trusted on Android 6 and lower",
                           "Android only reads network security configs from 7.0 (API 24); on older versions every app "
                           "trusts user-installed CAs.",
                           "Raise minSdk to 24, or accept the risk on those devices.", "uses-sdk", "MASVS-NETWORK"))

    perm_findings, weak = audit_permissions(root)
    out += perm_findings
    out += audit_components(app, target_sdk, min_sdk, weak)
    out += audit_deep_links(app)
    out += audit_target_sdk(target_sdk, required_target)
    out += audit_tasks(root, app, min_sdk)
    if target_sdk is None:
        out.append(finding("AND-050", "info", "targetSdk unknown",
                           "No uses-sdk targetSdkVersion in the manifest (Gradle sets it). Defaults that depend on it "
                           "(cleartext, exported) were not judged.",
                           "Re-run with --target-sdk N (and --min-sdk N) from build.gradle.", None))

    out.sort(key=lambda f: -SEVERITY_ORDER.index(f["severity"]))
    return {"package": root.get("package"), "target_sdk": target_sdk, "min_sdk": min_sdk,
            "network_security_config": nsc_ref, "findings": out}


def audit_file(path: str, nsc_path: Optional[str] = None, target_sdk: Optional[int] = None,
               min_sdk: Optional[int] = None, data: Optional[bytes] = None,
               required_target: int = PLAY_REQUIRED_TARGET) -> Dict[str, object]:
    if data is None:
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            raise AuditError(f"cannot read {path}: {exc.strerror}") from None
    root = parse_xml(data, path)
    app = root.find("application")
    ref = attr(app, "networkSecurityConfig") if app is not None else None
    nsc_root = None
    if nsc_path:
        try:
            with open(nsc_path, "rb") as fh:
                nsc_root = parse_xml(fh.read(), nsc_path)
        except OSError:
            raise AuditError(f"cannot read {nsc_path}") from None
    else:
        auto = find_nsc(path if path != "-" else None, ref)
        if auto:
            with open(auto, "rb") as fh:
                nsc_root = parse_xml(fh.read(), auto)
    res = audit_manifest(root, nsc_root, target_sdk, min_sdk, required_target)
    res["manifest"] = path
    return res


def render_text(res) -> str:
    lines = [f"Android manifest audit: {res['manifest']}",
             f"package {res['package'] or '?'}, targetSdk {res['target_sdk'] or '?'}, minSdk {res['min_sdk'] or '?'}, "
             f"{len(res['findings'])} finding(s)", ""]
    if not res["findings"]:
        lines.append("No issues found.")
    for f in res["findings"]:
        loc = f"  ({f['location']})" if f.get("location") else ""
        lines.append(f"[{f['severity'].upper():8}] {f['id']}  {f['title']}{loc}")
        lines.append(f"           {f['detail']}")
        lines.append(f"           fix: {f['fix']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Static audit of a decoded AndroidManifest.xml.")
    ap.add_argument("manifest", help="AndroidManifest.xml (text XML), or - for stdin")
    ap.add_argument("--nsc", help="network security config XML (default: res/xml/<name>.xml next to the manifest)")
    ap.add_argument("--target-sdk", type=int, help="targetSdkVersion when the manifest does not carry it (Gradle)")
    ap.add_argument("--min-sdk", type=int, help="minSdkVersion when the manifest does not carry it")
    ap.add_argument("--required-target-sdk", type=int, default=PLAY_REQUIRED_TARGET,
                    help=f"targetSdk Google Play requires for new releases (default: {PLAY_REQUIRED_TARGET}, "
                         "the phone and tablet rule since 2026-08-31; use 35 for Wear OS or Automotive, 34 for TV)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)
    try:
        data = sys.stdin.buffer.read() if args.manifest == "-" and hasattr(sys.stdin, "buffer") else (
            sys.stdin.read().encode() if args.manifest == "-" else None)
        res = audit_file(args.manifest, args.nsc, args.target_sdk, args.min_sdk, data, args.required_target_sdk)
    except AuditError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(res, indent=2) if args.json else render_text(res))
    if args.fail_on != "never":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= threshold for f in res["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
