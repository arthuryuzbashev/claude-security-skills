import json
import plistlib
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from _helpers import call_main, load_script, run_cli, skill_path

andr = load_script("mobile-appsec", "android_manifest_audit")
ios = load_script("mobile-appsec", "ios_plist_audit")
EX = skill_path("mobile-appsec", "examples")
NS = 'xmlns:android="http://schemas.android.com/apk/res/android"'


def ids(findings):
    return {f["id"] for f in findings}


def manifest(app_attrs="", body="", sdk='<uses-sdk android:minSdkVersion="26" android:targetSdkVersion="36"/>', extra="",
             root_attrs=""):
    xml = (f'<manifest {NS} package="test.example.app" {root_attrs}>{sdk}{extra}'
           f'<application android:allowBackup="false" {app_attrs}>{body}</application></manifest>')
    return ET.fromstring(xml)


def run_android(**kw):
    nsc = kw.pop("nsc", None)
    target = kw.pop("target_sdk", None)
    nsc_root = ET.fromstring(nsc) if nsc else None
    return andr.audit_manifest(manifest(**kw), nsc_root, target)["findings"]


class AndroidAppFlagTests(unittest.TestCase):
    def test_clean_manifest(self):
        self.assertEqual(run_android(), [])

    def test_debuggable(self):
        found = run_android(app_attrs='android:debuggable="true"')
        self.assertIn("AND-001", ids(found))
        self.assertEqual(found[0]["severity"], "high")
        self.assertNotIn("AND-001", ids(run_android(app_attrs='android:debuggable="false"')))

    def test_test_only(self):
        self.assertIn("AND-004", ids(run_android(app_attrs='android:testOnly="true"')))

    def test_backup(self):
        root = ET.fromstring(f'<manifest {NS}><uses-sdk android:targetSdkVersion="34"/><application/></manifest>')
        self.assertIn("AND-003", ids(andr.audit_manifest(root)["findings"]))
        root = ET.fromstring(f'<manifest {NS}><uses-sdk android:targetSdkVersion="34"/>'
                             '<application android:allowBackup="true"/></manifest>')
        self.assertIn("AND-002", ids(andr.audit_manifest(root)["findings"]))
        root = ET.fromstring(f'<manifest {NS}><uses-sdk android:targetSdkVersion="34"/>'
                             '<application android:allowBackup="true" android:dataExtractionRules="@xml/r"/></manifest>')
        self.assertFalse({"AND-002", "AND-003"} & ids(andr.audit_manifest(root)["findings"]))

    def test_cleartext_explicit_and_default(self):
        self.assertIn("AND-010", ids(run_android(app_attrs='android:usesCleartextTraffic="true"')))
        old = '<uses-sdk android:minSdkVersion="26" android:targetSdkVersion="27"/>'
        self.assertIn("AND-011", ids(run_android(sdk=old)))
        self.assertNotIn("AND-011", ids(run_android(sdk=old, app_attrs='android:usesCleartextTraffic="false"')))

    def test_min_sdk_user_ca(self):
        low = '<uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34"/>'
        self.assertIn("AND-016", ids(run_android(sdk=low)))

    def test_unknown_target_sdk(self):
        self.assertIn("AND-050", ids(run_android(sdk="")))
        self.assertNotIn("AND-050", ids(run_android(sdk="", target_sdk=34)))
        self.assertNotIn("AND-051", ids(run_android(sdk="")))

    def test_play_target_sdk(self):
        def sev(target):
            sdk = f'<uses-sdk android:minSdkVersion="30" android:targetSdkVersion="{target}"/>'
            return {f["id"]: f["severity"] for f in run_android(sdk=sdk)}.get("AND-051")
        self.assertEqual(sev(34), "medium")
        self.assertEqual(sev(35), "low")
        self.assertIsNone(sev(36))
        self.assertIsNone(sev(37))
        # Wear OS / Automotive rule: 35 is enough
        sdk = '<uses-sdk android:minSdkVersion="30" android:targetSdkVersion="35"/>'
        res = andr.audit_manifest(manifest(sdk=sdk), required_target=35)
        self.assertNotIn("AND-051", ids(res["findings"]))
        # --target-sdk from Gradle feeds the same check
        self.assertIn("AND-051", ids(run_android(sdk="", target_sdk=34)))

    def test_task_reparenting(self):
        found = run_android(app_attrs='android:allowTaskReparenting="true"')
        self.assertEqual([(f["id"], f["severity"]) for f in found], [("AND-052", "medium")])
        body = '<activity android:name=".Login" android:allowTaskReparenting="true"/>'
        found = run_android(body=body, sdk='<uses-sdk android:minSdkVersion="30" android:targetSdkVersion="36"/>')
        self.assertEqual([(f["id"], f["severity"], f["location"]) for f in found], [("AND-052", "low", ".Login")])
        self.assertEqual(run_android(app_attrs='android:allowTaskReparenting="false"'), [])

    def test_shared_user_id(self):
        found = run_android(root_attrs='android:sharedUserId="test.example.shared"')
        self.assertEqual(ids(found), {"AND-053"})
        migrated = 'android:sharedUserId="test.example.shared" android:sharedUserMaxSdkVersion="32"'
        self.assertEqual(run_android(root_attrs=migrated), [])


class AndroidNscTests(unittest.TestCase):
    def test_weak_config(self):
        nsc = ('<network-security-config><base-config cleartextTrafficPermitted="true"><trust-anchors>'
               '<certificates src="system"/><certificates src="user"/></trust-anchors></base-config>'
               '<domain-config cleartextTrafficPermitted="true"><domain>old.example.test</domain></domain-config>'
               '</network-security-config>')
        found = andr.audit_nsc(ET.fromstring(nsc))
        self.assertEqual(ids(found), {"AND-012", "AND-013", "AND-014", "AND-015"})
        self.assertEqual([f for f in found if f["id"] == "AND-013"][0]["location"], "domain-config old.example.test")

    def test_debug_overrides_and_pins_ok(self):
        nsc = ('<network-security-config><base-config cleartextTrafficPermitted="false"/>'
               '<domain-config><domain>api.example.test</domain><pin-set><pin digest="SHA-256">AAAA</pin></pin-set>'
               '</domain-config><debug-overrides><trust-anchors><certificates src="user"/></trust-anchors>'
               '</debug-overrides></network-security-config>')
        self.assertEqual(andr.audit_nsc(ET.fromstring(nsc)), [])

    def test_nsc_default_cleartext_old_target(self):
        nsc = "<network-security-config><domain-config><domain>a.example.test</domain><pin-set/></domain-config></network-security-config>"
        self.assertIn("AND-011", ids(andr.audit_nsc(ET.fromstring(nsc), 27)))
        self.assertNotIn("AND-011", ids(andr.audit_nsc(ET.fromstring(nsc), 28)))

    def test_nsc_replaces_manifest_cleartext_flag(self):
        nsc = '<network-security-config><base-config cleartextTrafficPermitted="false"/><pin-set/></network-security-config>'
        found = run_android(app_attrs='android:usesCleartextTraffic="true" android:networkSecurityConfig="@xml/n"', nsc=nsc)
        self.assertNotIn("AND-010", ids(found))

    def test_missing_nsc_file(self):
        found = run_android(app_attrs='android:networkSecurityConfig="@xml/n"')
        self.assertIn("AND-017", ids(found))


class AndroidComponentTests(unittest.TestCase):
    def test_exported_without_permission(self):
        body = ('<provider android:name=".P" android:authorities="a" android:exported="true"/>'
                '<service android:name=".S" android:exported="true"/>'
                '<receiver android:name=".R" android:exported="true"/>'
                '<activity android:name=".A" android:exported="true"/>')
        found = run_android(body=body)
        sev = {f["id"]: f["severity"] for f in found}
        self.assertEqual(sev, {"AND-020": "high", "AND-021": "medium", "AND-022": "medium", "AND-023": "low"})

    def test_protected_or_private_components(self):
        body = ('<provider android:name=".P" android:authorities="a" android:exported="true" android:permission="x.SIG"/>'
                '<service android:name=".S" android:exported="false"/>'
                '<receiver android:name=".R"/>'
                '<activity android:name=".Main" android:exported="true"><intent-filter>'
                '<action android:name="android.intent.action.MAIN"/>'
                '<category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>')
        self.assertEqual(run_android(body=body), [])

    def test_implicit_export_before_31(self):
        body = '<receiver android:name=".R"><intent-filter><action android:name="x.Y"/></intent-filter></receiver>'
        sdk30 = '<uses-sdk android:minSdkVersion="26" android:targetSdkVersion="30"/>'
        found = run_android(body=body, sdk=sdk30)
        self.assertIn("AND-022", ids(found))
        self.assertIn("by default", [f for f in found if f["id"] == "AND-022"][0]["title"])
        found = run_android(body=body)  # targetSdk 36
        self.assertEqual(ids(found), {"AND-024"})

    def test_provider_default_export_by_sdk(self):
        body = '<provider android:name=".P" android:authorities="a"/>'
        self.assertNotIn("AND-020", ids(run_android(body=body)))
        old = '<uses-sdk android:minSdkVersion="16" android:targetSdkVersion="16"/>'
        self.assertIn("AND-020", ids(run_android(body=body, sdk=old)))

    def test_provider_half_protected(self):
        body = '<provider android:name=".P" android:authorities="a" android:exported="true" android:readPermission="x.R"/>'
        found = run_android(body=body)
        self.assertEqual([(f["id"], f["severity"]) for f in found], [("AND-020", "medium")])

    def test_weak_custom_permission(self):
        extra = '<permission android:name="test.example.app.SYNC" android:protectionLevel="normal"/>'
        body = '<service android:name=".S" android:exported="true" android:permission="test.example.app.SYNC"/>'
        found = run_android(extra=extra, body=body)
        self.assertEqual(sorted(f["severity"] for f in found if f["id"] == "AND-032"), ["low", "medium"])
        extra = '<permission android:name="test.example.app.SYNC" android:protectionLevel="signature"/>'
        self.assertEqual(run_android(extra=extra, body=body), [])


class AndroidPermissionAndLinkTests(unittest.TestCase):
    def test_permissions(self):
        extra = ('<uses-permission android:name="android.permission.CAMERA"/>'
                 '<uses-permission android:name="android.permission.INTERNET"/>'
                 '<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>')
        found = run_android(extra=extra)
        self.assertEqual(ids(found), {"AND-030", "AND-031"})
        self.assertIn("CAMERA", [f for f in found if f["id"] == "AND-030"][0]["detail"])
        only_internet = '<uses-permission android:name="android.permission.INTERNET"/>'
        self.assertEqual(run_android(extra=only_internet), [])

    def _link(self, data, verify=""):
        return (f'<activity android:name=".L" android:exported="true"><intent-filter {verify}>'
                '<action android:name="android.intent.action.VIEW"/>'
                '<category android:name="android.intent.category.DEFAULT"/>'
                f'<category android:name="android.intent.category.BROWSABLE"/>{data}</intent-filter></activity>')

    def test_custom_scheme(self):
        found = run_android(body=self._link('<data android:scheme="myapp"/>'))
        self.assertEqual(ids(found), {"AND-040"})

    def test_unverified_and_http_links(self):
        found = run_android(body=self._link('<data android:scheme="http"/><data android:scheme="https"/>'
                                            '<data android:host="www.example.test"/>'))
        self.assertEqual(ids(found), {"AND-041", "AND-042"})

    def test_verified_https_link_clean(self):
        found = run_android(body=self._link('<data android:scheme="https" android:host="www.example.test"/>',
                                            'android:autoVerify="true"'))
        self.assertEqual(found, [])


class AndroidCliTests(unittest.TestCase):
    def test_weak_example(self):
        code, out, _ = call_main(andr, [str(EX / "android_weak" / "AndroidManifest.xml"), "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(set(data), {"manifest", "package", "target_sdk", "min_sdk", "network_security_config", "findings"})
        self.assertTrue({"AND-001", "AND-012", "AND-014", "AND-020", "AND-040", "AND-051", "AND-052", "AND-053"}
                        <= ids(data["findings"]))
        for f in data["findings"]:
            self.assertTrue({"id", "severity", "title", "detail", "fix"} <= set(f))

    def test_hardened_example(self):
        code, out, _ = call_main(andr, [str(EX / "android_hardened" / "AndroidManifest.xml")])
        self.assertEqual(code, 0, out)
        self.assertIn("No issues found", out)

    def test_stdin_and_fail_on(self):
        xml = f'<manifest {NS}><uses-sdk android:targetSdkVersion="36"/><application android:allowBackup="false"/></manifest>'
        code, out, _ = call_main(andr, ["-", "--json"], stdin=xml)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["findings"], [])
        weak = xml.replace('android:allowBackup="false"', 'android:allowBackup="true"')
        self.assertEqual(call_main(andr, ["-", "--fail-on", "medium"], stdin=weak)[0], 1)
        self.assertEqual(call_main(andr, ["-"], stdin=weak)[0], 0)

    def test_bad_inputs(self):
        with tempfile.TemporaryDirectory() as d:
            axml = Path(d, "AndroidManifest.xml")
            axml.write_bytes(b"\x03\x00\x08\x00" + b"\x00" * 64)
            code, _, err = call_main(andr, [str(axml)])
            self.assertEqual(code, 2)
            self.assertIn("apktool", err)
            dtd = Path(d, "dtd.xml")
            dtd.write_text('<?xml version="1.0"?><!DOCTYPE m [<!ENTITY a "x">]><manifest/>')
            self.assertEqual(call_main(andr, [str(dtd)])[0], 2)
            notman = Path(d, "other.xml")
            notman.write_text("<resources/>")
            self.assertEqual(call_main(andr, [str(notman)])[0], 2)
        self.assertEqual(call_main(andr, ["/nonexistent/secskills.xml"])[0], 2)

    def test_required_target_flag(self):
        xml = f'<manifest {NS}><uses-sdk android:targetSdkVersion="35"/><application android:allowBackup="false"/></manifest>'
        code, out, _ = call_main(andr, ["-", "--json", "--fail-on", "low"], stdin=xml)
        self.assertEqual((code, ids(json.loads(out)["findings"])), (1, {"AND-051"}))
        code, out, _ = call_main(andr, ["-", "--json", "--fail-on", "low", "--required-target-sdk", "35"], stdin=xml)
        self.assertEqual((code, json.loads(out)["findings"]), (0, []))

    def test_help(self):
        proc = run_cli("mobile-appsec", "android_manifest_audit", "--help")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--target-sdk", proc.stdout)
        self.assertIn("--required-target-sdk", proc.stdout)


class IosAtsTests(unittest.TestCase):
    def test_arbitrary_loads(self):
        found = ios.audit_ats({"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}})
        self.assertEqual([(f["id"], f["severity"]) for f in found], [("IOS-001", "high")])

    def test_arbitrary_loads_ignored_with_override(self):
        found = ios.audit_ats({"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True,
                                                          "NSAllowsArbitraryLoadsInWebContent": True}})
        sev = {f["id"]: f["severity"] for f in found}
        self.assertEqual(sev, {"IOS-001": "low", "IOS-002": "medium"})

    def test_media_and_local(self):
        found = ios.audit_ats({"NSAppTransportSecurity": {"NSAllowsArbitraryLoadsForMedia": True,
                                                          "NSAllowsLocalNetworking": True}})
        self.assertEqual(ids(found), {"IOS-003", "IOS-007"})

    def test_exception_domains(self):
        ats = {"NSExceptionDomains": {"old.example.test": {
            "NSExceptionAllowsInsecureHTTPLoads": True, "NSExceptionMinimumTLSVersion": "TLSv1.1",
            "NSExceptionRequiresForwardSecrecy": False}}}
        found = ios.audit_ats({"NSAppTransportSecurity": ats})
        self.assertEqual(ids(found), {"IOS-004", "IOS-005", "IOS-006"})
        good = {"NSExceptionDomains": {"new.example.test": {"NSExceptionMinimumTLSVersion": "TLSv1.2"}}}
        self.assertEqual(ios.audit_ats({"NSAppTransportSecurity": good}), [])

    def test_no_ats_is_clean(self):
        self.assertEqual(ios.audit_ats({}), [])


class IosInfoTests(unittest.TestCase):
    def test_url_schemes(self):
        found = ios.audit_info({"CFBundleURLTypes": [{"CFBundleURLSchemes": ["myapp"]}]})
        self.assertEqual(ids(found), {"IOS-010"})

    def test_usage_descriptions(self):
        found = ios.audit_info({"NSCameraUsageDescription": "TODO", "NSMicrophoneUsageDescription": "",
                                "NSPhotoLibraryUsageDescription": "$(PRODUCT_NAME) needs it",
                                "NSFaceIDUsageDescription": "Face ID unlocks your saved cards."})
        flagged = {f["location"] for f in found if f["id"] == "IOS-020"}
        self.assertEqual(flagged, {"NSCameraUsageDescription", "NSMicrophoneUsageDescription"})

    def test_file_sharing_and_queries(self):
        found = ios.audit_info({"UIFileSharingEnabled": True,
                                "LSApplicationQueriesSchemes": [f"s{i}" for i in range(51)]})
        self.assertEqual(ids(found), {"IOS-021", "IOS-022"})
        self.assertEqual(ios.audit_info({"UIFileSharingEnabled": False,
                                         "LSApplicationQueriesSchemes": ["mailto"]}), [])

    def test_secrets_masked(self):
        found = ios.audit_info({"StripeKey": "sk_live_FAKE0000TEST", "AwsId": "AKIAFAKEFAKEFAKE0000",
                                "MapsKey": "AIza" + "F" * 35, "ServerSecret": "Fake0nly9Key4Tests7NotReal"})
        sev = {f["location"]: f["severity"] for f in found if f["id"] == "IOS-030"}
        self.assertEqual(sev, {"StripeKey": "high", "AwsId": "high", "MapsKey": "low", "ServerSecret": "medium"})
        blob = json.dumps(found)
        for raw in ("FAKE0000TEST", "AKIAFAKEFAKE", "Fake0nly9Key"):
            self.assertNotIn(raw, blob)
        self.assertIn("sk_l...", blob)

    def test_non_secrets_ignored(self):
        found = ios.audit_info({"APIKeyPlaceholder": "$(API_KEY)", "PasswordHint": "Use your email",
                                "CFBundleIdentifier": "test.example.app", "ApiKey": "your_api_key_here_please"})
        self.assertEqual(found, [])

    def test_debug_flags(self):
        self.assertEqual(ids(ios.audit_info({"EnableDebugMenu": True})), {"IOS-031"})
        self.assertEqual(ios.audit_info({"EnableDebugMenu": False}), [])


class IosEntitlementTests(unittest.TestCase):
    def test_weak(self):
        found = ios.audit_entitlements({"get-task-allow": True, "aps-environment": "development",
                                        "com.apple.developer.associated-domains": ["applinks:a.example.test?mode=developer"]})
        self.assertEqual(ids(found), {"IOS-040", "IOS-041", "IOS-042"})

    def test_release(self):
        self.assertEqual(ios.audit_entitlements({"get-task-allow": False, "aps-environment": "production",
                                                 "com.apple.developer.associated-domains": ["applinks:a.example.test"]}), [])


def privacy(**kw):
    base = {"NSPrivacyTracking": False, "NSPrivacyTrackingDomains": [], "NSPrivacyCollectedDataTypes": [],
            "NSPrivacyAccessedAPITypes": [{"NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryUserDefaults",
                                           "NSPrivacyAccessedAPITypeReasons": ["CA92.1"]}]}
    base.update(kw)
    return ios.audit_privacy_manifest(base)


class IosPrivacyManifestTests(unittest.TestCase):
    def test_clean(self):
        self.assertEqual(privacy(), [])
        self.assertEqual(privacy(NSPrivacyTracking=True, NSPrivacyTrackingDomains=["ads.example.test"]), [])

    def test_tracking_flag_and_domains(self):
        self.assertEqual(ids(privacy(NSPrivacyTracking=True)), {"IOS-050"})
        found = privacy(NSPrivacyTrackingDomains=["ads.example.test"])
        self.assertEqual(ids(found), {"IOS-050"})
        self.assertIn("ads.example.test", found[0]["detail"])

    def test_collected_data(self):
        entry = {"NSPrivacyCollectedDataType": "NSPrivacyCollectedDataTypeEmailAddress",
                 "NSPrivacyCollectedDataTypeLinked": True, "NSPrivacyCollectedDataTypeTracking": True,
                 "NSPrivacyCollectedDataTypePurposes": ["NSPrivacyCollectedDataTypePurposeAnalytics"]}
        found = privacy(NSPrivacyCollectedDataTypes=[entry])
        self.assertEqual([(f["id"], f["severity"]) for f in found], [("IOS-051", "medium")])
        self.assertEqual(privacy(NSPrivacyTracking=True, NSPrivacyTrackingDomains=["t.example.test"],
                                 NSPrivacyCollectedDataTypes=[entry]), [])
        partial = {"NSPrivacyCollectedDataType": "NSPrivacyCollectedDataTypeEmailAddress"}
        found = privacy(NSPrivacyCollectedDataTypes=[partial])
        self.assertEqual([(f["id"], f["severity"]) for f in found], [("IOS-051", "low")])

    def test_required_reasons(self):
        def api(cat, reasons):
            return privacy(NSPrivacyAccessedAPITypes=[{"NSPrivacyAccessedAPIType": cat,
                                                       "NSPrivacyAccessedAPITypeReasons": reasons}])
        self.assertEqual(api("NSPrivacyAccessedAPICategoryDiskSpace", ["E174.1", "85F4.1"]), [])
        self.assertEqual(api("NSPrivacyAccessedAPICategorySystemBootTime", ["35F9.1"]), [])
        self.assertEqual(ids(api("NSPrivacyAccessedAPICategoryUserDefault", ["CA92.1"])), {"IOS-052"})
        self.assertEqual(ids(api("NSPrivacyAccessedAPICategoryFileTimestamp", [])), {"IOS-052"})
        found = api("NSPrivacyAccessedAPICategoryDiskSpace", ["C617.1"])
        self.assertEqual(ids(found), {"IOS-052"})
        self.assertIn("C617.1", found[0]["detail"])

    def test_cli_discovery_and_bundle_note(self):
        with tempfile.TemporaryDirectory() as d:
            app = Path(d, "Payload", "Demo.app")
            app.mkdir(parents=True)
            info = app / "Info.plist"
            info.write_bytes(plistlib.dumps({"CFBundleIdentifier": "test.example.demo"}))
            code, out, _ = call_main(ios, [str(info), "--json"])
            data = json.loads(out)
            self.assertEqual(ids(data["findings"]), {"IOS-053"})
            self.assertFalse(data["privacy_manifest_checked"])
            (app / "PrivacyInfo.xcprivacy").write_bytes(plistlib.dumps({"NSPrivacyTracking": True}))
            code, out, _ = call_main(ios, [str(info), "--json"])
            data = json.loads(out)
            self.assertEqual(ids(data["findings"]), {"IOS-050"})
            self.assertTrue(data["privacy_manifest_checked"])
            other = Path(d, "clean.xcprivacy")
            other.write_bytes(plistlib.dumps({"NSPrivacyTracking": False}))
            code, out, _ = call_main(ios, [str(info), "--json", "--privacy-manifest", str(other)])
            self.assertEqual(json.loads(out)["findings"], [])
            src = Path(d, "Info.plist")  # source tree, not a .app: no IOS-053
            src.write_bytes(plistlib.dumps({"CFBundleIdentifier": "test.example.demo"}))
            self.assertEqual(json.loads(call_main(ios, [str(src), "--json"])[1])["findings"], [])
            bad = Path(d, "bad.xcprivacy")
            bad.write_text("not a plist")
            self.assertEqual(call_main(ios, [str(src), "--privacy-manifest", str(bad)])[0], 2)


class IosCliTests(unittest.TestCase):
    def test_weak_example(self):
        code, out, _ = call_main(ios, [str(EX / "ios_weak" / "Info.plist"), "--entitlements",
                                       str(EX / "ios_weak" / "App.entitlements"), "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(set(data), {"plist", "bundle_id", "minimum_os", "entitlements_checked",
                                     "privacy_manifest_checked", "findings"})
        self.assertTrue({"IOS-001", "IOS-004", "IOS-030", "IOS-040", "IOS-050", "IOS-051", "IOS-052"}
                        <= ids(data["findings"]))
        self.assertNotIn("FAKE0000TEST", out)

    def test_hardened_example(self):
        code, out, _ = call_main(ios, [str(EX / "ios_hardened" / "Info.plist"), "--entitlements",
                                       str(EX / "ios_hardened" / "App.entitlements")])
        self.assertEqual(code, 0, out)
        self.assertIn("No issues found", out)
        self.assertIn("privacy manifest checked", out)

    def test_binary_plist(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "Info.plist")
            p.write_bytes(plistlib.dumps({"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}},
                                         fmt=plistlib.FMT_BINARY))
            code, out, _ = call_main(ios, [str(p), "--json"])
            self.assertEqual(code, 1)
            self.assertIn("IOS-001", out)

    def test_fail_on_and_bad_input(self):
        weak = plistlib.dumps({"CFBundleURLTypes": [{"CFBundleURLSchemes": ["myapp"]}]}).decode()
        self.assertEqual(call_main(ios, ["-"], stdin=weak)[0], 0)
        self.assertEqual(call_main(ios, ["-", "--fail-on", "low"], stdin=weak)[0], 1)
        self.assertEqual(call_main(ios, ["-"], stdin="not a plist")[0], 2)
        self.assertEqual(call_main(ios, ["/nonexistent/Info.plist"])[0], 2)
        arr = plistlib.dumps(["a"]).decode()
        self.assertEqual(call_main(ios, ["-"], stdin=arr)[0], 2)

    def test_help(self):
        proc = run_cli("mobile-appsec", "ios_plist_audit", "--help")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--entitlements", proc.stdout)
        self.assertIn("--privacy-manifest", proc.stdout)


if __name__ == "__main__":
    unittest.main()
