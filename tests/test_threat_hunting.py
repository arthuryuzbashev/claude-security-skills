"""Tests for skills/threat-hunting (ioc_extract.py, attack_mapper.py)."""
import json
import os
import tempfile
import unittest

from _helpers import call_main, load_script, run_cli, skill_path

SKILL = "threat-hunting"
EX = skill_path(SKILL, "examples")
ioc = load_script(SKILL, "ioc_extract")
am = load_script(SKILL, "attack_mapper")


class TestRefangDefang(unittest.TestCase):
    def test_refang_common_forms(self):
        self.assertEqual(ioc.refang("hxxps://evil[.]example[.]test/a"), "https://evil.example.test/a")
        self.assertEqual(ioc.refang("bad(.)example(.)test"), "bad.example.test")
        self.assertEqual(ioc.refang("user[at]example[dot]test"), "user@example.test")

    def test_defang_url_and_ip(self):
        self.assertEqual(ioc.defang("https://evil.example.test/x", "url"), "hxxps[://]evil[.]example[.]test/x")
        self.assertEqual(ioc.defang("203.0.113.9", "ipv4"), "203[.]0[.]113[.]9")

    def test_mask_url_hides_token(self):
        masked = ioc.mask_url("https://a.example.test/p?token=sk_live_FAKEFAKE1234&id=1")
        self.assertIn("token=sk_l...", masked)
        self.assertNotIn("FAKEFAKE1234", masked)


class TestExtract(unittest.TestCase):
    def test_types_from_defanged_text(self):
        r = ioc.extract("Beacon to hxxp://c2[.]bad-site[.]test/gate from 198[.]51[.]100[.]10")
        self.assertIn("198.51.100.10", r["ipv4"])
        self.assertIn("c2.bad-site.test", r["domain"])
        self.assertTrue(any(u.startswith("http://c2.bad-site.test") for u in r["url"]))

    def test_private_ips_dropped_unless_keep_all(self):
        text = "seen 10.1.2.3 and 192.168.0.5 and 127.0.0.1 and 203.0.113.7"
        self.assertEqual(ioc.extract(text)["ipv4"], ["203.0.113.7"])
        self.assertIn("10.1.2.3", ioc.extract(text, keep_all=True)["ipv4"])

    def test_benign_domains_dropped(self):
        r = ioc.extract("see docs.microsoft.com and attack.mitre.org and bad.example.test")
        self.assertEqual(r["domain"], ["bad.example.test"])
        self.assertIn("docs.microsoft.com", ioc.extract("docs.microsoft.com", keep_all=True)["domain"])

    def test_filenames_not_domains(self):
        r = ioc.extract("opened invoice.docm then dumped lsass.dmp")
        self.assertEqual(r["domain"], [])

    def test_hashes_by_length(self):
        r = ioc.extract("5d41402abc4b2a76b9719d911017c592 aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d "
                        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
        self.assertEqual(len(r["md5"]), 1)
        self.assertEqual(len(r["sha1"]), 1)
        self.assertEqual(len(r["sha256"]), 1)

    def test_cve_normalised(self):
        self.assertEqual(ioc.extract("cve-2024-21887 and CVE-2023-46805")["cve"], ["CVE-2023-46805", "CVE-2024-21887"])

    def test_registry_and_paths(self):
        r = ioc.extract(r"Run key HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Evil wrote C:\Users\Public\x.exe and /tmp/.x/run")
        self.assertTrue(r["registry"])
        self.assertIn("/tmp/.x/run", r["filepath"])

    def test_types_filter(self):
        r = ioc.extract("203.0.113.7 bad.example.test", types=["ipv4"])
        self.assertEqual(list(r), ["ipv4"])

    def test_nothing_found(self):
        r = ioc.extract("nothing interesting here")
        self.assertTrue(all(v == [] for v in r.values()))


class TestIocCli(unittest.TestCase):
    def test_example_json(self):
        code, out, _ = call_main(ioc, [str(EX / "incident_report.txt"), "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(list(data)[:3], ["ipv4", "ipv6", "domain"])
        self.assertEqual(data["ipv4"], ["198.51.100.23", "203.0.113.45"])
        self.assertNotIn("10.20.30.40", data["ipv4"])
        self.assertTrue(all("FAKEFAKE1234" not in u for u in data["url"]))

    def test_defang_csv(self):
        code, out, _ = call_main(ioc, [str(EX / "incident_report.txt"), "--format", "csv", "--defang"])
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("type,value"))
        self.assertIn("198[.]51[.]100[.]23", out)

    def test_stdin(self):
        code, out, _ = call_main(ioc, ["--file", "-", "--format", "list"], stdin="hit 203.0.113.99\n")
        self.assertEqual(code, 0)
        self.assertIn("203.0.113.99", out)

    def test_bad_types_exit_2(self):
        code, _, _ = call_main(ioc, [str(EX / "incident_report.txt"), "--types", "nope"])
        self.assertEqual(code, 2)

    def test_missing_file_exit_2(self):
        code, _, _ = call_main(ioc, [str(EX / "does_not_exist.txt")])
        self.assertEqual(code, 2)

    def test_help(self):
        self.assertEqual(run_cli(SKILL, "ioc_extract", "--help").returncode, 0)


class TestAttackTable(unittest.TestCase):
    def test_ids_well_formed_and_unique(self):
        ids = [t[0] for t in am.TECHNIQUES]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(ids), 60)
        for tid, name, tactics, _ in am.TECHNIQUES:
            self.assertRegex(tid, r"^T\d{4}(\.\d{3})?$")
            self.assertTrue(name)
            self.assertTrue(tactics)

    def test_all_tactics_known_and_covered(self):
        known = {t[1] for t in am.TACTICS} | {t[0] for t in am.TACTICS} | {t[2] for t in am.TACTICS}
        used = set()
        for _, _, tactics, _ in am.TECHNIQUES:
            for tac in tactics:
                self.assertIn(tac, known)
                used.add(tac)
        self.assertEqual(len(am.TACTICS), 14)

    def test_spot_check_pairs(self):
        table = {t[0]: t[1] for t in am.TECHNIQUES}
        self.assertEqual(table.get("T1003.001"), "OS Credential Dumping: LSASS Memory")
        self.assertTrue(table.get("T1059.001", "").endswith("PowerShell"))
        self.assertTrue(table.get("T1053.005", "").endswith("Scheduled Task"))
        self.assertTrue(table.get("T1566.001", "").endswith("Spearphishing Attachment"))
        self.assertEqual(table.get("T1490"), "Inhibit System Recovery")


class TestAttackMapper(unittest.TestCase):
    def test_maps_keywords(self):
        ids = [t["id"] for t in am.map_text("procdump -ma lsass.exe\npowershell -enc AAAA")["techniques"]]
        self.assertIn("T1003.001", ids)
        self.assertIn("T1059.001", ids)

    def test_no_match(self):
        r = am.map_text("The coffee machine is broken")
        self.assertEqual(r["techniques"], [])

    def test_explicit_unknown_id_not_guessed(self):
        r = am.map_text("analyst noted T9999 in the report")
        t = [x for x in r["techniques"] if x["id"] == "T9999"]
        self.assertTrue(t)
        self.assertIsNone(t[0]["name"])

    def test_coverage_shape(self):
        cov = am.map_text("procdump lsass")["coverage"]
        self.assertEqual(len(cov), 14)
        for c in cov:
            self.assertEqual(set(c), {"tactic", "tactic_id", "shortname", "matched", "in_table", "techniques"})

    def test_example_cli_json(self):
        code, out, _ = call_main(am, [str(EX / "hunt_notes.txt"), "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(set(data), {"lines", "techniques", "coverage"})
        ids = [t["id"] for t in data["techniques"]]
        for tid in ("T1566.001", "T1003.001", "T1490", "T1547.001"):
            self.assertIn(tid, ids)
        unmatched = [l["text"] for l in data["lines"] if not l["techniques"]]
        self.assertEqual(unmatched, ["Printer queue jammed on floor 3"])

    def test_navigator_layer(self):
        with tempfile.TemporaryDirectory() as d:
            out_path = os.path.join(d, "layer.json")
            code, _, _ = call_main(am, [str(EX / "hunt_notes.txt"), "--navigator", out_path, "--layer-name", "t"])
            self.assertEqual(code, 0)
            with open(out_path) as fh:
                layer = json.load(fh)
        self.assertEqual(layer["domain"], "enterprise-attack")
        self.assertEqual(layer["versions"]["layer"], "4.5")
        self.assertEqual(layer["name"], "t")
        self.assertTrue(all(t["score"] >= 1 for t in layer["techniques"]))

    def test_list_and_empty_input(self):
        code, out, _ = call_main(am, ["--list"])
        self.assertEqual(code, 0)
        self.assertIn("T1003.001", out)
        self.assertEqual(call_main(am, ["--file", "-"], stdin="")[0], 2)

    def test_help(self):
        self.assertEqual(run_cli(SKILL, "attack_mapper", "--help").returncode, 0)


if __name__ == "__main__":
    unittest.main()
