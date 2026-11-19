import json
import unittest

from _helpers import call_main, load_script, run_cli, skill_path

email = load_script("security-recon", "email_auth_audit")
surface = load_script("security-recon", "surface_map")
EX = skill_path("security-recon", "examples")


def ids(findings):
    return {f["id"] for f in findings}


def dkim_key(name):
    """Pull the p= key of a selector out of the example files."""
    for path in ("weak_records.txt", "strong_records.txt"):
        for n, text in email.parse_record_lines((EX / path).read_text()):
            if n and n.startswith(name + "._domainkey"):
                return email.parse_tags(text)["p"]
    raise KeyError(name)


class SpfTests(unittest.TestCase):
    def test_plus_all_and_neutral(self):
        self.assertIn("EML-004", ids(email.check_spf(["v=spf1 a mx +all"])[0]))
        self.assertIn("EML-004", ids(email.check_spf(["v=spf1 all"])[0]), "bare all means +all")
        self.assertIn("EML-005", ids(email.check_spf(["v=spf1 a ?all"])[0]))

    def test_good_record_is_quiet(self):
        findings, lookups = email.check_spf(["v=spf1 ip4:192.0.2.0/24 mx -all"])
        self.assertEqual(findings, [])
        self.assertEqual(lookups, 1)

    def test_missing_multiple_unknown(self):
        self.assertIn("EML-001", ids(email.check_spf([])[0]))
        self.assertIn("EML-002", ids(email.check_spf(["v=spf1 -all", "v=spf1 mx -all"])[0]))
        self.assertIn("EML-003", ids(email.check_spf(["v=spf1 ipv4:192.0.2.1 -all"])[0]))
        self.assertIn("EML-007", ids(email.check_spf(["v=spf1 mx"])[0]))
        self.assertNotIn("EML-007", ids(email.check_spf(["v=spf1 redirect=_spf.example.test"])[0]))

    def test_lookup_count_recursive(self):
        table = {"a.example.test": ["v=spf1 include:b.example.test mx a -all"],
                 "b.example.test": ["v=spf1 " + " ".join(f"a:h{i}.example.test" for i in range(8)) + " -all"]}
        resolver = lambda n: table.get(n, [])
        findings, lookups = email.check_spf(["v=spf1 include:a.example.test -all"], resolver)
        self.assertEqual(lookups, 12)
        self.assertIn("EML-009", ids(findings))

    def test_offline_include_note_and_missing_target(self):
        findings, lookups = email.check_spf(["v=spf1 include:x.example.test -all"])
        self.assertEqual(lookups, 1)
        self.assertIn("EML-010", ids(findings))
        findings, _ = email.check_spf(["v=spf1 include:x.example.test -all"], lambda n: [])
        self.assertIn("EML-011", ids(findings))

    def test_split_txt_strings_join(self):
        self.assertEqual(email.join_txt_strings('"v=spf1 a" " -all"'), "v=spf1 a -all")


class DmarcTests(unittest.TestCase):
    def test_none_and_missing(self):
        self.assertIn("DMR-001", ids(email.check_dmarc([])))
        found = ids(email.check_dmarc(["v=DMARC1; p=none"]))
        self.assertTrue({"DMR-005", "DMR-009"} <= found)

    def test_enforced_is_quiet(self):
        self.assertEqual(email.check_dmarc(["v=DMARC1; p=reject; rua=mailto:d@example.test"]), [])

    def test_subdomain_pct_and_invalid(self):
        found = ids(email.check_dmarc(["v=DMARC1; p=reject; sp=none; pct=20; rua=mailto:d@example.test"]))
        self.assertTrue({"DMR-006", "DMR-008"} <= found)
        self.assertIn("DMR-004", ids(email.check_dmarc(["v=DMARC1; rua=mailto:d@example.test"])))
        self.assertIn("DMR-003", ids(email.check_dmarc(["p=reject; v=DMARC1"])))
        self.assertIn("DMR-002", ids(email.check_dmarc(["v=DMARC1; p=reject", "v=DMARC1; p=none"])))


class DkimTests(unittest.TestCase):
    def test_key_sizes_from_examples(self):
        self.assertEqual(email.rsa_key_bits(dkim_key("mail2019")), 1024)
        self.assertEqual(email.rsa_key_bits(dkim_key("s1")), 2048)

    def test_findings(self):
        weak = ids(email.check_dkim({"old": "v=DKIM1; t=y; k=rsa; p=" + dkim_key("mail2019")}))
        self.assertEqual(weak, {"DKM-006", "DKM-007"})
        self.assertEqual(email.check_dkim({"s1": "v=DKIM1; k=rsa; p=" + dkim_key("s1")}), [])
        self.assertIn("DKM-002", ids(email.check_dkim({"gone": "v=DKIM1; p="})))
        self.assertIn("DKM-004", ids(email.check_dkim({"bad": "v=DKIM1; p=bm90LWEta2V5"})))
        self.assertIn("DKM-001", ids(email.check_dkim({}, looked_up=True)))
        self.assertEqual(email.check_dkim({}, looked_up=False), [])


class MtaStsTests(unittest.TestCase):
    def test_policy_modes(self):
        good = (EX / "mta-sts.txt").read_text()
        self.assertEqual(email.check_mta_sts(["v=STSv1; id=20260101"], good), [])
        testing = good.replace("enforce", "testing").replace("1209600", "3600")
        self.assertEqual(ids(email.check_mta_sts(["v=STSv1; id=1"], testing)), {"MTS-005", "MTS-008"})
        self.assertIn("MTS-003", ids(email.check_mta_sts(["v=STSv1; id=2024-01-01"])))
        self.assertIn("MTS-001", ids(email.check_mta_sts([])))
        self.assertIn("MTS-007", ids(email.check_mta_sts(["v=STSv1; id=1"], "version: STSv1\nmode: enforce\nmax_age: 604800")))

    def test_tls_rpt(self):
        self.assertIn("TRP-002", ids(email.check_tls_rpt(["v=TLSRPTv1;"])))
        self.assertEqual(email.check_tls_rpt(["v=TLSRPTv1; rua=mailto:t@example.test"]), [])


class EmailCliTests(unittest.TestCase):
    def test_weak_example(self):
        code, out, _ = call_main(email, ["--file", str(EX / "weak_records.txt"), "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(set(data), {"target", "records", "spf_lookups", "score", "grade", "findings"})
        self.assertEqual(data["spf_lookups"], 11)
        for expected in ("EML-009", "EML-005", "EML-008", "DMR-006", "DMR-008", "DMR-009", "DKM-006", "MTS-003", "TRP-001"):
            self.assertIn(expected, ids(data["findings"]))
        for f in data["findings"]:
            self.assertTrue({"id", "severity", "title", "detail", "fix"} <= set(f))

    def test_strong_example_is_clean(self):
        code, out, _ = call_main(email, ["--file", str(EX / "strong_records.txt"),
                                         "--mta-sts-policy", str(EX / "mta-sts.txt"), "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["grade"], "A")

    def test_inline_only_checks_given_records(self):
        code, out, _ = call_main(email, ["--spf", "v=spf1 -all", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["findings"], [])
        code, _, _ = call_main(email, ["--dmarc", "v=DMARC1; p=none", "--fail-on", "medium"])
        self.assertEqual(code, 1)

    def test_bad_input(self):
        self.assertEqual(call_main(email, [])[0], 2)
        self.assertEqual(call_main(email, ["--file", "-"], stdin="nothing here")[0], 2)

    def test_help_subprocess(self):
        self.assertEqual(run_cli("security-recon", "email_auth_audit", "--help").returncode, 0)


class SurfaceMapTests(unittest.TestCase):
    def test_normalize_dedup_and_scope(self):
        names = surface.extract_names((EX / "hosts.txt").read_text())
        hosts, wilds, rejected = surface.normalize(names, "example.test")
        self.assertEqual(hosts.count("www.example.test"), 1)
        self.assertIn("login.example.test", hosts, "URL is reduced to its host")
        self.assertNotIn("partner.other.test", hosts, "out of scope")
        self.assertEqual(rejected, ["not"], "first word of a junk line is rejected")
        self.assertEqual(wilds, [])

    def test_classify_tokens(self):
        self.assertEqual(surface.classify("jenkins-old2.example.test", "example.test"), ["ci-cd", "legacy"])
        self.assertEqual(surface.classify("www.example.test", "example.test"), [])
        self.assertEqual(surface.classify("example.test", "example.test"), [], "apex is never classified by its own name")
        self.assertEqual(surface.classify("devices.example.test", "example.test"), [], "whole words only")

    def test_crtsh_wildcards(self):
        names = surface.extract_names((EX / "crtsh.json").read_text())
        hosts, wilds, _ = surface.normalize(names, "example.test")
        self.assertIn("uat-admin.example.test", hosts)
        self.assertEqual(wilds, ["example.test"])
        _, findings = surface.analyze(hosts, wilds, "example.test")
        self.assertTrue({"SRF-001", "SRF-002", "SRF-003", "SRF-030"} <= ids(findings))

    def test_dns_checks_from_records(self):
        names = surface.extract_names((EX / "hosts.txt").read_text())
        hosts, wilds, _ = surface.normalize(names, "example.test")
        table = surface.parse_records((EX / "dns_answers.txt").read_text())
        dns = {h: surface.records_resolver(table)(h) for h in hosts if h in table}
        _, findings = surface.analyze(hosts, wilds, "example.test", dns)
        by_host = {(f["id"], f.get("location")) for f in findings}
        self.assertIn(("SRF-021", "staging-api.example.test"), by_host)
        self.assertIn(("SRF-022", "old-shop.example.test"), by_host)
        self.assertIn(("SRF-020", "jenkins.example.test"), by_host)
        self.assertIn(("SRF-020", "dev2.example.test"), by_host)
        self.assertNotIn(("SRF-021", "docs.example.test"), by_host, "CNAME that resolves is fine")
        self.assertNotIn(("SRF-020", "www.example.test"), by_host, "documentation ranges are not private")

    def test_cli(self):
        code, out, _ = call_main(surface, [str(EX / "hosts.txt"), "--domain", "example.test",
                                           "--records", str(EX / "dns_answers.txt"), "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(set(data), {"summary", "hosts", "rejected", "findings"})
        self.assertEqual(data["summary"]["hosts"], 13)
        code, _, _ = call_main(surface, [str(EX / "hosts.txt"), "--domain", "example.test"])
        self.assertEqual(code, 0, "names alone never reach high")
        self.assertEqual(call_main(surface, ["-"], stdin="\n\n")[0], 2)
        self.assertEqual(call_main(surface, [str(EX / "missing.txt")])[0], 2)

    def test_help_subprocess(self):
        self.assertEqual(run_cli("security-recon", "surface_map", "--help").returncode, 0)


if __name__ == "__main__":
    unittest.main()
