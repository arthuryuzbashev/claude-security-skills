import json
import unittest

from _helpers import call_main, load_script, run_cli, skill_path

email = load_script("security-recon", "email_auth_audit")
surface = load_script("security-recon", "surface_map")
posture = load_script("security-recon", "domain_posture")
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

    def test_broad_ip_range(self):
        self.assertIn("EML-012", ids(email.check_spf(["v=spf1 ip4:198.0.0.0/8 -all"])[0]))
        self.assertIn("EML-012", ids(email.check_spf(["v=spf1 ip6:2001:db8::/16 -all"])[0]))
        self.assertNotIn("EML-012", ids(email.check_spf(["v=spf1 ip4:192.0.2.0/24 ip4:192.0.2.1 ip6:2001:db8::/48 -all"])[0]))

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


    def test_rfc9989_missing_p_with_rua_is_medium(self):
        sev = {f["id"]: f["severity"] for f in email.check_dmarc(["v=DMARC1; rua=mailto:d@example.test"])}
        self.assertEqual(sev["DMR-004"], "medium")
        sev = {f["id"]: f["severity"] for f in email.check_dmarc(["v=DMARC1; p=bogus"])}
        self.assertEqual(sev["DMR-004"], "high")

    def test_test_mode_np_and_report_uris(self):
        self.assertIn("DMR-010", ids(email.check_dmarc(["v=DMARC1; p=reject; t=y; rua=mailto:d@example.test"])))
        self.assertNotIn("DMR-010", ids(email.check_dmarc(["v=DMARC1; p=reject; t=n; rua=mailto:d@example.test"])))
        self.assertIn("DMR-011", ids(email.check_dmarc(["v=DMARC1; p=reject; np=none; rua=mailto:d@example.test"])))
        self.assertNotIn("DMR-011", ids(email.check_dmarc(["v=DMARC1; p=reject; np=reject; rua=mailto:d@example.test"])))
        self.assertIn("DMR-012", ids(email.check_dmarc(["v=DMARC1; p=reject; rua=https://reports.example.test/d"])))
        self.assertNotIn("DMR-012", ids(email.check_dmarc(["v=DMARC1; p=reject; rua=mailto:a@example.test,mailto:b@example.test"])))


class BimiTests(unittest.TestCase):
    GOOD = "v=BIMI1; l=https://example.test/logo.svg; a=https://example.test/vmc.pem"

    def test_good_record_with_enforced_dmarc(self):
        self.assertEqual(email.check_bimi([self.GOOD], ["v=DMARC1; p=reject; rua=mailto:d@example.test"]), [])
        self.assertEqual(email.check_bimi([], ["v=DMARC1; p=none"]), [], "no BIMI record is not a finding")

    def test_findings(self):
        self.assertIn("BIM-001", ids(email.check_bimi([self.GOOD], ["v=DMARC1; p=none"])))
        self.assertIn("BIM-001", ids(email.check_bimi([self.GOOD], ["v=DMARC1; p=quarantine; pct=50"])))
        self.assertEqual(email.check_bimi([self.GOOD]), [], "DMARC not given: prerequisite skipped")
        self.assertIn("BIM-002", ids(email.check_bimi(["v=BIMI1; l=http://example.test/logo.png; a=https://x.test/c.pem"])))
        self.assertIn("BIM-003", ids(email.check_bimi(["v=BIMI1; l=https://example.test/logo.svg"])))
        self.assertIn("BIM-004", ids(email.check_bimi([self.GOOD, self.GOOD])))
        self.assertEqual(email.check_bimi(["v=BIMI1; l=;"]), [], "empty l= is an opt-out")


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

    def test_max_age_above_limit(self):
        good = (EX / "mta-sts.txt").read_text()
        self.assertIn("MTS-009", ids(email.check_mta_sts(["v=STSv1; id=1"], good.replace("1209600", "63072000"))))
        self.assertNotIn("MTS-009", ids(email.check_mta_sts(["v=STSv1; id=1"], good.replace("1209600", "31557600"))))
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
        for expected in ("EML-009", "EML-005", "EML-008", "DMR-006", "DMR-008", "DMR-009", "DKM-006", "MTS-003", "TRP-001",
                         "EML-012", "BIM-001", "BIM-002", "BIM-003"):
            self.assertIn(expected, ids(data["findings"]))
        for f in data["findings"]:
            self.assertTrue({"id", "severity", "title", "detail", "fix"} <= set(f))

    def test_strong_example_is_clean(self):
        code, out, _ = call_main(email, ["--file", str(EX / "strong_records.txt"),
                                         "--mta-sts-policy", str(EX / "mta-sts.txt"), "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["grade"], "A")
        self.assertEqual(data["findings"], [])
        self.assertEqual(len(data["records"]["bimi"]), 1)

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

    def test_api_docs_category_and_takeover_list(self):
        self.assertEqual(surface.classify("swagger.example.test", "example.test"), ["api-docs"])
        self.assertEqual(surface.classify("graphql-dev.example.test", "example.test"), ["non-prod", "api-docs"])
        self.assertEqual(surface.classify("api.example.test", "example.test"), [])
        _, findings = surface.analyze(["swagger.example.test"], [], "example.test")
        self.assertEqual(ids(findings), {"SRF-011"})
        dns = {"help.example.test": {"cname": ["acme.helpjuice.com"], "ips": [], "known": True},
               "shop.example.test": {"cname": ["acme.wpengine.com"], "ips": [], "known": True}}
        _, findings = surface.analyze(sorted(dns), [], "example.test", dns)
        by_host = {(f["id"], f.get("location")) for f in findings}
        self.assertIn(("SRF-021", "help.example.test"), by_host)
        self.assertIn(("SRF-022", "shop.example.test"), by_host, "WP Engine is listed as not vulnerable")


class DomainPostureTests(unittest.TestCase):
    TODAY = __import__("datetime").date(2026, 11, 19)

    def test_good_security_txt_is_quiet(self):
        self.assertEqual(posture.check_security_txt((EX / "security.txt").read_text(), self.TODAY), [])

    def test_security_txt_findings(self):
        self.assertEqual(ids(posture.check_security_txt(None, self.TODAY)), {"STX-001"})
        self.assertIn("STX-002", ids(posture.check_security_txt("Expires: 2027-01-01T00:00:00Z", self.TODAY)))
        self.assertIn("STX-003", ids(posture.check_security_txt("Contact: mailto:s@example.test", self.TODAY)))
        old = "Contact: mailto:s@example.test\nExpires: 2026-01-01T00:00:00Z"
        self.assertIn("STX-004", ids(posture.check_security_txt(old, self.TODAY)))
        far = "Contact: mailto:s@example.test\nExpires: 2030-01-01T00:00:00Z"
        self.assertIn("STX-005", ids(posture.check_security_txt(far, self.TODAY)))
        bad = "Contact: http://example.test/r\nContact: security team\nExpires: 2027-01-01T00:00:00Z"
        self.assertEqual([f["id"] for f in posture.check_security_txt(bad, self.TODAY)], ["STX-006", "STX-006"])
        twice = "Contact: mailto:s@example.test\nExpires: 2027-01-01T00:00:00Z\nExpires: 2027-02-01T00:00:00Z"
        self.assertIn("STX-007", ids(posture.check_security_txt(twice, self.TODAY)))
        good = (EX / "security.txt").read_text()
        self.assertIn("STX-008", ids(posture.check_security_txt(good, self.TODAY, legacy_only=True)))

    def test_signed_security_txt(self):
        signed = ("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n" + (EX / "security.txt").read_text()
                  + "-----BEGIN PGP SIGNATURE-----\nFAKEFAKE\n-----END PGP SIGNATURE-----\n")
        self.assertTrue(posture.parse_security_txt(signed)["signed"])
        self.assertEqual(posture.check_security_txt(signed, self.TODAY), [])

    def test_caa_and_dnssec(self):
        self.assertEqual(ids(posture.check_caa([], "example.test")), {"CAA-001"})
        self.assertIn("CAA-002", ids(posture.check_caa(['128 tbs "x"', '0 iodef "mailto:s@example.test"'], "example.test")))
        self.assertNotIn("CAA-002", ids(posture.check_caa(['128 issue "letsencrypt.org"'], "example.test")))
        self.assertEqual(ids(posture.check_caa(['0 issue "letsencrypt.org"'], "example.test")), {"CAA-003"})
        self.assertEqual(ids(posture.check_dnssec([], "example.test")), {"DNS-001"})
        self.assertEqual(posture.check_dnssec(["2371 13 2 ABCD"], "example.test"), [])

    def test_cli_offline(self):
        code, out, _ = call_main(posture, ["www.example.test", "--records", str(EX / "posture_records.txt"),
                                           "--security-txt", str(EX / "security.txt"), "--today", "2026-11-19",
                                           "--json", "--fail-on", "info"])
        self.assertEqual(code, 0, "host inside the zone inherits its CAA and DS")
        data = json.loads(out)
        self.assertEqual(set(data), {"target", "checks", "security_txt", "caa", "dnssec", "findings"})
        self.assertTrue(data["dnssec"])
        code, _, _ = call_main(posture, ["--security-txt", "-", "--today", "2026-11-19", "--fail-on", "medium"],
                               stdin="Contact: mailto:s@example.test\n")
        self.assertEqual(code, 1)
        self.assertEqual(call_main(posture, [])[0], 2)
        self.assertEqual(call_main(posture, ["--security-txt", str(EX / "missing.txt")])[0], 2)
        self.assertEqual(call_main(posture, ["--security-txt", "-", "--today", "nope"], stdin="x")[0], 2)

    def test_help_subprocess(self):
        self.assertEqual(run_cli("security-recon", "domain_posture", "--help").returncode, 0)


if __name__ == "__main__":
    unittest.main()
