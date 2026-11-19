import json
import unittest

from _helpers import call_main, load_script, run_cli, skill_path

cvss = load_script("vuln-triage", "cvss_calc")
deps = load_script("vuln-triage", "dep_audit")
EX = skill_path("vuln-triage", "examples")


def ids(findings):
    return {f["id"] for f in findings}


class CvssTests(unittest.TestCase):
    KNOWN = {
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N": 6.4,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
    }

    def test_known_base_scores(self):
        for vector, expected in self.KNOWN.items():
            self.assertEqual(cvss.score_vector(vector)["base_score"], expected, vector)

    def test_roundup_spec_behaviour(self):
        self.assertEqual(cvss.roundup(4.0), 4.0)
        self.assertEqual(cvss.roundup(4.02), 4.1)
        self.assertEqual(cvss.roundup(4.000002), 4.0, "float noise below 1e-5 must not bump the score")

    def test_severity_bands(self):
        self.assertEqual([cvss.severity(s) for s in (0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10)],
                         ["none", "low", "low", "medium", "medium", "high", "high", "critical", "critical"])

    def test_temporal_and_environmental(self):
        r = cvss.score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C")
        self.assertEqual(r["temporal_score"], 8.8)
        self.assertEqual(r["score"], 8.8)
        r = cvss.score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:L/IR:L/AR:L/MAV:A")
        self.assertEqual(r["environmental_score"], 6.9)
        neutral = cvss.score_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N/CR:X/MAV:X")
        self.assertEqual(neutral["environmental_score"], neutral["base_score"], "all-X environment equals base")

    def test_invalid_vectors(self):
        for bad in ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",           # no prefix
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",      # missing A
                    "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # bad value
                    "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:1",
                    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"):
            with self.assertRaises(ValueError, msg=bad):
                cvss.parse_vector(bad)

    def test_v30_note(self):
        self.assertIn("note", cvss.score_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))

    def test_cli(self):
        code, out, _ = call_main(cvss, ["--file", str(EX / "vectors.txt"), "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(set(data), {"results", "errors"})
        self.assertEqual(len(data["results"]), 6)
        self.assertTrue({"vector", "base_score", "base_severity", "score", "severity", "impact", "exploitability"}
                        <= set(data["results"][0]))
        self.assertEqual(call_main(cvss, ["CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"])[0], 0)
        self.assertEqual(call_main(cvss, ["CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "--fail-on", "medium"])[0], 1)
        self.assertEqual(call_main(cvss, ["CVSS:3.1/AV:N"])[0], 2)
        self.assertEqual(call_main(cvss, [])[0], 2)

    def test_help_subprocess(self):
        self.assertEqual(run_cli("vuln-triage", "cvss_calc", "--help").returncode, 0)


class ParserTests(unittest.TestCase):
    def test_requirements(self):
        d, f = deps.parse_requirements((EX / "python-app" / "requirements.txt").read_text())
        pinned = {x["name"]: x["version"] for x in d if x["version"]}
        self.assertEqual(pinned["pyyaml"], "5.3.1", "comment stripped, name normalized")
        self.assertEqual(pinned["gunicorn"], "20.1.0", "hash continuation handled")
        found = {(x["id"], x["title"].split()[0]) for x in f}
        self.assertIn(("DEP-010", "jinja2"), found)
        self.assertIn(("DEP-012", "urllib3"), found)
        self.assertIn(("DEP-011", "internal-utils"), found)

    def test_pinned_requirements_are_quiet(self):
        d, f = deps.parse_requirements("Django==4.2.11\nrequests[socks]==2.31.0 ; python_version>'3.8'\n")
        self.assertEqual(f, [])
        self.assertEqual([x["name"] for x in d], ["django", "requests"])

    def test_package_lock_v3_and_v1(self):
        data = json.loads((EX / "node-app" / "package-lock.json").read_text())
        d = deps.parse_package_lock(data)
        names = {(x["name"], x["version"]) for x in d}
        self.assertIn(("qs", "6.7.0"), names, "nested node_modules path")
        self.assertNotIn("example-shop-web", {x["name"] for x in d}, "root package skipped")
        v1 = {"lockfileVersion": 1, "dependencies": {"a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}}}
        self.assertEqual({(x["name"], x["version"]) for x in deps.parse_package_lock(v1)}, {("a", "1.0.0"), ("b", "2.0.0")})

    def test_package_json(self):
        data = json.loads((EX / "node-app" / "package.json").read_text())
        d, f = deps.parse_package_json(data, str(EX / "node-app" / "package.json"))
        self.assertIn(("lodash", "4.17.20"), {(x["name"], x["version"]) for x in d})
        by_name = {x["title"].split()[0]: x for x in f}
        self.assertEqual(by_name["left-pad-ng"]["id"], "DEP-012")
        self.assertEqual(by_name["theme-kit"]["id"], "DEP-011")
        self.assertEqual(by_name["express"]["severity"], "info", "range is fine next to a lockfile")

    def test_poetry_and_pipfile(self):
        poetry = '[[package]]\nname = "Jinja2"\nversion = "3.1.2"\ncategory = "main"\n\n[[package]]\nname = "pytest"\nversion = "7.0.0"\ncategory = "dev"\n'
        d = deps.parse_poetry_lock(poetry)
        self.assertEqual([(x["name"], x["version"], x["dev"]) for x in d], [("jinja2", "3.1.2", False), ("pytest", "7.0.0", True)])
        pip = {"_meta": {}, "default": {"flask": {"version": "==2.0.1"}}, "develop": {"black": {"version": "==22.1.0"}}}
        self.assertEqual([(x["name"], x["version"]) for x in deps.parse_pipfile_lock(pip)], [("flask", "2.0.1"), ("black", "22.1.0")])


class MatchingTests(unittest.TestCase):
    def test_version_ordering(self):
        k = deps.version_key
        self.assertLess(k("1.2.3"), k("1.10.0"))
        self.assertLess(k("2.0.0rc1"), k("2.0.0"))
        self.assertLess(k("1.0.0-alpha.1"), k("1.0.0-beta"))
        self.assertLess(k("1.0.dev1"), k("1.0a1"))
        self.assertEqual(k("1.0"), k("1.0.0"))
        self.assertLess(k("1.0"), k("1.0.post1"))

    def test_ranges(self):
        ev = [{"type": "SEMVER", "events": [{"introduced": "6.7.0"}, {"fixed": "6.7.3"}, {"introduced": "6.8.0"}, {"fixed": "6.8.3"}]}]
        self.assertTrue(deps.in_ranges("6.7.0", ev))
        self.assertFalse(deps.in_ranges("6.7.3", ev))
        self.assertTrue(deps.in_ranges("6.8.1", ev))
        self.assertFalse(deps.in_ranges("6.6.0", ev))
        last = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "1.4"}]}]
        self.assertTrue(deps.in_ranges("1.4", last))
        self.assertFalse(deps.in_ranges("1.5", last))

    def test_severity_sources(self):
        self.assertEqual(deps.vuln_severity({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}),
                         ("critical", 9.8))
        self.assertEqual(deps.vuln_severity({"database_specific": {"severity": "MODERATE"}}), ("medium", None))
        self.assertEqual(deps.vuln_severity({}), ("medium", None))

    def test_alias_merge(self):
        d = [deps.dep("requests", "2.19.1", "PyPI", "r.txt:1")]
        rng = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]
        aff = [{"package": {"ecosystem": "PyPI", "name": "requests"}, "ranges": rng}]
        v1 = {"id": "GHSA-aaaa", "aliases": ["CVE-2099-5"], "affected": aff,
              "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]}
        v2 = {"id": "PYSEC-bbbb", "aliases": ["CVE-2099-5", "GHSA-aaaa"], "affected": aff}
        out = deps.vuln_findings(d, {0: [v2, v1]}, set())
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["vuln_id"], "GHSA-aaaa", "the rated record wins")


class DepAuditCliTests(unittest.TestCase):
    def run_examples(self, *extra):
        return call_main(deps, [str(EX / "python-app"), str(EX / "node-app"), "--osv-results",
                                str(EX / "osv-results.json"), "--kev", str(EX / "kev.json"), "--json", *extra])

    def test_examples_offline_match(self):
        code, out, _ = self.run_examples()
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(set(data), {"mode", "dependencies", "findings", "upgrades"})
        vulns = [f for f in data["findings"] if f["id"] == "DEP-001"]
        self.assertEqual({f["vuln_id"] for f in vulns},
                         {"EXAMPLE-PY-0001", "EXAMPLE-PY-0002", "EXAMPLE-PY-0003", "EXAMPLE-JS-0001", "EXAMPLE-JS-0002", "EXAMPLE-JS-0003"})
        self.assertNotIn("EXAMPLE-PY-0004", {f["vuln_id"] for f in vulns}, "fixed before the pinned version")
        first = data["findings"][0]
        self.assertEqual((first["vuln_id"], first["priority"], first["kev"]), ("EXAMPLE-JS-0002", "P1", True))
        lodash = [f for f in vulns if f["package"] == "lodash"]
        self.assertEqual(len(lodash), 1, "package.json and lockfile entries are merged")
        self.assertEqual(lodash[0]["fixed"], ["4.17.21"])
        plan = {p["package"]: p["target"] for p in data["upgrades"]}
        self.assertEqual(plan["pyyaml"], "5.4")
        for f in data["findings"]:
            self.assertTrue({"id", "severity", "title", "detail", "fix"} <= set(f))

    def test_no_dev_drops_dev_vulns(self):
        _, out, _ = self.run_examples("--no-dev")
        self.assertNotIn("minimatch", {f.get("package") for f in json.loads(out)["findings"]})

    def test_exit_codes(self):
        self.assertEqual(self.run_examples("--fail-on", "never")[0], 0)
        code, _, _ = call_main(deps, [str(EX / "python-app" / "requirements.txt")])
        self.assertEqual(code, 0, "pinning issues alone stay below high")
        self.assertEqual(call_main(deps, [str(EX / "missing.txt")])[0], 2)
        self.assertEqual(call_main(deps, [str(EX)])[0], 2, "directory without manifests")

    def test_prioritize_text(self):
        code, out, _ = call_main(deps, [str(EX / "node-app"), "--osv-results", str(EX / "osv-results.json"),
                                        "--kev", str(EX / "kev.json"), "--prioritize"])
        self.assertEqual(code, 1)
        self.assertIn("Upgrade plan:", out)
        self.assertTrue(out.splitlines()[3].startswith("P1"))

    def test_help_subprocess(self):
        self.assertEqual(run_cli("vuln-triage", "dep_audit", "--help").returncode, 0)


if __name__ == "__main__":
    unittest.main()
