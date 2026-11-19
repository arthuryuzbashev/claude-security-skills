import json
import os
import tempfile
import unittest

from _helpers import call_main, load_script, run_cli, skill_path

sm = load_script("threat-modeling", "stride_model")
md = load_script("threat-modeling", "model_diff")
EX = skill_path("threat-modeling", "examples")
V1, V2 = str(EX / "checkout_v1.yaml"), str(EX / "checkout_v2.yaml")


def model(components, flows, zones=None):
    return sm.load_model(json.dumps({"name": "t", "zones": zones or {}, "components": components, "flows": flows}))


def run(components, flows, zones=None):
    return sm.build(model(components, flows, zones))


def flag_ids(result):
    return [f["id"] for f in result["findings"] if f["kind"] == "flag"]


USER = {"id": "u", "type": "user", "zone": "internet"}
API = {"id": "api", "type": "api", "zone": "internal", "logging": True}
DB = {"id": "db", "type": "db", "zone": "data", "logging": True}


class LoadTests(unittest.TestCase):
    def test_yaml_example_loads(self):
        with open(V1, encoding="utf-8") as fh:
            m = sm.load_model(fh.read())
        self.assertEqual(len(m["components"]), 5)
        self.assertEqual(m["trust"]["dmz"], 1)

    def test_unknown_component_in_flow(self):
        with self.assertRaises(ValueError):
            model([USER], [{"from": "u", "to": "ghost"}])

    def test_bad_type_and_duplicate_id(self):
        with self.assertRaises(ValueError):
            model([{"id": "x", "type": "mainframe"}], [])
        with self.assertRaises(ValueError):
            model([USER, dict(USER)], [])

    def test_unknown_zone_warns(self):
        m = model([{"id": "x", "type": "api", "zone": "moonbase"}], [])
        self.assertEqual(m["trust"]["moonbase"], 2)
        self.assertTrue(any("moonbase" in w for w in m["warnings"]))

    def test_encryption_from_protocol(self):
        m = model([API, DB], [{"from": "api", "to": "db", "protocol": "postgres+tls"},
                              {"from": "api", "to": "db", "protocol": "http"},
                              {"from": "api", "to": "db", "protocol": "postgres"}])
        enc = [sm.analyze_flow(f, m)["encrypted"] for f in m["flows"]]
        self.assertEqual(enc, [True, False, None])
        self.assertEqual([f["key"] for f in m["flows"]], ["api->db", "api->db#2", "api->db#3"])


class StrideTests(unittest.TestCase):
    def test_per_element_letters(self):
        r = run([USER, API, DB], [{"from": "u", "to": "api", "protocol": "https", "auth": "session"},
                                  {"from": "api", "to": "db", "protocol": "postgres+tls", "auth": "iam"}])
        by_loc = {}
        for f in r["findings"]:
            if f["kind"] == "threat":
                by_loc.setdefault(f["location"].split(" ")[0], set()).add(f["stride"])
        self.assertEqual(by_loc["u"], {"S", "R"})
        self.assertEqual(by_loc["api"], set("STRIDE"))
        self.assertEqual(by_loc["db"], {"T", "I", "D"})
        flow_threats = [f["id"] for f in r["findings"] if f["location"].startswith("flow")]
        self.assertEqual(sorted(flow_threats), sorted(["STR-T30", "STR-I30", "STR-D30"] * 2))

    def test_no_flow_threats_inside_one_zone(self):
        r = run([dict(API, zone="data"), DB], [{"from": "api", "to": "db", "protocol": "https", "auth": "iam"}])
        self.assertFalse([f for f in r["findings"] if f["location"].startswith("flow")])
        self.assertEqual(r["summary"]["boundary_crossings"], 0)

    def test_llm_specific_threats(self):
        r = run([USER, {"id": "bot", "type": "llm", "zone": "internal", "logging": True}, API],
                [{"from": "u", "to": "bot", "protocol": "https", "auth": "session"},
                 {"from": "bot", "to": "api", "protocol": "https", "auth": "apikey"}])
        found = {f["id"] for f in r["findings"]}
        self.assertTrue({"LLM-T01", "LLM-I01", "LLM-E01", "LLM-D01"} <= found)
        agency = [f for f in r["findings"] if f["id"] == "LLM-E01"][0]
        self.assertEqual(agency["likelihood"], 3)

    def test_likelihood_impact_defaults(self):
        r = run([USER, API], [{"from": "u", "to": "api", "protocol": "https", "auth": "session", "data": "credentials"}])
        s01 = [f for f in r["findings"] if f["id"] == "STR-S01"][0]
        self.assertEqual((s01["likelihood"], s01["impact"], s01["severity"]), (3, 3, "high"))
        r = run([dict(API, zone="data"), DB], [{"from": "api", "to": "db", "protocol": "https", "auth": "iam", "data": "public"}])
        s01 = [f for f in r["findings"] if f["id"] == "STR-S01"][0]
        self.assertEqual((s01["likelihood"], s01["impact"], s01["severity"]), (1, 1, "low"))


class FlagTests(unittest.TestCase):
    def test_unauthenticated_inbound(self):
        r = run([USER, API], [{"from": "u", "to": "api", "protocol": "https", "auth": "none", "data": "pii"}])
        self.assertIn("FLOW-001", flag_ids(r))
        r = run([USER, API], [{"from": "u", "to": "api", "protocol": "https", "auth": "oauth", "data": "pii"}])
        self.assertNotIn("FLOW-001", flag_ids(r))

    def test_public_unauthenticated_is_low(self):
        r = run([USER, API], [{"from": "u", "to": "api", "protocol": "https", "auth": "none", "data": "public"}])
        f = [x for x in r["findings"] if x["id"] == "FLOW-001"][0]
        self.assertEqual(f["severity"], "low")

    def test_plaintext_sensitive(self):
        r = run([USER, API], [{"from": "u", "to": "api", "protocol": "http", "auth": "session", "data": "pii"}])
        f = [x for x in r["findings"] if x["id"] == "FLOW-002"][0]
        self.assertEqual(f["severity"], "critical")
        r = run([API, dict(DB, zone="internal")], [{"from": "api", "to": "db", "encrypted": False, "auth": "iam", "data": "pii"}])
        self.assertEqual([x["severity"] for x in r["findings"] if x["id"] == "FLOW-002"], ["high"])
        r = run([API, DB], [{"from": "api", "to": "db", "protocol": "mtls", "auth": "iam", "data": "pii"}])
        self.assertFalse({"FLOW-002", "FLOW-003"} & set(flag_ids(r)))

    def test_plaintext_boundary_non_sensitive(self):
        r = run([API, DB], [{"from": "api", "to": "db", "protocol": "tcp", "auth": "iam", "data": "internal"}])
        self.assertIn("FLOW-003", flag_ids(r))

    def test_not_stated(self):
        r = run([USER, API], [{"from": "u", "to": "api", "data": "pii"}])
        self.assertTrue({"FLOW-004", "FLOW-005"} <= set(flag_ids(r)))

    def test_store_from_untrusted_and_low_trust_store(self):
        r = run([USER, dict(DB, zone="internet")], [{"from": "u", "to": "db", "protocol": "https", "auth": "iam"}])
        self.assertTrue({"FLOW-006", "ELEM-002"} <= set(flag_ids(r)))

    def test_logging(self):
        r = run([USER, dict(API, logging=False)], [{"from": "u", "to": "api", "protocol": "https", "auth": "session"}])
        f = [x for x in r["findings"] if x["id"] == "ELEM-001"][0]
        self.assertEqual(f["severity"], "medium")
        r = run([USER, API], [{"from": "u", "to": "api", "protocol": "https", "auth": "session"}])
        self.assertNotIn("ELEM-001", flag_ids(r))

    def test_orphan_component(self):
        r = run([USER, API, DB], [{"from": "u", "to": "api", "protocol": "https", "auth": "session"}])
        self.assertIn("ELEM-003", flag_ids(r))


class RenderTests(unittest.TestCase):
    def test_mermaid_structure(self):
        with open(V2, encoding="utf-8") as fh:
            r = sm.build(sm.load_model(fh.read()))
        mm = r["mermaid"]
        self.assertTrue(mm.startswith("flowchart LR"))
        self.assertIn('subgraph zone_internet["internet (trust 0)"]', mm)
        self.assertIn('n_db[("Orders DB")]', mm)
        self.assertIn("linkStyle", mm)
        self.assertEqual(mm.count("subgraph"), mm.count("\n  end"))

    def test_mermaid_escapes_quotes_and_reserved_ids(self):
        r = run([{"id": "end", "name": 'Say "hi"', "type": "api", "zone": "internal"}], [])
        self.assertIn("n_end", r["mermaid"])
        self.assertIn("#quot;hi#quot;", r["mermaid"])

    def test_markdown_sections(self):
        with open(V1, encoding="utf-8") as fh:
            out = sm.render_markdown(sm.build(sm.load_model(fh.read())))
        for heading in ("# Threat model: Shop checkout v1", "```mermaid", "## Design flags", "## STRIDE threats"):
            self.assertIn(heading, out)


class StrideCliTests(unittest.TestCase):
    def test_examples(self):
        code, out, _ = call_main(sm, [V2, "--json"])
        self.assertEqual(code, 1)
        d = json.loads(out)
        self.assertEqual(set(d), {"name", "summary", "warnings", "findings", "mermaid", "flows"})
        self.assertEqual(d["summary"]["components"], 8)
        for f in d["findings"]:
            self.assertTrue({"id", "severity", "title", "detail", "fix", "location", "kind"} <= set(f))
        self.assertIn("critical", [f["severity"] for f in d["findings"]])
        self.assertEqual(call_main(sm, [str(EX / "minimal.json")])[0], 0)
        self.assertEqual(call_main(sm, [V1, "--fail-on", "critical"])[0], 0)

    def test_mermaid_only_stdin_and_output(self):
        with open(V1, encoding="utf-8") as fh:
            text = fh.read()
        code, out, _ = call_main(sm, ["-", "--mermaid-only", "--fail-on", "never"], stdin=text)
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("flowchart LR"))
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "tm.md")
            self.assertEqual(call_main(sm, [V1, "--output", path, "--fail-on", "never"])[0], 0)
            self.assertTrue(os.path.getsize(path) > 500)

    def test_errors_exit_2(self):
        self.assertEqual(call_main(sm, ["-"], stdin="")[0], 2)
        self.assertEqual(call_main(sm, ["-"], stdin='{"components": [{"id": "a", "type": "api"}], "flows": [{"from": "a", "to": "b"}]}')[0], 2)
        self.assertEqual(call_main(sm, ["/nonexistent.yaml"])[0], 2)

    def test_help(self):
        p = run_cli("threat-modeling", "stride_model", "--help")
        self.assertEqual(p.returncode, 0)
        self.assertIn("--mermaid-only", p.stdout)


class DiffTests(unittest.TestCase):
    BASE = {"components": [USER, API, DB],
            "flows": [{"id": "login", "from": "u", "to": "api", "protocol": "https", "auth": "session", "data": "pii"},
                      {"id": "q", "from": "api", "to": "db", "protocol": "postgres+tls", "auth": "iam", "data": "pii"}]}

    def diff(self, new):
        old = sm.load_model(json.dumps(self.BASE))
        return md.diff_models(old, sm.load_model(json.dumps(new)))

    def test_no_change(self):
        r = self.diff(self.BASE)
        self.assertEqual(r["findings"], [])

    def test_new_boundary_flow(self):
        new = json.loads(json.dumps(self.BASE))
        new["flows"].append({"id": "hook", "from": "u", "to": "api", "protocol": "http", "auth": "none", "data": "pii"})
        r = self.diff(new)
        f = [x for x in r["findings"] if x["id"] == "DIFF-001"][0]
        self.assertEqual(f["severity"], "high")
        self.assertEqual(r["needs_review"], ["hook"])

    def test_new_internal_flow_is_low(self):
        new = json.loads(json.dumps(self.BASE))
        new["components"].append({"id": "job", "type": "service", "zone": "internal"})
        new["flows"].append({"id": "j", "from": "job", "to": "api", "protocol": "https", "auth": "mtls"})
        r = self.diff(new)
        self.assertEqual({(f["id"], f["severity"]) for f in r["findings"]}, {("DIFF-002", "low"), ("DIFF-004", "low")})

    def test_weakened_flow(self):
        new = json.loads(json.dumps(self.BASE))
        new["flows"][0]["auth"] = "none"
        new["flows"][1]["protocol"] = "postgres"
        r = self.diff(new)
        changed = {f["location"]: f for f in r["findings"] if f["id"] == "DIFF-003"}
        self.assertEqual(changed["flow login"]["severity"], "high")
        self.assertEqual(changed["flow q"]["severity"], "high")
        self.assertIn("encryption lost", changed["flow q"]["detail"])

    def test_zone_move_logging_and_removal(self):
        new = json.loads(json.dumps(self.BASE))
        new["components"][2] = dict(DB, zone="dmz", logging=False)
        new["flows"] = new["flows"][:1]
        found = {(f["id"], f["severity"]) for f in self.diff(new)["findings"]}
        self.assertIn(("DIFF-005", "high"), found)
        self.assertIn(("DIFF-006", "medium"), found)
        self.assertIn(("DIFF-007", "info"), found)

    def test_example_cli(self):
        code, out, _ = call_main(md, [V1, V2, "--json"])
        self.assertEqual(code, 1)
        d = json.loads(out)
        self.assertEqual(set(d), {"old", "new", "findings", "needs_review", "summary"})
        self.assertEqual(sorted(d["needs_review"]), ["api-db", "chat", "tracking"])
        for f in d["findings"]:
            self.assertTrue({"id", "severity", "title", "detail", "fix", "location", "change"} <= set(f))
        code, out, _ = call_main(md, [V1, V1])
        self.assertEqual(code, 0)
        self.assertIn("No security-relevant changes", out)
        self.assertEqual(call_main(md, [V1, V2, "--fail-on", "never"])[0], 0)

    def test_errors_exit_2(self):
        self.assertEqual(call_main(md, [V1, "/nonexistent.yaml"])[0], 2)

    def test_help(self):
        p = run_cli("threat-modeling", "model_diff", "--help")
        self.assertEqual(p.returncode, 0)
        self.assertIn("old", p.stdout)


if __name__ == "__main__":
    unittest.main()
