"""Tests for skills/detection-engineering (sigma_lint.py, detection_test.py)."""
import json
import os
import tempfile
import unittest

from _helpers import call_main, load_script, run_cli, skill_path

SKILL = "detection-engineering"
EX = skill_path(SKILL, "examples")
sl = load_script(SKILL, "sigma_lint")
dt = load_script(SKILL, "detection_test")

GOOD = """
title: Test Rule
id: 0b6c2f2e-6a59-4c1e-9d4f-2f1c7b0a9e11
status: experimental
description: test
date: 2026-11-19
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -ec '
  filter:
    User: 'NT AUTHORITY\\SYSTEM'
  condition: selection and not filter
falsepositives:
  - Admin scripts
level: high
"""


def lint(text):
    return [f["id"] for f in sl.lint_rule(sl.load_yaml_docs(text)[0])]


def with_line(text, old, new):
    assert old in text, old
    return text.replace(old, new)


class TestYamlReader(unittest.TestCase):
    def test_nested_structures(self):
        doc = sl.load_yaml_docs(GOOD)[0]
        self.assertEqual(doc["logsource"], {"category": "process_creation", "product": "windows"})
        self.assertEqual(doc["detection"]["selection"]["CommandLine|contains"], [" -enc ", " -ec "])
        self.assertEqual(doc["detection"]["selection"]["Image|endswith"], "\\powershell.exe")
        self.assertEqual(doc["tags"], ["attack.execution", "attack.t1059.001"])

    def test_list_of_maps_flow_list_block_scalar_comments(self):
        text = ("a:\n  - x|endswith: '.exe'\n    y: 1\n  - z: [b, 'c, d']\n"
                "desc: |\n  line one\n  line two\nk: v  # comment\nn: null\n")
        doc = sl.load_yaml_docs(text)[0]
        self.assertEqual(doc["a"], [{"x|endswith": ".exe", "y": 1}, {"z": ["b", "c, d"]}])
        self.assertEqual(doc["desc"], "line one\nline two")
        self.assertEqual(doc["k"], "v")
        self.assertIsNone(doc["n"])

    def test_multi_document(self):
        self.assertEqual(len(sl.load_yaml_docs("a: 1\n---\nb: 2\n")), 2)

    def test_bad_indentation_raises(self):
        with self.assertRaises(sl.YamlError):
            sl.load_yaml_docs("a: 1\n    b: 2\n")


class TestLintChecks(unittest.TestCase):
    def test_good_rule_clean(self):
        self.assertEqual(lint(GOOD), [])

    def test_missing_title(self):
        self.assertIn("SIG-001", lint(with_line(GOOD, "title: Test Rule\n", "")))

    def test_bad_id(self):
        self.assertIn("SIG-002", lint(with_line(GOOD, "id: 0b6c2f2e-6a59-4c1e-9d4f-2f1c7b0a9e11", "id: 42")))

    def test_bad_status_and_level(self):
        got = lint(with_line(with_line(GOOD, "status: experimental", "status: prod"), "level: high", "level: severe"))
        self.assertIn("SIG-010", got)
        self.assertIn("SIG-011", got)

    def test_undefined_selection(self):
        self.assertIn("SIG-020", lint(with_line(GOOD, "not filter", "not filters")))

    def test_pattern_matches_nothing(self):
        self.assertIn("SIG-020", lint(with_line(GOOD, "selection and not filter", "1 of sel_* and not filter")))

    def test_pattern_and_them_count_as_use(self):
        got = lint(with_line(GOOD, "selection and not filter", "1 of them"))
        self.assertNotIn("SIG-020", got)
        self.assertNotIn("SIG-024", got)

    def test_unused_selection(self):
        self.assertIn("SIG-024", lint(with_line(GOOD, "selection and not filter", "selection")))

    def test_bad_tags(self):
        got = lint(with_line(GOOD, "attack.t1059.001", "attack.T1059.001"))
        self.assertIn("SIG-030", got)
        self.assertIn("SIG-031", lint(with_line(GOOD, "  - attack.execution\n", "  - execution\n")))

    def test_valid_tag_forms(self):
        text = with_line(GOOD, "  - attack.execution\n", "  - attack.execution\n  - attack.g0016\n  - attack.s0002\n  - cve.2021-44228\n")
        self.assertEqual(lint(text), [])

    def test_falsepositives_missing(self):
        self.assertIn("SIG-040", lint(with_line(GOOD, "falsepositives:\n  - Admin scripts\n", "")))

    def test_dates(self):
        old = [f for f in sl.lint_rule(sl.load_yaml_docs(with_line(GOOD, "2026-11-19", "2026/11/19"))[0]) if f["id"] == "SIG-050"]
        self.assertEqual(old[0]["severity"], "low")
        bad = [f for f in sl.lint_rule(sl.load_yaml_docs(with_line(GOOD, "2026-11-19", "2026-13-40"))[0]) if f["id"] == "SIG-050"]
        self.assertEqual(bad[0]["severity"], "medium")

    def test_logsource_empty(self):
        self.assertIn("SIG-060", lint(with_line(GOOD, "  category: process_creation\n  product: windows\n", "  definition: x\n")))

    def test_unknown_modifier_and_bad_regex(self):
        self.assertIn("SIG-070", lint(with_line(GOOD, "Image|endswith", "Image|endwith")))
        self.assertIn("SIG-071", lint(with_line(GOOD, "Image|endswith: '\\powershell.exe'", "Image|re: '(unclosed'")))

    def test_missing_condition(self):
        self.assertIn("SIG-021", lint(with_line(GOOD, "  condition: selection and not filter\n", "")))

    def test_json_rule(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "r.json")
            with open(p, "w") as fh:
                json.dump(sl.load_yaml_docs(GOOD)[0], fh)
            res = sl.lint_paths([p])
        self.assertEqual(res["rules"][0]["findings"], [])

    def test_duplicate_id_across_files(self):
        with tempfile.TemporaryDirectory() as d:
            for n in ("a.yml", "b.yml"):
                with open(os.path.join(d, n), "w") as fh:
                    fh.write(GOOD)
            res = sl.lint_paths([d])
        self.assertIn("SIG-003", [f["id"] for r in res["rules"] for f in r["findings"]])


class TestLintCli(unittest.TestCase):
    def test_example_rules_clean(self):
        code, out, _ = call_main(sl, [str(EX / "rules"), "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(len(data["rules"]), 3)
        self.assertEqual(set(data["summary"]), {"info", "low", "medium", "high", "critical"})
        self.assertTrue(all(r["findings"] == [] for r in data["rules"]))

    def test_bad_rule(self):
        code, out, _ = call_main(sl, [str(EX / "bad_rule.yml"), "--json"])
        self.assertEqual(code, 1)
        findings = json.loads(out)["rules"][0]["findings"]
        got = {f["id"] for f in findings}
        for fid in ("SIG-002", "SIG-010", "SIG-011", "SIG-020", "SIG-024", "SIG-030", "SIG-040", "SIG-050", "SIG-070"):
            self.assertIn(fid, got)
        for f in findings:
            self.assertTrue({"id", "severity", "title", "detail", "fix"} <= set(f))

    def test_fail_on_levels(self):
        self.assertEqual(call_main(sl, [str(EX / "bad_rule.yml"), "--fail-on", "never"])[0], 0)
        self.assertEqual(call_main(sl, [str(EX / "rules"), "--fail-on", "info"])[0], 0)

    def test_parse_error_and_missing(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "broken.yml")
            with open(p, "w") as fh:
                fh.write("title: x\n   bad: indent\n")
            code, out, _ = call_main(sl, [p, "--json"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["rules"][0]["findings"][0]["id"], "SIG-000")
        self.assertEqual(call_main(sl, [str(EX / "nope.yml")])[0], 2)

    def test_help(self):
        self.assertEqual(run_cli(SKILL, "sigma_lint", "--help").returncode, 0)


def rule(detection_yaml):
    return dt.compile_rule(sl.load_yaml_docs("title: t\nlogsource:\n  product: x\ndetection:\n" + detection_yaml)[0])


def hit(compiled, event):
    return dt.match_event(compiled, event)["match"]


class TestMatching(unittest.TestCase):
    def test_contains_startswith_endswith_case_insensitive(self):
        r = rule("  sel:\n    Image|endswith: '\\cmd.exe'\n    CommandLine|startswith: 'CMD'\n    User|contains: admin\n  condition: sel\n")
        self.assertTrue(hit(r, {"Image": "C:\\Windows\\CMD.EXE", "CommandLine": "cmd /c dir", "User": "CORP\\Admin1"}))
        self.assertFalse(hit(r, {"Image": "C:\\Windows\\cmd.exe.bak", "CommandLine": "cmd /c dir", "User": "CORP\\Admin1"}))

    def test_list_is_or_keys_are_and(self):
        r = rule("  sel:\n    A: [x, y]\n    B: z\n  condition: sel\n")
        self.assertTrue(hit(r, {"A": "y", "B": "z"}))
        self.assertFalse(hit(r, {"A": "y", "B": "q"}))
        self.assertFalse(hit(r, {"A": "w", "B": "z"}))

    def test_all_modifier(self):
        r = rule("  sel:\n    C|contains|all: [comsvcs, minidump]\n  condition: sel\n")
        self.assertTrue(hit(r, {"C": "comsvcs.dll, MiniDump 1"}))
        self.assertFalse(hit(r, {"C": "comsvcs.dll only"}))

    def test_regex_is_case_sensitive_unless_i(self):
        r = rule("  sel:\n    C|re: 'ab+c'\n  condition: sel\n")
        self.assertTrue(hit(r, {"C": "xxabbbc"}))
        self.assertFalse(hit(r, {"C": "ABBC"}))
        ri = rule("  sel:\n    C|re|i: 'ab+c'\n  condition: sel\n")
        self.assertTrue(hit(ri, {"C": "ABBC"}))

    def test_wildcards_and_null_and_exists(self):
        # Sigma: a backslash right before a wildcard escapes it, so a literal backslash
        # followed by a wildcard is written as two backslashes.
        r = rule("  sel:\n    P: 'C:\\Users\\\\*\\AppData\\\\?pp.exe'\n  condition: sel\n")
        self.assertTrue(hit(r, {"P": "C:\\Users\\bob\\AppData\\app.exe"}))
        lit = rule("  sel:\n    P: 'a\\*b'\n  condition: sel\n")
        self.assertTrue(hit(lit, {"P": "a*b"}))
        self.assertFalse(hit(lit, {"P": "axxb"}))
        n = rule("  sel:\n    Parent: null\n  condition: sel\n")
        self.assertTrue(hit(n, {"Other": 1}))
        self.assertFalse(hit(n, {"Parent": "x"}))
        e = rule("  sel:\n    Parent|exists: true\n  condition: sel\n")
        self.assertTrue(hit(e, {"Parent": "x"}))
        self.assertFalse(hit(e, {}))

    def test_dotted_fields_and_keywords(self):
        r = rule("  sel:\n    process.name: bash\n  kw:\n    - 'nc -e'\n  condition: sel and kw\n")
        self.assertTrue(hit(r, {"process": {"name": "bash"}, "message": "ran nc -e /bin/sh"}))
        self.assertFalse(hit(r, {"process": {"name": "bash"}, "message": "ls"}))

    def test_condition_forms(self):
        sels = "  selection_a:\n    A: 1\n  selection_b:\n    B: 1\n  filter_x:\n    X: 1\n"
        one = rule(sels + "  condition: 1 of selection_* and not filter_x\n")
        allof = rule(sels + "  condition: all of selection_*\n")
        paren = rule(sels + "  condition: (selection_a or selection_b) and not filter_x\n")
        them = rule(sels + "  condition: all of them\n")
        self.assertTrue(hit(one, {"A": 1}))
        self.assertFalse(hit(one, {"A": 1, "X": 1}))
        self.assertFalse(hit(allof, {"A": 1}))
        self.assertTrue(hit(allof, {"A": 1, "B": 1}))
        self.assertTrue(hit(paren, {"B": 1}))
        self.assertTrue(hit(them, {"A": 1, "B": 1, "X": 1}))
        self.assertFalse(hit(them, {"A": 1, "B": 1}))

    def test_precedence_not_and_or(self):
        r = rule("  a:\n    A: 1\n  b:\n    B: 1\n  c:\n    C: 1\n  condition: a or b and not c\n")
        self.assertTrue(hit(r, {"A": 1, "B": 1, "C": 1}))   # a or (b and not c)
        self.assertFalse(hit(r, {"B": 1, "C": 1}))

    def test_errors(self):
        with self.assertRaises(dt.RuleError):
            rule("  sel:\n    A: 1\n  condition: sel | count() > 5\n")
        with self.assertRaises(dt.RuleError):
            rule("  sel:\n    A: 1\n  condition: sel and missing\n")
        with self.assertRaises(dt.RuleError):
            hit(rule("  sel:\n    A|windash: '-x'\n  condition: sel\n"), {"A": "-x"})


class TestDetectionCli(unittest.TestCase):
    def test_examples(self):
        code, out, _ = call_main(dt, [str(EX / "rules"), "--events", str(EX / "events.jsonl"), "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["events"], 10)
        lines = {r["title"]: [m["line"] for m in r["matches"]] for r in data["rules"]}
        self.assertEqual(lines["PowerShell Started With an Encoded Command"], [1])
        self.assertEqual(lines["LSASS Memory Dump With comsvcs.dll or ProcDump"], [4, 6])
        self.assertEqual(lines["Scheduled Task Created From a User-Writable Path"], [8])
        m = data["rules"][0]["matches"][0]
        self.assertEqual(set(m), {"line", "selections", "summary"})

    def test_expect_pass_and_fail(self):
        lsass = str(EX / "rules" / "proc_creation_win_lsass_dump_tools.yml")
        ev = str(EX / "events.jsonl")
        self.assertEqual(call_main(dt, [lsass, "--events", ev, "--expect", "4,6"])[0], 0)
        code, out, _ = call_main(dt, [lsass, "--events", ev, "--expect", "4"])
        self.assertEqual(code, 1)
        self.assertIn("FAIL", out)

    def test_stdin_events(self):
        rule_path = str(EX / "rules" / "proc_creation_win_schtasks_create.yml")
        ev = json.dumps({"Image": "C:\\Windows\\System32\\schtasks.exe", "User": "CORP\\x",
                         "CommandLine": "schtasks /create /tr C:\\Users\\Public\\a.exe"})
        code, out, _ = call_main(dt, [rule_path, "--events", "-", "--expect", "1"], stdin=ev + "\n")
        self.assertEqual(code, 0)

    def test_bad_inputs_exit_2(self):
        rule_path = str(EX / "rules" / "proc_creation_win_schtasks_create.yml")
        self.assertEqual(call_main(dt, [rule_path, "--events", "-"], stdin="not json\n")[0], 2)
        self.assertEqual(call_main(dt, [rule_path, "--events", str(EX / "missing.jsonl")])[0], 2)
        self.assertEqual(call_main(dt, [str(EX / "bad_rule.yml"), "--events", str(EX / "events.jsonl")])[0], 2)
        self.assertEqual(call_main(dt, [rule_path, "--events", str(EX / "events.jsonl"), "--expect", "x"])[0], 2)

    def test_help(self):
        self.assertEqual(run_cli(SKILL, "detection_test", "--help").returncode, 0)


if __name__ == "__main__":
    unittest.main()
