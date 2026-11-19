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


CORR = """
title: Brute force burst
id: 2f1a6e0c-0b7d-4c55-9a2e-6d3f00000002
status: test
level: high
description: Ten or more failed logons per source in ten minutes.
correlation:
  type: event_count
  rules:
    - failed_logon
  group-by:
    - IpAddress
  timespan: 10m
  condition:
    gte: 10
falsepositives:
  - Misconfigured service accounts
tags:
  - attack.credential-access
  - attack.t1110.001
date: 2026-11-19
"""

FILTER = """
title: Filter admin accounts
id: 2f1a6e0c-0b7d-4c55-9a2e-6d3f00000004
logsource:
  category: process_creation
  product: windows
filter:
  rules:
    - 0b6c2f2e-6a59-4c1e-9d4f-2f1c7b0a9e11
  selection:
    User|startswith: 'adm_'
  condition: selection
date: 2026-11-19
description: test
"""


class TestAttackTagsV20(unittest.TestCase):
    def test_new_tactic_tags_accepted(self):
        text = with_line(GOOD, "  - attack.execution\n", "  - attack.execution\n  - attack.stealth\n  - attack.defense-impairment\n  - attack.t1685\n")
        self.assertEqual(lint(text), [])

    def test_legacy_defense_evasion(self):
        got = [f for f in sl.lint_rule(sl.load_yaml_docs(with_line(GOOD, "attack.execution", "attack.defense-evasion"))[0]) if f["id"] == "SIG-033"]
        self.assertEqual(got[0]["severity"], "low")
        self.assertNotIn("SIG-030", lint(with_line(GOOD, "attack.execution", "attack.defense-evasion")))

    def test_revoked_technique(self):
        f = [x for x in sl.lint_rule(sl.load_yaml_docs(with_line(GOOD, "attack.t1059.001", "attack.t1562.001"))[0]) if x["id"] == "SIG-034"]
        self.assertEqual(f[0]["severity"], "medium")
        self.assertIn("T1685", f[0]["detail"])
        self.assertIn("attack.t1685", f[0]["fix"])

    def test_deprecated_and_unknown_technique(self):
        self.assertIn("SIG-034", lint(with_line(GOOD, "attack.t1059.001", "attack.t1053.004")))
        self.assertIn("SIG-035", lint(with_line(GOOD, "attack.t1059.001", "attack.t1999")))
        self.assertNotIn("SIG-035", lint(with_line(GOOD, "attack.t1059.001", "attack.t1621")))


class TestModifierValues(unittest.TestCase):
    def sel(self, line):
        return lint(with_line(GOOD, "    Image|endswith: '\\powershell.exe'\n", line + "\n"))

    def test_good_values_clean(self):
        for line in ("    CommandLine|windash|contains: '-enc'", "    DestinationIp|cidr: '10.0.0.0/8'",
                     "    Port|gte: 1024", "    EventTime|hour: 23", "    User|exists: true",
                     "    Image|re|i: 'power.*'", "    CommandLine|contains|all:\n      - 'a'\n      - 'b'"):
            self.assertEqual(self.sel(line), [], line)

    def test_all_single_value(self):
        self.assertIn("SIG-072", self.sel("    CommandLine|contains|all: 'a'"))

    def test_flag_without_re(self):
        self.assertIn("SIG-073", self.sel("    Image|i: 'power'"))

    def test_numeric_and_time(self):
        self.assertIn("SIG-074", self.sel("    Port|gt: 'high'"))
        self.assertIn("SIG-074", self.sel("    EventTime|minute: 60"))
        self.assertNotIn("SIG-070", self.sel("    EventTime|minute: 30"))

    def test_bad_cidr(self):
        self.assertIn("SIG-075", self.sel("    DestinationIp|cidr: '10.0.0.0/33'"))

    def test_exists_needs_bool(self):
        self.assertIn("SIG-076", self.sel("    User|exists: 'yes'"))

    def test_re_with_string_modifier(self):
        self.assertIn("SIG-077", self.sel("    Image|re|contains: 'a.*b'"))

    def test_related(self):
        good = GOOD + "related:\n  - id: 0b6c2f2e-6a59-4c1e-9d4f-2f1c7b0a9e12\n    type: derived\n"
        self.assertEqual(lint(good), [])
        self.assertIn("SIG-013", lint(good.replace("type: derived", "type: copied")))


class TestCorrelationAndFilter(unittest.TestCase):
    def test_good_correlation_clean(self):
        self.assertEqual(lint(CORR), [])

    def test_correlation_type_rules_timespan(self):
        self.assertIn("SIG-080", lint(with_line(CORR, "type: event_count", "type: count")))
        self.assertIn("SIG-081", lint(with_line(CORR, "  rules:\n    - failed_logon\n", "")))
        self.assertIn("SIG-082", lint(with_line(CORR, "timespan: 10m", "timespan: 1h30m")))
        self.assertIn("SIG-082", lint(with_line(CORR, "  timespan: 10m\n", "")))

    def test_correlation_condition(self):
        self.assertIn("SIG-083", lint(with_line(CORR, "gte: 10", "above: 10")))
        self.assertIn("SIG-083", lint(with_line(CORR, "gte: 10", "gte: ten")))
        self.assertIn("SIG-083", lint(with_line(CORR, "  condition:\n    gte: 10\n", "")))
        self.assertNotIn("SIG-083", lint(with_line(CORR, "gte: 10", "gt: 10\n    lte: 200")))

    def test_value_count_needs_field(self):
        vc = with_line(CORR, "type: event_count", "type: value_count")
        self.assertIn("SIG-084", lint(vc))
        self.assertNotIn("SIG-084", lint(with_line(vc, "gte: 10", "field: TargetUserName\n    gte: 10")))

    def test_temporal(self):
        t = with_line(with_line(CORR, "type: event_count", "type: temporal"), "  condition:\n    gte: 10\n", "")
        self.assertIn("SIG-086", lint(t))
        self.assertNotIn("SIG-083", lint(t))
        self.assertNotIn("SIG-086", lint(with_line(t, "    - failed_logon\n", "    - failed_logon\n    - good_logon\n")))

    def test_group_by_and_detection(self):
        self.assertIn("SIG-085", lint(with_line(CORR, "  group-by:\n    - IpAddress\n", "")))
        self.assertIn("SIG-087", lint(CORR + "detection:\n  sel:\n    A: 1\n  condition: sel\n"))

    def test_filter_rule(self):
        self.assertEqual(lint(FILTER), [])
        self.assertIn("SIG-090", lint(with_line(FILTER, "  rules:\n    - 0b6c2f2e-6a59-4c1e-9d4f-2f1c7b0a9e11\n", "")))
        self.assertIn("SIG-020", lint(with_line(FILTER, "condition: selection", "condition: sel")))

    def test_reference_check_across_files(self):
        with tempfile.TemporaryDirectory() as d:
            for name, text in (("base.yml", GOOD), ("corr.yml", CORR), ("flt.yml", FILTER)):
                with open(os.path.join(d, name), "w") as fh:
                    fh.write(text)
            res = sl.lint_paths([d])
        by_file = {os.path.basename(r["file"]): [f["id"] for f in r["findings"]] for r in res["rules"]}
        self.assertIn("SIG-088", by_file["corr.yml"])
        self.assertNotIn("SIG-088", by_file["flt.yml"])


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
            hit(rule("  sel:\n    A|base64offset: 'x'\n  condition: sel\n"), {"A": "-x"})
        with self.assertRaises(dt.RuleError):
            hit(rule("  sel:\n    A|cidr: '10.0.0.0/33'\n  condition: sel\n"), {"A": "10.0.0.1"})
        with self.assertRaises(dt.RuleError):
            dt.compile_rule(sl.load_yaml_docs(CORR)[0])

    def test_windash(self):
        r = rule("  sel:\n    CommandLine|windash|contains: ' -enc '\n  condition: sel\n")
        self.assertTrue(hit(r, {"CommandLine": "powershell -enc AAAA"}))
        self.assertTrue(hit(r, {"CommandLine": "powershell /enc AAAA"}))
        self.assertTrue(hit(r, {"CommandLine": "powershell \u2013enc AAAA"}))
        self.assertFalse(hit(r, {"CommandLine": "powershell enc AAAA"}))

    def test_cidr(self):
        r = rule("  sel:\n    DestinationIp|cidr:\n      - '10.0.0.0/8'\n      - '2001:db8::/32'\n  condition: sel\n")
        self.assertTrue(hit(r, {"DestinationIp": "10.20.30.40"}))
        self.assertTrue(hit(r, {"DestinationIp": "2001:db8::5"}))
        self.assertFalse(hit(r, {"DestinationIp": "192.0.2.10"}))
        self.assertFalse(hit(r, {"DestinationIp": "not-an-ip"}))

    def test_numeric_modifiers(self):
        r = rule("  sel:\n    Port|gte: 1024\n    Bytes|lt: 500\n  condition: sel\n")
        self.assertTrue(hit(r, {"Port": 1024, "Bytes": "499"}))
        self.assertFalse(hit(r, {"Port": 80, "Bytes": 10}))
        self.assertFalse(hit(r, {"Port": "high", "Bytes": 10}))

    def test_neq(self):
        r = rule("  sel:\n    User|neq:\n      - 'svc_backup'\n      - 'SYSTEM'\n  condition: sel\n")
        self.assertTrue(hit(r, {"User": "alice"}))
        self.assertFalse(hit(r, {"User": "svc_backup"}))
        self.assertFalse(hit(r, {"User": "system"}))
        self.assertFalse(hit(r, {"Other": "x"}))


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
