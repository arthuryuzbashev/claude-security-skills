import json
import unittest
from datetime import date

from _helpers import call_main, load_script, run_cli, skill_path

rr = load_script("grc-compliance", "risk_register")
cg = load_script("grc-compliance", "control_gap")
EX = skill_path("grc-compliance", "examples")
HEADER = "id,title,owner,likelihood,impact,control_effectiveness,controls,treatment,last_review,next_review,status\n"
TODAY = date(2026, 11, 19)


def register(*rows):
    risks, errors = rr.load_register(HEADER + "".join(r + "\n" for r in rows))
    return risks, errors


def ids(findings):
    return {f["id"] for f in findings}


class ScoringTests(unittest.TestCase):
    def test_bands(self):
        self.assertEqual([rr.rating(s) for s in (1, 4, 5, 9, 10, 14, 15, 25)],
                         ["low", "low", "medium", "medium", "high", "high", "critical", "critical"])

    def test_residual_from_effectiveness(self):
        risks, errors = register("R1,Ransomware,CISO,4,5,partial,EDR,mitigate,,2027-01-01,open")
        self.assertEqual(errors, [])
        self.assertEqual(risks[0]["inherent"], 20)
        self.assertEqual(risks[0]["residual"], 10.0)
        self.assertEqual(risks[0]["residual_rating"], "high")

    def test_residual_floor_and_explicit(self):
        risks, _ = register("R1,Low,CISO,1,1,strong,x,mitigate,,2027-01-01,open")
        self.assertEqual(risks[0]["residual"], 1.0)
        text = "id,title,owner,likelihood,impact,residual_likelihood,residual_impact,next_review\nR2,X,Ann,4,4,2,3,2027-01-01\n"
        risks, _ = rr.load_register(text)
        self.assertEqual(risks[0]["residual"], 6.0)
        self.assertEqual(risks[0]["residual_position"], [2, 3])

    def test_bad_score_is_error(self):
        _, errors = register("R1,X,Ann,7,2,,,mitigate,,2027-01-01,open")
        self.assertTrue(errors)


class RegisterCheckTests(unittest.TestCase):
    def test_missing_owner(self):
        risks, _ = register("R1,X,,3,3,,,mitigate,,2027-01-01,open")
        self.assertIn("RR-001", ids(rr.check(risks, TODAY)))
        risks, _ = register("R1,X,Ann,3,3,,,mitigate,,2027-01-01,open")
        self.assertNotIn("RR-001", ids(rr.check(risks, TODAY)))

    def test_overdue_review(self):
        risks, _ = register("R1,X,Ann,5,5,none,,mitigate,,2026-10-01,open")
        f = [x for x in rr.check(risks, TODAY) if x["id"] == "RR-002"]
        self.assertEqual(f[0]["severity"], "high")
        risks, _ = register("R1,X,Ann,5,5,none,,mitigate,,2026-12-01,open")
        self.assertNotIn("RR-002", ids(rr.check(risks, TODAY)))

    def test_last_review_plus_cycle(self):
        risks, _ = register("R1,X,Ann,2,2,,,mitigate,2026-01-01,,open")
        self.assertIn("RR-002", ids(rr.check(risks, TODAY)))

    def test_no_review_date(self):
        risks, _ = register("R1,X,Ann,2,2,,,mitigate,,,open")
        self.assertIn("RR-003", ids(rr.check(risks, TODAY)))

    def test_accepted_high_and_no_treatment(self):
        risks, _ = register("R1,X,Ann,4,4,none,,accept,,2027-01-01,open", "R2,Y,Ann,4,4,none,,,,2027-01-01,open")
        found = ids(rr.check(risks, TODAY))
        self.assertIn("RR-004", found)
        self.assertIn("RR-005", found)
        risks, _ = register("R1,X,Ann,2,2,none,,accept,,2027-01-01,open")
        self.assertFalse({"RR-004", "RR-005"} & ids(rr.check(risks, TODAY)))

    def test_effectiveness_without_controls(self):
        risks, _ = register("R1,X,Ann,3,3,strong,,mitigate,,2027-01-01,open")
        self.assertIn("RR-007", ids(rr.check(risks, TODAY)))

    def test_closed_rows_skipped(self):
        risks, _ = register("R1,X,,5,5,none,,,,,closed")
        self.assertEqual(rr.check(risks, TODAY), [])

    def test_acceptance_expired(self):
        head = "id,title,owner,likelihood,impact,treatment,next_review,accepted_until\n"
        risks, errors = rr.load_register(head + "R1,X,Ann,4,4,accept,2027-01-01,2026-06-30\n")
        self.assertEqual(errors, [])
        self.assertIn("RR-008", ids(rr.check(risks, TODAY)))
        risks, _ = rr.load_register(head + "R1,X,Ann,4,4,accept,2027-01-01,2027-06-30\n")
        self.assertNotIn("RR-008", ids(rr.check(risks, TODAY)))
        risks, _ = rr.load_register(head.replace("accepted_until", "acceptance_expiry") + "R1,X,Ann,4,4,accept,2027-01-01,2026-06-30\n")
        self.assertIn("RR-008", ids(rr.check(risks, TODAY)), "alias column name")

    def test_duplicate_ids(self):
        risks, _ = register("R1,X,Ann,2,2,,,mitigate,,2027-01-01,open", "R1,Y,Ann,2,2,,,mitigate,,2027-01-01,closed")
        self.assertIn("RR-009", ids(rr.check(risks, TODAY)), "closed duplicates still clash")
        risks, _ = register("R1,X,Ann,2,2,,,mitigate,,2027-01-01,open", "R2,Y,Ann,2,2,,,mitigate,,2027-01-01,open")
        self.assertNotIn("RR-009", ids(rr.check(risks, TODAY)))

    def test_treatment_overdue(self):
        head = "id,title,owner,likelihood,impact,treatment,next_review,target_date,status\n"
        risks, _ = rr.load_register(head + "R1,X,Ann,4,4,mitigate,2027-01-01,2026-09-30,open\n")
        f = [x for x in rr.check(risks, TODAY) if x["id"] == "RR-010"]
        self.assertEqual(f[0]["severity"], "medium")
        risks, _ = rr.load_register(head + "R1,X,Ann,4,4,mitigate,2027-01-01,2026-12-31,open\n")
        self.assertNotIn("RR-010", ids(rr.check(risks, TODAY)))
        risks, _ = rr.load_register(head + "R1,X,Ann,4,4,mitigate,2027-01-01,2026-09-30,closed\n")
        self.assertNotIn("RR-010", ids(rr.check(risks, TODAY)))
        _, errors = rr.load_register(head + "R1,X,Ann,4,4,mitigate,2027-01-01,soon,open\n")
        self.assertTrue(errors, "bad date is a row error")

    def test_heat_map_counts(self):
        risks, _ = register("R1,X,Ann,4,5,none,,mitigate,,2027-01-01,open", "R2,Y,Ann,4,5,none,,mitigate,,2027-01-01,open")
        grid = rr.heat_map(risks, "inherent")
        self.assertEqual(sum(map(sum, grid)), 2)


class RegisterCliTests(unittest.TestCase):
    def test_example(self):
        code, out, _ = call_main(rr, [str(EX / "risk_register.csv"), "--today", "2026-11-19", "--json"])
        self.assertEqual(code, 1)
        d = json.loads(out)
        self.assertEqual(set(d), {"summary", "risks", "findings"})
        self.assertEqual(len(d["risks"]), 8)
        for f in d["findings"]:
            self.assertTrue({"id", "severity", "title", "detail", "fix"} <= set(f))
        self.assertIn("RR-002", ids(d["findings"]))

    def test_markdown_and_fail_on_never(self):
        code, out, _ = call_main(rr, [str(EX / "risk_register.csv"), "--today", "2026-11-19", "--fail-on", "never"])
        self.assertEqual(code, 0)
        self.assertIn("R-001", out)

    def test_clean_register_exit_0(self):
        code, _, _ = call_main(rr, ["-", "--today", "2026-11-19"], stdin=HEADER + "R1,X,Ann,2,2,partial,MFA,mitigate,,2027-01-01,open\n")
        self.assertEqual(code, 0)

    def test_bad_input_exit_2(self):
        self.assertEqual(call_main(rr, ["-"], stdin=HEADER + "R1,X,Ann,9,9,,,,,,open\n")[0], 2)
        self.assertEqual(call_main(rr, ["/nonexistent.csv"])[0], 2)

    def test_help(self):
        p = run_cli("grc-compliance", "risk_register", "--help")
        self.assertEqual(p.returncode, 0)
        self.assertIn("--today", p.stdout)


class ControlGapTests(unittest.TestCase):
    def test_parse_formats(self):
        a, _ = cg.parse_answers("mfa: yes  passkeys\nbackups: partial\n")
        self.assertEqual(a["mfa"], {"answer": "yes", "note": "passkeys"})
        a, _ = cg.parse_answers("control,answer,note\nCTL-01,no,none yet\n")
        self.assertEqual(a["mfa"]["answer"], "no")
        a, w = cg.parse_answers('{"mfa": {"answer": "yes"}, "made_up": "yes"}')
        self.assertEqual(list(a), ["mfa"])
        self.assertTrue(w)

    def test_bad_answer_raises(self):
        with self.assertRaises(ValueError):
            cg.parse_answers("mfa: maybe\n")

    def test_no_answer_is_gap_with_priority(self):
        r = cg.assess({"mfa": {"answer": "no", "note": ""}}, include_unanswered=False)
        gap = [g for g in r["findings"] if g["control"] == "CTL-01"][0]
        self.assertEqual((gap["id"], gap["severity"]), ("GAP-001", "critical"))
        self.assertIn("PR.AA", gap["mappings"])

    def test_partial_is_one_step_lower(self):
        r = cg.assess({"mfa": {"answer": "partial", "note": ""}}, include_unanswered=False)
        self.assertEqual(r["findings"][0]["severity"], "high")

    def test_yes_has_no_gap_and_full_coverage(self):
        r = cg.assess({"mfa": {"answer": "yes", "note": ""}}, include_unanswered=False)
        self.assertEqual(r["findings"], [])
        self.assertIn("PR.AA", r["coverage"]["csf"]["full"])
        self.assertEqual(r["answers"]["unanswered"], len(cg.CONTROLS) - 1)

    def test_unanswered_counted_as_gaps(self):
        r = cg.assess({"mfa": {"answer": "yes", "note": ""}})
        self.assertEqual(len(r["findings"]), len(cg.CONTROLS) - 1)
        self.assertFalse(r["findings"][0]["answered"])

    def test_mapping_ids_well_formed(self):
        import re
        for c in cg.CONTROLS:
            for ref in c["csf"]:
                self.assertIn(ref, cg.CSF_CATEGORIES, c["key"])
            for ref in c["iso"]:
                self.assertRegex(ref, r"^[5-8]\.\d{1,2}$", c["key"])
            for ref in c["soc2"]:
                self.assertTrue(re.match(r"^(CC[1-9]\.\d|A1\.[1-3]|C1\.[12]|PI1\.[1-5]|P[1-8]\.\d)$", ref), (c["key"], ref))
            for ref in c["nis2"]:
                self.assertRegex(ref, r"^Art\.(20|23|21\(2\)\([a-j]\))$", c["key"])

    def test_corrected_iso_mappings(self):
        self.assertEqual(cg.BY_KEY["management_oversight"]["iso"], [], "5.35 is independent review, not management review")
        self.assertIn("8.8", cg.BY_KEY["security_testing"]["iso"])

    def test_new_controls_and_nis2_coverage(self):
        self.assertEqual(cg.BY_KEY["incident_notification"]["code"], "CTL-38")
        self.assertEqual(cg.BY_KEY["software_supply_chain"]["code"], "CTL-40")
        self.assertEqual(cg.BY_CODE["ctl-01"]["key"], "mfa", "old codes keep their numbers")
        r = cg.assess({"incident_notification": {"answer": "no", "note": ""}}, include_unanswered=False)
        self.assertIn("Art.23", r["coverage"]["nis2"]["none"])
        self.assertIn("NIS2 Art.23", r["findings"][0]["mappings"])
        r = cg.assess({"incident_notification": {"answer": "yes", "note": ""}}, include_unanswered=False)
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["coverage"]["nis2"]["coverage_pct"], 100.0)


class ControlGapCliTests(unittest.TestCase):
    def test_example_text(self):
        code, out, _ = call_main(cg, [str(EX / "control_answers.txt"), "--json"])
        self.assertEqual(code, 1)
        d = json.loads(out)
        self.assertEqual(set(d), {"disclaimer", "controls", "answers", "coverage", "findings", "warnings"})
        self.assertTrue({"csf", "iso", "soc2"} <= set(d["coverage"]), "original keys stay")
        self.assertIn("nis2", d["coverage"])
        self.assertIn("not audit advice", d["disclaimer"])
        self.assertEqual(d["answers"]["unanswered"], 0)

    def test_example_json_skip_unanswered(self):
        code, out, _ = call_main(cg, [str(EX / "control_answers.json"), "--skip-unanswered", "--json"])
        d = json.loads(out)
        self.assertEqual(d["answers"]["yes"], 3)
        self.assertEqual({g["control"] for g in d["findings"]}, {"CTL-08", "CTL-09"})
        self.assertEqual(code, 1)

    def test_text_output_has_disclaimer(self):
        code, out, _ = call_main(cg, [str(EX / "control_answers.txt"), "--fail-on", "never"])
        self.assertEqual(code, 0)
        self.assertIn("not audit advice", out)

    def test_all_yes_exit_0(self):
        code, _, _ = call_main(cg, ["-", "--skip-unanswered"], stdin="mfa: yes\nbackups: yes\n")
        self.assertEqual(code, 0)

    def test_template_and_list(self):
        code, out, _ = call_main(cg, ["--template"])
        self.assertEqual(code, 0)
        a, _ = cg.parse_answers(out)
        self.assertEqual(a, {})
        self.assertEqual(call_main(cg, ["--list"])[0], 0)

    def test_errors_exit_2(self):
        self.assertEqual(call_main(cg, [])[0], 2)
        self.assertEqual(call_main(cg, ["-"], stdin="mfa: maybe\n")[0], 2)

    def test_help(self):
        p = run_cli("grc-compliance", "control_gap", "--help")
        self.assertEqual(p.returncode, 0)
        self.assertIn("--skip-unanswered", p.stdout)


if __name__ == "__main__":
    unittest.main()
