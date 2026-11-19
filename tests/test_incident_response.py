import json
import os
import re
import tempfile
import unittest
from datetime import datetime, timezone, timedelta

from _helpers import call_main, load_script, run_cli, skill_path

tl = load_script("incident-response", "timeline_build")
tp = load_script("incident-response", "triage_plan")
EX = skill_path("incident-response", "examples")
UTC = timezone.utc
OPTS = {"year": 2026, "tz": UTC, "dayfirst": False, "time_field": None}


def at(*args):
    return datetime(*args, tzinfo=UTC)


class TimestampTests(unittest.TestCase):
    def test_iso_with_and_without_offset(self):
        self.assertEqual(tl.parse_timestamp("2026-03-04T10:00:00Z"), at(2026, 3, 4, 10))
        self.assertEqual(tl.parse_timestamp("2026-03-04 14:00:00+04:00"), at(2026, 3, 4, 10))
        self.assertEqual(tl.parse_timestamp("2026-03-04T10:00:00.250Z").microsecond, 250000)
        plus4 = timezone(timedelta(hours=4))
        self.assertEqual(tl.parse_timestamp("2026-03-04 14:00:00", default_tz=plus4), at(2026, 3, 4, 10))

    def test_epoch_units(self):
        self.assertEqual(tl.parse_timestamp(1772618400), at(2026, 3, 4, 10))
        self.assertEqual(tl.parse_timestamp("1772618400000"), at(2026, 3, 4, 10))
        self.assertEqual(tl.parse_timestamp(1772618400.5).microsecond, 500000)

    def test_syslog_clf_and_us(self):
        self.assertEqual(tl.parse_timestamp("Mar  4 10:00:00", year=2026), at(2026, 3, 4, 10))
        self.assertEqual(tl.parse_timestamp("04/Mar/2026:14:00:00 +0400"), at(2026, 3, 4, 10))
        self.assertEqual(tl.parse_timestamp("3/4/2026 10:00:00 AM"), at(2026, 3, 4, 10))
        self.assertEqual(tl.parse_timestamp("3/4/2026 12:30:00 PM"), at(2026, 3, 4, 12, 30))
        self.assertEqual(tl.parse_timestamp("4/3/2026 10:00:00", dayfirst=True), at(2026, 3, 4, 10))

    def test_garbage_is_none(self):
        for bad in ("", "hello world", None, "13/45/2026 10:00:00"):
            self.assertIsNone(tl.parse_timestamp(bad), bad)
        with self.assertRaises(tl.ParseError):
            tl.parse_offset("+4h")


class LoadingTests(unittest.TestCase):
    def test_detect_format(self):
        self.assertEqual(tl.detect_format('{"a": 1}', "x.log"), "json")
        self.assertEqual(tl.detect_format("TimeCreated,Id,Message,Host\n", "x.txt"), "csv")
        self.assertEqual(tl.detect_format("Mar  4 10:00:00 web01 sshd[1]: hi", "auth.log"), "text")

    def test_json_lines_and_cloudtrail_wrapper(self):
        text = json.dumps({"Records": [{"eventTime": "2026-03-04T10:00:00Z", "eventName": "ConsoleLogin"}]})
        events, skipped = tl.load_events(text, "ct.json", OPTS)
        self.assertEqual((len(events), skipped), (1, 0))
        self.assertIn("ConsoleLogin", events[0]["message"])
        events, skipped = tl.load_events('{"ts": 1772618400, "msg": "a"}\nnot json\n{"msg": "no time"}', "x.jsonl", OPTS)
        self.assertEqual((len(events), skipped), (1, 2))

    def test_secrets_are_masked(self):
        line = "2026-03-04T10:00:00Z curl -H 'Authorization: Bearer FAKEtoken1234567890' password=Hunter2fake"
        ev, _ = tl.load_events(line, "x.log", OPTS)
        msg = ev[0]["message"]
        self.assertNotIn("token1234567890", msg)
        self.assertNotIn("Hunter2fake", msg)
        self.assertIn("FAKE...", msg)
        self.assertEqual(tl.mask_secrets("key AKIAFAKEFAKEFAKE1234 used"), "key AKIA... used")

    def test_examples_merge_in_order(self):
        inputs = [(p.name, p.read_text()) for p in sorted(EX.iterdir())]
        events, skipped = tl.build_timeline(inputs, OPTS)
        self.assertEqual(len(events), 22)
        self.assertEqual(set(skipped.values()), {0})
        self.assertEqual(len({e["source"] for e in events}), 4)
        epochs = [e["epoch"] for e in events]
        self.assertEqual(epochs, sorted(epochs))

    def test_filters(self):
        inputs = [(p.name, p.read_text()) for p in sorted(EX.iterdir())]
        events, _ = tl.build_timeline(inputs, OPTS, keywords=["4720"])
        self.assertTrue(events)
        self.assertTrue(all("4720" in e["message"] for e in events))
        all_events, _ = tl.build_timeline(inputs, OPTS)
        mid = all_events[10]["epoch"]
        start = datetime.fromtimestamp(mid, UTC)
        later, _ = tl.build_timeline(inputs, OPTS, start=start)
        self.assertTrue(all(e["epoch"] >= mid for e in later))
        self.assertLess(len(later), len(all_events))


class TimelineCliTests(unittest.TestCase):
    def test_json_shape(self):
        files = [str(p) for p in sorted(EX.iterdir())]
        code, out, _ = call_main(tl, files + ["--year", "2026", "--format", "json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(set(data), {"count", "sources", "skipped", "events"})
        self.assertEqual(set(data["events"][0]), {"time", "epoch", "source", "host", "message", "raw_time"})
        self.assertTrue(data["events"][0]["time"].endswith("Z"))

    def test_markdown_csv_and_output_file(self):
        code, out, _ = call_main(tl, [str(EX / "auth.log"), "--year", "2026"])
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("| Time (UTC) |"))
        code, out, _ = call_main(tl, [str(EX / "auth.log"), "--year", "2026", "--format", "csv"])
        self.assertTrue(out.startswith("time_utc,source,host,message,raw_time"))
        fd, path = tempfile.mkstemp(suffix=".md")
        os.close(fd)
        self.addCleanup(os.remove, path)
        code, _, err = call_main(tl, [str(EX / "auth.log"), "--year", "2026", "--output", path])
        self.assertEqual(code, 0)
        self.assertIn("wrote", err)
        with open(path) as fh:
            self.assertIn("web01", fh.read())

    def test_error_exits(self):
        self.assertEqual(call_main(tl, ["/nonexistent/file.log"])[0], 2)
        self.assertEqual(call_main(tl, ["-"], stdin="")[0], 2)
        self.assertEqual(call_main(tl, [str(EX / "auth.log"), "--from", "not a date"])[0], 2)
        self.assertEqual(call_main(tl, [str(EX / "auth.log"), "--tz-offset", "bogus"])[0], 2)

    def test_skipped_lines_note(self):
        code, out, err = call_main(tl, ["-"], stdin="2026-03-04T10:00:00Z ok\nno time here\n")
        self.assertEqual(code, 0)
        self.assertIn("1 line(s)", err)

    def test_help_subprocess(self):
        self.assertEqual(run_cli("incident-response", "timeline_build", "--help").returncode, 0)
        p = run_cli("incident-response", "timeline_build", "-", "--format", "json",
                    stdin="2026-03-04T10:00:00Z event one\n")
        self.assertEqual(json.loads(p.stdout)["count"], 1)


class TriagePlanTests(unittest.TestCase):
    def test_every_type_and_platform_builds(self):
        for inc in tp.INCIDENTS:
            for plat in tp.PLATFORMS:
                plan = tp.build_plan(inc, plat)
                self.assertGreater(len(plan), 5)
                self.assertEqual([s["priority"] for s in plan], list(range(1, len(plan) + 1)))
                for s in plan:
                    self.assertEqual(set(s), {"priority", "phase", "title", "why", "commands", "approval"})

    def test_volatile_before_evidence_for_host_incidents(self):
        phases = [s["phase"] for s in tp.build_plan("malware", "windows")]
        self.assertIn("volatile", phases)
        self.assertLess(phases.index("volatile"), phases.index("recover"))
        self.assertEqual(phases[0], "prepare")

    def test_ransomware_contains_before_memory(self):
        phases = [s["phase"] for s in tp.build_plan("ransomware", "windows")]
        self.assertLess(phases.index("contain"), phases.index("volatile"))

    def test_bec_has_no_host_collection(self):
        phases = {s["phase"] for s in tp.build_plan("bec", "linux")}
        self.assertNotIn("volatile", phases)

    def test_state_changing_steps_need_approval(self):
        risky = re.compile(r"\b(rm -rf|shutdown|reboot|mkfs|format [a-z]:|del /|Remove-Item|iptables -F)\b", re.I)
        for inc in tp.INCIDENTS:
            for plat in tp.PLATFORMS:
                for s in tp.build_plan(inc, plat):
                    if not s["approval"]:
                        for c in s["commands"]:
                            self.assertIsNone(risky.search(c), f"{inc}/{plat}: {c}")

    def test_platform_specific_commands(self):
        win = " ".join(c for s in tp.build_plan("malware", "windows") for c in s["commands"])
        lin = " ".join(c for s in tp.build_plan("malware", "linux") for c in s["commands"])
        self.assertNotEqual(win, lin)

    def test_unknown_values_raise(self):
        with self.assertRaises(ValueError):
            tp.build_plan("alien-invasion", "linux")
        with self.assertRaises(ValueError):
            tp.build_plan("malware", "amiga")

    def test_report_skeleton(self):
        text = tp.report_skeleton("bec", "linux")
        self.assertTrue(text.startswith("# Incident report: bec"))
        self.assertIn("| Incident ID |", text)

    def test_cli(self):
        code, out, _ = call_main(tp, ["ransomware", "--platform", "windows", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(set(data), {"incident", "platform", "description", "steps"})
        code, out, _ = call_main(tp, ["--list"])
        self.assertEqual(code, 0)
        self.assertIn("lost-device", out)
        code, out, _ = call_main(tp, ["bec", "--report", "--json"])
        self.assertEqual(set(json.loads(out)), {"incident", "platform", "report"})
        self.assertEqual(call_main(tp, [])[0], 2)
        self.assertEqual(call_main(tp, ["alien-invasion"])[0], 2)
        code, out, _ = call_main(tp, ["web-compromise"])
        self.assertIn("[ ]  1.", out)

    def test_help_subprocess(self):
        self.assertEqual(run_cli("incident-response", "triage_plan", "--help").returncode, 0)


if __name__ == "__main__":
    unittest.main()
