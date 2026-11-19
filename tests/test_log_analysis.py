"""Tests for skills/log-analysis (log_triage.py, query_translate.py)."""
import json
import unittest

from _helpers import call_main, load_script, run_cli, skill_path

SKILL = "log-analysis"
EX = skill_path(SKILL, "examples")
lt = load_script(SKILL, "log_triage")
qt = load_script(SKILL, "query_translate")


def ssh_fail(sec, ip, user="root"):
    return f"Nov 19 04:{sec // 60:02d}:{sec % 60:02d} host sshd[100]: Failed password for {user} from {ip} port 4000 ssh2"


def ssh_ok(sec, ip, user="root"):
    return f"Nov 19 04:{sec // 60:02d}:{sec % 60:02d} host sshd[100]: Accepted password for {user} from {ip} port 4000 ssh2"


def web(sec, ip, path, status=200, ua="Mozilla/5.0"):
    return (f'{ip} - - [19/Nov/2026:10:{sec // 60:02d}:{sec % 60:02d} +0000] "GET {path} HTTP/1.1" '
            f'{status} 100 "-" "{ua}"')


def ids(result):
    return [f["id"] for f in result["findings"]]


class TestAuth(unittest.TestCase):
    def test_brute_force(self):
        r = lt.triage([ssh_fail(i, "203.0.113.5") for i in range(12)], year=2026)
        self.assertIn("AUTH-001", ids(r))

    def test_below_threshold_quiet(self):
        r = lt.triage([ssh_fail(i * 2, "203.0.113.5") for i in range(4)], year=2026)
        self.assertNotIn("AUTH-001", ids(r))
        self.assertNotIn("AUTH-002", ids(r))

    def test_threshold_configurable(self):
        r = lt.triage([ssh_fail(i, "203.0.113.5") for i in range(4)], cfg=lt.Config(brute_threshold=3), year=2026)
        self.assertIn("AUTH-001", ids(r))

    def test_spray(self):
        r = lt.triage([ssh_fail(i, "192.0.2.77", f"user{i}") for i in range(6)], year=2026)
        self.assertIn("AUTH-002", ids(r))

    def test_success_after_failures(self):
        lines = [ssh_fail(i, "203.0.113.50", "admin") for i in range(4)] + [ssh_ok(30, "203.0.113.50", "admin")]
        r = lt.triage(lines, year=2026)
        self.assertIn("AUTH-003", ids(r))

    def test_success_without_failures_quiet(self):
        r = lt.triage([ssh_ok(1, "198.51.100.7", "deploy")], year=2026)
        self.assertNotIn("AUTH-003", ids(r))

    def test_sudo_unexpected_and_denied(self):
        lines = [
            "Nov 19 05:00:00 host sudo:    mallory : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
            "Nov 19 05:00:05 host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update",
            "Nov 19 05:01:00 host sudo: www-data : user NOT in sudoers ; TTY=pts/2 ; PWD=/var/www ; USER=root ; COMMAND=/bin/sh",
        ]
        r = lt.triage(lines, cfg=lt.Config(sudo_users=["alice"]), year=2026)
        got = ids(r)
        self.assertIn("AUTH-004", got)
        self.assertIn("AUTH-005", got)
        unexpected = [f for f in r["findings"] if f["id"] == "AUTH-004"]
        self.assertTrue(all("alice" not in f["title"] for f in unexpected))


class TestWeb(unittest.TestCase):
    def test_scanner_ua(self):
        r = lt.triage([web(1, "192.0.2.9", "/", ua="sqlmap/1.7")])
        self.assertIn("WEB-001", ids(r))

    def test_normal_browsing_quiet(self):
        r = lt.triage([web(i, "198.51.100.20", f"/page/{i}") for i in range(10)])
        self.assertEqual(r["findings"], [])

    def test_404_burst(self):
        r = lt.triage([web(i, "192.0.2.10", f"/x{i}", 404) for i in range(25)])
        self.assertIn("WEB-002", ids(r))

    def test_sensitive_path_and_exposure(self):
        r = lt.triage([web(1, "192.0.2.11", "/.env", 404), web(2, "198.51.100.99", "/.git/config", 200)])
        self.assertIn("WEB-003", ids(r))
        self.assertIn("WEB-007", ids(r))

    def test_sqli_xss_traversal(self):
        r = lt.triage([
            web(1, "192.0.2.12", "/item?id=1%27%20UNION%20SELECT%20password%20FROM%20users--", 500),
            web(2, "192.0.2.12", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200),
            web(3, "192.0.2.12", "/download?f=../../../../etc/passwd", 400),
        ])
        got = ids(r)
        for fid in ("WEB-004", "WEB-005", "WEB-006"):
            self.assertIn(fid, got)

    def test_mask_path(self):
        self.assertEqual(lt.mask_path("/reset?token=f9a8b7c6d5e4"), "/reset?token=f9a8...")
        self.assertEqual(lt.mask_path("/a?page=2"), "/a?page=2")


class TestTriageCli(unittest.TestCase):
    def test_auth_example(self):
        code, out, _ = call_main(lt, [str(EX / "auth.log"), "--year", "2026", "--sudo-users", "alice", "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        for key in ("source", "events_parsed", "skipped_lines", "formats", "time_range", "findings", "top_talkers"):
            self.assertIn(key, data)
        got = [f["id"] for f in data["findings"]]
        for fid in ("AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004", "AUTH-005"):
            self.assertIn(fid, got)
        self.assertEqual(data["findings"][0]["severity"], "critical")
        for f in data["findings"]:
            self.assertTrue({"id", "severity", "title", "detail", "fix"} <= set(f))

    def test_access_example(self):
        code, out, _ = call_main(lt, [str(EX / "access.log"), "--json"])
        self.assertEqual(code, 1)
        got = [f["id"] for f in json.loads(out)["findings"]]
        for fid in ("WEB-001", "WEB-002", "WEB-003", "WEB-004", "WEB-005", "WEB-006", "WEB-007"):
            self.assertIn(fid, got)
        self.assertNotIn("f9a8b7c6d5e4f3a2", out)

    def test_jsonl_example(self):
        code, out, _ = call_main(lt, [str(EX / "vpn_auth.jsonl"), "--json"])
        self.assertEqual(code, 1)
        got = [f["id"] for f in json.loads(out)["findings"]]
        self.assertIn("AUTH-003", got)

    def test_json_field_mapping(self):
        lines = "\n".join(json.dumps({"t": f"2026-11-19T10:00:{i:02d}Z", "src": "203.0.113.8", "who": "bob", "res": "FAIL"})
                          for i in range(12))
        code, out, _ = call_main(lt, ["--file", "-", "--format", "json", "--field", "ts=t", "--field", "ip=src",
                                      "--field", "user=who", "--field", "outcome=res", "--json"], stdin=lines)
        self.assertIn("AUTH-001", [f["id"] for f in json.loads(out)["findings"]])

    def test_clean_example_exit_0(self):
        code, _, _ = call_main(lt, [str(EX / "clean.log"), "--year", "2026"])
        self.assertEqual(code, 0)

    def test_fail_on_never(self):
        code, _, _ = call_main(lt, [str(EX / "access.log"), "--fail-on", "never"])
        self.assertEqual(code, 0)

    def test_unparseable_exit_2(self):
        code, _, _ = call_main(lt, ["--file", "-"], stdin="hello\nworld\n")
        self.assertEqual(code, 2)

    def test_help(self):
        self.assertEqual(run_cli(SKILL, "log_triage", "--help").returncode, 0)


class TestQueryTranslate(unittest.TestCase):
    def test_every_query_lints_clean(self):
        for uc in qt.LIBRARY:
            for lang in qt.LANGS:
                q = qt.render_query(uc, lang)
                if q is None:
                    continue
                self.assertEqual(qt.lint_query(q, lang), [], f"{uc}/{lang}")

    def test_lint_catches_problems(self):
        self.assertTrue(qt.lint_query('index=auth | stats count by (src', "spl"))
        self.assertTrue(qt.lint_query('SigninLogs | where x == "open', "kql"))

    def test_threshold_and_window_applied(self):
        q = qt.render_query("ssh-brute-force", "spl", threshold=42, window=7)
        self.assertIn("42", q)
        self.assertNotIn("{threshold}", q)

    def test_library_size_and_attack(self):
        self.assertGreaterEqual(len(qt.LIBRARY), 10)
        for uc in qt.LIBRARY.values():
            for tid in uc["attack"]:
                self.assertRegex(tid, r"^T\d{4}(\.\d{3})?$")

    def test_cli_json(self):
        code, out, _ = call_main(qt, ["lsass-dump", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(set(data), {"use_case", "title", "attack", "queries"})
        self.assertEqual(set(data["queries"]), set(qt.LANGS))

    def test_missing_language_marked(self):
        code, out, _ = call_main(qt, ["password-spray", "--lang", "eql", "--json"])
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(out)["queries"]["eql"]["available"])

    def test_list_and_errors(self):
        self.assertEqual(call_main(qt, ["--list"])[0], 0)
        self.assertEqual(call_main(qt, [])[0], 2)
        self.assertEqual(call_main(qt, ["no-such-case"])[0], 2)
        self.assertEqual(call_main(qt, ["ssh-brute-force", "--threshold", "0"])[0], 2)

    def test_help(self):
        self.assertEqual(run_cli(SKILL, "query_translate", "--help").returncode, 0)


if __name__ == "__main__":
    unittest.main()
