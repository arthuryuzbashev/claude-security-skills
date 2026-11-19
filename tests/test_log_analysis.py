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


def ct(name, who="bob", itype="IAMUser", t="2026-11-19T08:00:00Z", ip="203.0.113.9", **kw):
    ident = {"type": itype, "arn": "arn:aws:iam::111122223333:" + ("root" if itype == "Root" else "user/" + who)}
    if itype != "Root":
        ident["userName"] = who
    rec = {"eventVersion": "1.10", "eventTime": t, "eventSource": kw.pop("source", "iam.amazonaws.com"),
           "eventName": name, "userIdentity": ident, "sourceIPAddress": ip}
    rec.update(kw)
    return json.dumps(rec)


def login(itype="IAMUser", mfa="No", ok=True, who="bob"):
    return ct("ConsoleLogin", who=who, itype=itype, source="signin.amazonaws.com",
              responseElements={"ConsoleLogin": "Success" if ok else "Failure"},
              additionalEventData={"MFAUsed": mfa})


def signin(user, code, t="2026-11-19T12:00:00Z", ip="198.51.100.7", proto="none"):
    return json.dumps({"TimeGenerated": t, "UserPrincipalName": user, "IPAddress": ip, "ResultType": str(code),
                       "AppDisplayName": "Office 365 Exchange Online", "AuthenticationProtocol": proto})


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


class TestCloudTrail(unittest.TestCase):
    def test_root_login(self):
        r = lt.triage([login("Root", "No")])
        f = [x for x in r["findings"] if x["id"] == "CLOUD-001"]
        self.assertEqual(f[0]["severity"], "critical")
        self.assertEqual(lt.triage([login("Root", "Yes")])["findings"][0]["severity"], "high")
        self.assertNotIn("CLOUD-001", ids(lt.triage([login("Root", "No", ok=False)])))

    def test_console_without_mfa(self):
        self.assertIn("CLOUD-002", ids(lt.triage([login("IAMUser", "No")])))
        self.assertNotIn("CLOUD-002", ids(lt.triage([login("IAMUser", "Yes")])))

    def test_trail_tampering(self):
        r = lt.triage([ct("StopLogging", source="cloudtrail.amazonaws.com", requestParameters={"name": "org-trail"})])
        self.assertEqual([(f["id"], f["severity"]) for f in r["findings"]], [("CLOUD-003", "high")])
        failed = lt.triage([ct("DeleteTrail", source="cloudtrail.amazonaws.com", errorCode="AccessDenied")])
        self.assertEqual(failed["findings"][0]["severity"], "medium")
        self.assertEqual(ids(lt.triage([ct("GetTrailStatus", source="cloudtrail.amazonaws.com")])), [])

    def test_new_access_key(self):
        other = lt.triage([ct("CreateAccessKey", requestParameters={"userName": "ci-deploy"})])
        self.assertEqual(other["findings"][0]["severity"], "medium")
        self.assertIn("ci-deploy", other["findings"][0]["title"])
        self_made = lt.triage([ct("CreateAccessKey", requestParameters={"userName": "bob"})])
        self.assertEqual(self_made["findings"][0]["severity"], "low")
        self.assertEqual(ids(lt.triage([ct("CreateAccessKey", errorCode="AccessDenied")])), [])
        self.assertEqual(ids(lt.triage([ct("ListAccessKeys")])), [])

    def test_denied_burst(self):
        burst = [ct("ListUsers", who="build-bot", t=f"2026-11-19T09:30:{i:02d}Z", errorCode="AccessDenied") for i in range(10)]
        self.assertIn("CLOUD-007", ids(lt.triage(burst)))
        self.assertNotIn("CLOUD-007", ids(lt.triage(burst[:9])))
        spread = [ct("ListUsers", who="build-bot", t=f"2026-11-19T{9 + i}:00:00Z", errorCode="AccessDenied") for i in range(10)]
        self.assertNotIn("CLOUD-007", ids(lt.triage(spread)))

    def test_records_wrapper_and_console_failures_feed_auth(self):
        rec = json.loads(ct("ListBuckets", source="s3.amazonaws.com"))
        r = lt.triage([json.dumps({"Records": [rec, rec]})])
        self.assertEqual(r["events_parsed"], 2)
        self.assertEqual(r["formats"], {"cloudtrail": 2})
        fails = [ct("ConsoleLogin", who=f"user{i}", source="signin.amazonaws.com", t=f"2026-11-19T08:00:{i:02d}Z",
                    responseElements={"ConsoleLogin": "Failure"}, errorMessage="Failed authentication") for i in range(6)]
        self.assertIn("AUTH-002", ids(lt.triage(fails)))

    def test_example_file(self):
        code, out, _ = call_main(lt, [str(EX / "cloudtrail.jsonl"), "--json"])
        self.assertEqual(code, 1)
        got = ids(json.loads(out))
        for fid in ("CLOUD-001", "CLOUD-002", "CLOUD-003", "CLOUD-004", "CLOUD-007"):
            self.assertIn(fid, got)
        self.assertEqual(json.loads(out)["findings"][0]["id"], "CLOUD-001")


class TestEntra(unittest.TestCase):
    def test_mfa_fatigue(self):
        denials = [signin("j.doe@example.com", 500121, t=f"2026-11-19T12:0{i}:00Z") for i in range(3)]
        r = lt.triage(denials)
        self.assertEqual([(f["id"], f["severity"]) for f in r["findings"]], [("CLOUD-005", "high")])
        r = lt.triage(denials + [signin("j.doe@example.com", 0, t="2026-11-19T12:05:00Z")])
        self.assertEqual(r["findings"][0]["severity"], "critical")
        self.assertNotIn("CLOUD-005", ids(lt.triage(denials[:2])))

    def test_mfa_threshold_flag(self):
        lines = "\n".join(signin("j.doe@example.com", 500121, t=f"2026-11-19T12:0{i}:00Z") for i in range(3))
        code, out, _ = call_main(lt, ["--file", "-", "--mfa-threshold", "5", "--json"], stdin=lines)
        self.assertNotIn("CLOUD-005", ids(json.loads(out)))
        self.assertEqual(code, 0)

    def test_normal_mfa_interrupt_quiet(self):
        r = lt.triage([signin("m.ross@example.com", 50074, t="2026-11-19T12:00:00Z") for _ in range(4)]
                      + [signin("m.ross@example.com", 0, t="2026-11-19T12:00:30Z")])
        self.assertEqual(ids(r), [])

    def test_device_code(self):
        self.assertIn("CLOUD-006", ids(lt.triage([signin("k.lee@example.com", 0, proto="deviceCode")])))
        self.assertNotIn("CLOUD-006", ids(lt.triage([signin("k.lee@example.com", 50126, proto="deviceCode")])))
        self.assertNotIn("CLOUD-006", ids(lt.triage([signin("k.lee@example.com", 0, proto="oAuth2")])))

    def test_spray_from_failure_codes(self):
        lines = [signin(f"u{i}@example.com", 50126, t=f"2026-11-19T13:00:{i:02d}Z", ip="203.0.113.50") for i in range(6)]
        self.assertIn("AUTH-002", ids(lt.triage(lines)))
        blocked = [signin(f"u{i}@example.com", 53003, t=f"2026-11-19T13:00:{i:02d}Z", ip="203.0.113.50") for i in range(6)]
        self.assertNotIn("AUTH-002", ids(lt.triage(blocked)))

    def test_graph_and_diagnostic_shapes(self):
        graph = json.dumps({"value": [{"createdDateTime": "2026-11-19T12:00:00Z", "userPrincipalName": "a@example.com",
                                       "ipAddress": "198.51.100.1", "status": {"errorCode": 500121}}] * 3})
        self.assertIn("CLOUD-005", ids(lt.triage([graph])))
        diag = json.dumps({"time": "2026-11-19T12:00:00Z", "category": "SignInLogs", "resultType": "0",
                           "callerIpAddress": "198.51.100.2",
                           "properties": {"userPrincipalName": "b@example.com", "authenticationProtocol": "deviceCode"}})
        r = lt.triage([diag])
        self.assertEqual(r["formats"], {"entra": 1})
        self.assertIn("CLOUD-006", ids(r))

    def test_example_file(self):
        code, out, _ = call_main(lt, [str(EX / "entra_signins.jsonl"), "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data["findings"][0]["id"], "CLOUD-005")
        self.assertEqual(data["findings"][0]["severity"], "critical")
        self.assertEqual(sorted(set(ids(data))), ["AUTH-002", "CLOUD-005", "CLOUD-006"])


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
        self.assertGreaterEqual(len(qt.LIBRARY), 17)
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

    def test_v20_attack_ids(self):
        self.assertEqual(qt.LIBRARY["log-cleared"]["attack"], ["T1685.005"])
        for uc in qt.LIBRARY.values():
            self.assertNotIn("T1070.001", uc["attack"])
            self.assertNotIn("T1562.008", uc["attack"])

    def test_identity_and_cloud_use_cases(self):
        for name, tid in (("mfa-fatigue", "T1621"), ("oauth-consent", "T1528"), ("device-code-signin", "T1528"),
                          ("entra-password-spray", "T1110.003"), ("aws-console-login-risk", "T1078.004"),
                          ("cloudtrail-tampering", "T1685.002"), ("aws-access-key-created", "T1098.001")):
            self.assertIn(tid, qt.LIBRARY[name]["attack"], name)
        self.assertIn('ResultType in ("500121", "0")', qt.render_query("mfa-fatigue", "kql"))
        self.assertIn("StopLogging", qt.render_query("cloudtrail-tampering", "kql"))
        self.assertIn('AuthenticationProtocol == "deviceCode"', qt.render_query("device-code-signin", "kql"))

    def test_eql_runs_cap(self):
        ok = qt.build("ssh-brute-force", ["eql"], threshold=100)["queries"]["eql"]
        self.assertTrue(ok["available"])
        self.assertNotIn("note", ok)
        self.assertIn("runs=100", ok["query"])
        too_many = qt.build("ssh-brute-force", ["eql", "esql"], threshold=101)["queries"]
        self.assertFalse(too_many["eql"]["available"])
        self.assertIn("1 to 100", too_many["eql"]["note"])
        self.assertTrue(too_many["esql"]["available"])
        self.assertTrue(qt.build("lsass-dump", ["eql"], threshold=500)["queries"]["eql"]["available"])
        code, out, _ = call_main(qt, ["mfa-fatigue", "--lang", "eql", "--threshold", "150"])
        self.assertEqual(code, 0)
        self.assertIn("1 to 100", out)

    def test_help(self):
        self.assertEqual(run_cli(SKILL, "query_translate", "--help").returncode, 0)


if __name__ == "__main__":
    unittest.main()
