import json
import os
import shutil
import tempfile
import unittest

from _helpers import call_main, load_script, run_cli, skill_path

sec = load_script("code-secrets-review", "secret_scan")
sast = load_script("code-secrets-review", "sast_lite")
REPO = str(skill_path("code-secrets-review", "examples", "fake-repo"))

# Token-shaped test values are assembled at runtime so this file never holds a literal that
# looks like a real provider key (keeps repo secret scanners and push protection quiet).
BODY36 = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def fake(prefix, body):
    return prefix + body


def ids(findings):
    return {f["id"] for f in findings}


class SecretRuleTests(unittest.TestCase):
    def scan(self, line, rel="config.py"):
        return sec.scan_text(line, rel)

    def test_provider_tokens(self):
        cases = {
            "SEC-001": 'key = "' + fake("AKIA", "Q7ZK3M9TPLX2WD4R") + '"',
            "SEC-003": "tok = " + fake("gh" + "p_", BODY36),
            "SEC-004": "slack = " + fake("xo" + "xb-", "1234567890-abcdefghij"),
            "SEC-006": "stripe = " + fake("sk_" + "live_", "a1B2c3D4e5F6g7H8i9J0k1L2"),
            "SEC-007": "stripe = " + fake("sk_" + "test_", "a1B2c3D4e5F6g7H8i9J0k1L2"),
            "SEC-008": "g = " + fake("AI" + "za", "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"),
            "SEC-012": "npm = " + fake("np" + "m_", BODY36),
        }
        for rid, line in cases.items():
            self.assertIn(rid, ids(self.scan(line)), rid)

    def test_aws_example_key_is_info(self):
        f = self.scan('k = "AKIAIOSFODNN7EXAMPLE"')
        self.assertEqual(f[0]["severity"], "info")

    def test_private_key_and_url_password(self):
        self.assertIn("SEC-009", ids(self.scan("-----BEGIN RSA PRIVATE KEY-----")))
        self.assertNotIn("SEC-009", ids(self.scan("-----BEGIN PUBLIC KEY-----")))
        self.assertIn("SEC-010", ids(self.scan('u = "mysql://root:Pq8fakeS3cret@db.example.test/app"')))
        self.assertNotIn("SEC-010", ids(self.scan('u = "https://www.example.test/path"')))

    def test_generic_entropy(self):
        self.assertIn("SEC-020", ids(self.scan('client_secret = "Xr8fakeS3cretQw4Zp7Lm2"')))
        self.assertEqual(self.scan('password = "aaaaaaaaaaaa"'), [], "low entropy")
        self.assertEqual(self.scan('password = "changeme123"'), [], "placeholder")
        self.assertEqual(self.scan('api_key = os.environ["API_KEY"]'), [])
        self.assertEqual(self.scan("token = get_token_from_vault()"), [])

    def test_unquoted_env_lines_only_outside_code(self):
        self.assertIn("SEC-020", ids(self.scan("DB_PASSWORD=Lm4fakeDbPassw0rdK8vQ2", ".env")))
        self.assertEqual(self.scan("DB_PASSWORD=Lm4fakeDbPassw0rdK8vQ2", "app.py"), [])

    def test_output_is_masked(self):
        secret = fake("gh" + "p_", BODY36)
        f = self.scan("t = " + secret)[0]
        self.assertNotIn(secret, json.dumps(f))
        self.assertIn("ghp_...", f["detail"])
        self.assertEqual(sec.mask("abcdefgh"), "abcd...")

    def test_inline_ignore(self):
        self.assertEqual(self.scan('client_secret = "Xr8fakeS3cretQw4Zp7Lm2"  # secskills:ignore'), [])

    def test_entropy_function(self):
        self.assertEqual(sec.shannon_entropy("aaaa"), 0.0)
        self.assertAlmostEqual(sec.shannon_entropy("abcd"), 2.0)


class SecretScanRepoTests(unittest.TestCase):
    def test_example_repo(self):
        findings, files = sec.scan_path(REPO)
        locs = {f.get("location", "") for f in findings}
        self.assertGreater(files, 5)
        self.assertTrue({"SEC-009", "SEC-010", "SEC-020", "SEC-030", "SEC-001"} <= ids(findings))
        self.assertFalse(any(l.startswith("tests/fixtures") for l in locs), "allowlist file honoured")
        self.assertFalse(any(l.startswith("clean/") for l in locs), "clean file stays clean")
        self.assertNotIn("config/.env.example", locs)
        self.assertNotIn("app.py:14", locs, "inline secskills:ignore honoured")

    def test_rule_scoped_ignore_and_skips(self):
        tmp = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(tmp, "docs"))
            os.makedirs(os.path.join(tmp, "node_modules"))
            line = 'client_secret = "Xr8fakeS3cretQw4Zp7Lm2"\n'
            for rel in ("docs/a.py", "node_modules/b.js", "c.py"):
                with open(os.path.join(tmp, rel), "w") as fh:
                    fh.write(line)
            with open(os.path.join(tmp, "blob.dat"), "wb") as fh:
                fh.write(b"\0\0" + line.encode())
            with open(os.path.join(tmp, ".secskills-ignore"), "w") as fh:
                fh.write("SEC-020:docs/*\n")
            findings, _ = sec.scan_path(tmp)
            self.assertEqual([f["location"] for f in findings], ["c.py:1"])
        finally:
            shutil.rmtree(tmp)

    def test_cli_json_exit_codes(self):
        code, out, _ = call_main(sec, [REPO, "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(set(data), {"target", "files_scanned", "findings"})
        for f in data["findings"]:
            self.assertTrue({"id", "severity", "title", "detail", "fix"} <= set(f))
        self.assertEqual(call_main(sec, [REPO, "--fail-on", "never"])[0], 0)
        self.assertEqual(call_main(sec, [os.path.join(REPO, "clean")])[0], 0)
        self.assertEqual(call_main(sec, ["/nonexistent/secskills"])[0], 2)

    def test_stdin(self):
        code, out, _ = call_main(sec, ["--stdin", "--json"], stdin="+ token = " + fake("gh" + "p_", BODY36) + "\n")
        self.assertEqual(code, 1)
        self.assertIn("SEC-003", ids(json.loads(out)["findings"]))

    def test_help_subprocess(self):
        p = run_cli("code-secrets-review", "secret_scan", "--help")
        self.assertEqual(p.returncode, 0)
        self.assertIn("--fail-on", p.stdout)


class SastTests(unittest.TestCase):
    POSITIVE = {
        ("py", "PY-001"): "x = eval(user_input)",
        ("py", "PY-002"): "subprocess.call(cmd, shell=True)",
        ("py", "PY-003"): "obj = pickle.loads(data)",
        ("py", "PY-004"): "cfg = yaml.load(text)",
        ("py", "PY-005"): "cur.execute(f\"SELECT * FROM t WHERE id = {uid}\")",
        ("py", "PY-006"): "requests.get(url, verify=False)",
        ("py", "PY-007"): "app.run(debug=True)",
        ("py", "PY-008"): "h = hashlib.md5(data)",
        ("py", "PY-009"): "name = tempfile.mktemp()",
        ("js", "JS-001"): "const r = eval(input);",
        ("js", "JS-002"): "exec(`rm ${path}`);",
        ("js", "JS-003"): "el.innerHTML = msg;",
        ("js", "JS-004"): "<div dangerouslySetInnerHTML={{ __html: x }} />",
        ("js", "JS-005"): "db.query(`SELECT * FROM t WHERE id = ${id}`);",
        ("js", "JS-006"): "crypto.createHash('sha1')",
        ("js", "JS-007"): "https.request({ rejectUnauthorized: false })",
        ("php", "PHP-001"): "eval($code);",
        ("php", "PHP-002"): "shell_exec($cmd);",
        ("php", "PHP-003"): "$o = unserialize($raw);",
        ("php", "PHP-004"): "$q = \"SELECT * FROM t WHERE id = \" . $_GET['id'];",
        ("php", "PHP-005"): "echo $_GET['q'];",
        ("php", "PHP-006"): "$h = md5($pw);",
        ("php", "PHP-007"): "include($_GET['p']);",
        ("go", "GO-001"): "exec.Command(\"sh\", \"-c\", cmd)",
        ("go", "GO-002"): "q := fmt.Sprintf(\"SELECT * FROM t WHERE id = %s\", id)",
        ("go", "GO-003"): "cfg := &tls.Config{InsecureSkipVerify: true}",
        ("go", "GO-004"): "h := md5.New()",
        ("go", "GO-005"): "out := template.HTML(userInput)",
    }
    NEGATIVE = {
        "py": ["x = ast.literal_eval(s)", "subprocess.run(['ls', p])", "cfg = yaml.safe_load(t)",
               "cfg = yaml.load(t, Loader=yaml.SafeLoader)", "cur.execute(\"SELECT * FROM t WHERE id = %s\", (uid,))",
               "h = hashlib.md5(data, usedforsecurity=False)", "# eval(x) in a comment", "x = eval(user)  # secskills:ignore",
               "h = hashlib.sha256(data)"],
        "js": ["el.textContent = msg;", "execFile('ls', [p]);", "db.query('SELECT * FROM t WHERE id = $1', [id]);",
               "// el.innerHTML = x", "crypto.createHash('sha256')", "if (el.innerHTML === '') {}"],
        "php": ["echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');", "$h = hash('sha256', $x);",
                "$o = unserialize($raw, ['allowed_classes' => false]);", "$s->exec($q);"],
        "go": ["exec.Command(\"ls\", dir)", "h := sha256.New()", "db.Query(\"SELECT * FROM t WHERE id = ?\", id)"],
    }

    def test_every_rule_has_a_positive(self):
        self.assertEqual({r["id"] for r in sast.RULES}, {rid for _, rid in self.POSITIVE})
        for (lang, rid), line in self.POSITIVE.items():
            self.assertIn(rid, ids(sast.scan_text(line, lang)), f"{rid}: {line}")

    def test_negatives(self):
        for lang, lines in self.NEGATIVE.items():
            for line in lines:
                self.assertEqual(sast.scan_text(line, lang), [], f"{lang}: {line}")

    def test_rules_have_cwe_and_fix(self):
        for r in sast.RULES:
            self.assertRegex(r["cwe"], r"^CWE-\d+$")
            self.assertTrue(r["fix"])

    def test_example_repo(self):
        findings, files = sast.scan_path(REPO)
        self.assertEqual(files, 7)
        found = ids(findings)
        for rid in ("PY-001", "PY-002", "PY-005", "JS-002", "JS-003", "JS-004", "PHP-004", "PHP-005", "GO-001", "GO-003"):
            self.assertIn(rid, found)
        self.assertFalse(any(f["location"].startswith("clean/") for f in findings))
        locs = {f["location"] for f in findings}
        self.assertIn("app.py:30", locs)
        self.assertNotIn("app.py:31", locs, "parameterized query not flagged")
        self.assertNotIn("web/report.php:6", locs, "escaped echo not flagged")

    def test_cli(self):
        code, out, _ = call_main(sast, [REPO, "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(set(data), {"target", "files_scanned", "findings"})
        self.assertTrue({"id", "severity", "title", "detail", "fix", "location", "cwe"} <= set(data["findings"][0]))
        self.assertEqual(call_main(sast, [REPO, "--fail-on", "never"])[0], 0)
        self.assertEqual(call_main(sast, [os.path.join(REPO, "clean")])[0], 0)
        self.assertEqual(call_main(sast, [REPO, "--lang", "cobol"])[0], 2)
        self.assertEqual(call_main(sast, ["/nonexistent/secskills"])[0], 2)
        code, out, _ = call_main(sast, [REPO, "--lang", "go", "--json"])
        self.assertEqual({f["language"] for f in json.loads(out)["findings"]}, {"go"})
        code, out, _ = call_main(sast, ["--list-rules", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(out)["rules"]), len(sast.RULES))

    def test_help_subprocess(self):
        p = run_cli("code-secrets-review", "sast_lite", "--help")
        self.assertEqual(p.returncode, 0)
        self.assertIn("--lang", p.stdout)


if __name__ == "__main__":
    unittest.main()
