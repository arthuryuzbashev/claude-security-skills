import json
import unittest

from _helpers import call_main, load_script, run_cli, skill_path

iac = load_script("cloud-iac", "iac_scan")
iam = load_script("cloud-iac", "iam_policy_audit")
EX = skill_path("cloud-iac", "examples")


def ids(findings):
    return {f["id"] for f in findings}


def tf(text):
    return iac.scan_terraform_files([("main.tf", text)])


def k8s(text):
    out = []
    for doc in iac.load_yaml_docs(text):
        out += iac.scan_k8s_doc(doc, "x.yaml")
    return out


POD = """apiVersion: v1
kind: Pod
metadata:
  name: p
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
    - name: app
      image: example.test/app:1.0.0
      securityContext:
        allowPrivilegeEscalation: false
      resources:
        limits: {cpu: 200m, memory: 128Mi}
"""


class YamlReaderTests(unittest.TestCase):
    def test_nested_structures_and_lines(self):
        docs = iac.load_yaml_docs("a: 1\nlist:\n  - name: x  # comment\n    v: 'q'\n  - plain\nflow: [a, \"b\"]\n---\nb: |\n  line1\n  line2\n")
        self.assertEqual(len(docs), 2)
        self.assertEqual(docs[0]["list"][0]["name"], "x")
        self.assertEqual(docs[0]["list"][0]["v"], "q")
        self.assertEqual(docs[0]["list"][1], "plain")
        self.assertEqual(list(docs[0]["flow"]), ["a", "b"])
        self.assertEqual(docs[0].key_lines["flow"], 6)
        self.assertEqual(docs[1]["b"], "line1\nline2")

    def test_json_manifest(self):
        doc = iac.load_yaml_docs(json.dumps({"kind": "Pod", "spec": {"hostNetwork": True, "containers": []}}))[0]
        self.assertTrue(iac.ytrue(doc["spec"]["hostNetwork"]))


class DockerfileTests(unittest.TestCase):
    def test_insecure_example(self):
        text = (EX / "insecure" / "Dockerfile").read_text()
        found = ids(iac.scan_dockerfile(text))
        self.assertEqual(found, {"IAC-001", "IAC-002", "IAC-003", "IAC-004", "IAC-005"})

    def test_secure_example_clean(self):
        self.assertEqual(iac.scan_dockerfile((EX / "secure" / "Dockerfile").read_text()), [])

    def test_stage_alias_and_root_user(self):
        f = iac.scan_dockerfile("FROM golang:1.22 AS b\nFROM b\nUSER root\n")
        self.assertEqual(ids(f), {"IAC-002"})
        self.assertEqual(iac.scan_dockerfile("FROM alpine:3.19\nUSER app\n"), [])

    def test_secret_is_masked(self):
        f = iac.scan_dockerfile("FROM alpine:3.19\nENV API_KEY=abcdef123456\nUSER 1\n")
        self.assertEqual(f[0]["id"], "IAC-004")
        self.assertNotIn("abcdef123456", json.dumps(f))
        self.assertIn("abcd...", f[0]["detail"])

    def test_env_reference_not_secret(self):
        self.assertEqual(iac.scan_dockerfile("FROM alpine:3.19\nARG NPM_TOKEN\nENV TOKEN=${NPM_TOKEN}\nUSER 1\n"), [])


class TerraformTests(unittest.TestCase):
    def test_insecure_example(self):
        found = ids(tf((EX / "insecure" / "main.tf").read_text()))
        for rule in ("IAC-101", "IAC-102", "IAC-103", "IAC-104", "IAC-110", "IAC-111", "IAC-112",
                     "IAC-120", "IAC-130", "IAC-131", "IAC-140"):
            self.assertIn(rule, found)

    def test_secure_example_clean(self):
        self.assertEqual(tf((EX / "secure" / "main.tf").read_text()), [])

    def test_sg_ssh_open_vs_restricted(self):
        sg = 'resource "aws_security_group" "s" {\n  ingress {\n    from_port = 3389\n    to_port = 3389\n    protocol = "tcp"\n    cidr_blocks = [%s]\n  }\n}\n'
        f = tf(sg % '"0.0.0.0/0"')
        self.assertEqual([x["id"] for x in f], ["IAC-110"])
        self.assertEqual(f[0]["location"], "main.tf:2")
        self.assertEqual(tf(sg % '"203.0.113.0/24"'), [])

    def test_vpc_ingress_rule_resource(self):
        f = tf('resource "aws_vpc_security_group_ingress_rule" "r" {\n  cidr_ipv4 = "0.0.0.0/0"\n  ip_protocol = "-1"\n}\n')
        self.assertEqual(ids(f), {"IAC-111"})

    def test_policy_document_and_heredoc(self):
        doc = 'data "aws_iam_policy_document" "d" {\n  statement {\n    actions = ["*"]\n    resources = ["arn:aws:s3:::b/*"]\n  }\n}\n'
        self.assertEqual(ids(tf(doc)), {"IAC-120"})
        here = 'resource "aws_iam_role_policy" "p" {\n  policy = <<EOF\n{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}\nEOF\n}\n'
        self.assertEqual(tf(here), [], "Deny statements are not grants")

    def test_s3_split_resources_link_to_bucket(self):
        text = (EX / "secure" / "main.tf").read_text().replace('aws_s3_bucket.assets.id\n  versioning', 'aws_s3_bucket.other.id\n  versioning')
        self.assertIn("IAC-103", ids(tf(text)))


class KubernetesTests(unittest.TestCase):
    def test_insecure_example(self):
        found = ids(k8s((EX / "insecure" / "deployment.yaml").read_text()))
        for rule in ("IAC-201", "IAC-202", "IAC-203", "IAC-204", "IAC-205", "IAC-206", "IAC-207", "IAC-210"):
            self.assertIn(rule, found)

    def test_hardened_pod_clean(self):
        self.assertEqual(k8s(POD), [])
        self.assertEqual(k8s((EX / "secure" / "deployment.yaml").read_text()), [])

    def test_capabilities_and_host_pid(self):
        text = POD.replace("allowPrivilegeEscalation: false", "allowPrivilegeEscalation: false\n        capabilities:\n          add: [SYS_ADMIN]")
        text = text.replace("spec:\n  securityContext", "spec:\n  hostPID: true\n  securityContext")
        self.assertEqual(ids(k8s(text)), {"IAC-208", "IAC-209"})

    def test_docker_sock_hostpath_is_critical(self):
        text = POD + "  volumes:\n    - name: s\n      hostPath:\n        path: /var/run/docker.sock\n"
        f = k8s(text)
        self.assertEqual(f[0]["id"], "IAC-203")
        self.assertEqual(f[0]["severity"], "critical")


class ComposeTests(unittest.TestCase):
    def scan(self, text):
        out = []
        for doc in iac.load_yaml_docs(text):
            out += iac.scan_compose_doc(doc, "docker-compose.yml")
        return out

    def test_insecure_example(self):
        found = ids(self.scan((EX / "insecure" / "docker-compose.yml").read_text()))
        self.assertEqual(found, {"IAC-301", "IAC-302", "IAC-303", "IAC-304", "IAC-306"})

    def test_secure_example_clean(self):
        self.assertEqual(self.scan((EX / "secure" / "docker-compose.yml").read_text()), [])


class IacCliTests(unittest.TestCase):
    def test_json_shape_and_exit_codes(self):
        code, out, _ = call_main(iac, [str(EX / "insecure"), "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(set(data), {"scanned", "count", "findings"})
        self.assertEqual(len(data["scanned"]), 4)
        for f in data["findings"]:
            self.assertTrue({"id", "severity", "title", "detail", "fix", "location"} <= set(f))
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out)
        self.assertEqual(call_main(iac, [str(EX / "secure")])[0], 0)
        self.assertEqual(call_main(iac, [str(EX / "insecure"), "--fail-on", "never"])[0], 0)

    def test_bad_input(self):
        self.assertEqual(call_main(iac, ["/no/such/path"])[0], 2)
        self.assertEqual(call_main(iac, ["-"], stdin="FROM x")[0], 2, "stdin needs --type")

    def test_stdin_with_type(self):
        code, out, _ = call_main(iac, ["-", "--type", "dockerfile", "--json"], stdin="FROM ubuntu\n")
        self.assertEqual(code, 0)
        self.assertEqual({f["id"] for f in json.loads(out)["findings"]}, {"IAC-001", "IAC-002"})

    def test_help_subprocess(self):
        self.assertEqual(run_cli("cloud-iac", "iac_scan", "--help").returncode, 0)


def stmt(**kw):
    base = {"Effect": "Allow"}
    base.update(kw)
    return {"Version": "2012-10-17", "Statement": [base]}


class IamAuditTests(unittest.TestCase):
    def audit(self, doc):
        return iam.audit_document(doc, "p.json")

    def test_admin_example(self):
        data = json.loads((EX / "iam" / "admin_policy.json").read_text())
        f = iam.audit_sources([("a", data)])
        self.assertEqual([(x["id"], x["severity"]) for x in f], [("IAM-001", "critical")])

    def test_privesc_example(self):
        data = json.loads((EX / "iam" / "privesc_policy.json").read_text())
        f = iam.audit_sources([("p", data)])
        titles = {x["title"] for x in f if x["id"] == "IAM-010"}
        self.assertIn("Privilege escalation path: PassRole + Lambda invoke", titles)
        self.assertIn("Privilege escalation path: CreatePolicyVersion", titles)
        self.assertTrue({"IAM-003", "IAM-006", "IAM-020"} <= ids(f))

    def test_least_privilege_clean(self):
        data = json.loads((EX / "iam" / "least_privilege_policy.json").read_text())
        self.assertEqual(iam.audit_sources([("l", data)]), [])

    def test_public_bucket_policy_string(self):
        data = json.loads((EX / "iam" / "public_bucket_policy.json").read_text())
        f = iam.audit_sources([("b", data)])
        self.assertEqual([(x["id"], x["severity"]) for x in f], [("IAM-030", "high")])
        w = self.audit(stmt(Principal={"AWS": "*"}, Action="s3:PutObject", Resource="arn:aws:s3:::b/*"))
        self.assertEqual(w[0]["severity"], "critical")
        c = self.audit(stmt(Principal="*", Action="s3:GetObject", Resource="arn:aws:s3:::b/*",
                            Condition={"StringEquals": {"aws:PrincipalOrgID": "o-example"}}))
        self.assertEqual(ids(c), {"IAM-031"})

    def test_not_action_and_service_wildcard(self):
        f = self.audit(stmt(NotAction="iam:*", Resource="*"))
        self.assertIn("IAM-004", ids(f))
        # iam:PassRole is excluded, so PassRole paths do not count, but lambda:UpdateFunctionCode does
        titles = {x["title"] for x in f if x["id"] == "IAM-010"}
        self.assertIn("Privilege escalation path: UpdateFunctionCode", titles)
        self.assertNotIn("Privilege escalation path: PassRole + EC2", titles)
        f = self.audit(stmt(Action="iam:*", Resource="arn:aws:iam::123456789012:role/x"))
        self.assertIn("IAM-003", ids(f))
        self.assertEqual([x["severity"] for x in f if x["id"] == "IAM-003"], ["high"])

    def test_wildcard_action_pattern_triggers_escalation(self):
        f = self.audit(stmt(Action="iam:Put*", Resource="*"))
        self.assertIn("Privilege escalation path: PutRolePolicy", {x["title"] for x in f})
        safe = self.audit(stmt(Action=["iam:Get*", "iam:List*"], Resource="*"))
        self.assertEqual([x for x in safe if x["id"] == "IAM-010"], [])

    def test_deny_subtracts_and_combine(self):
        doc = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"},
            {"Effect": "Deny", "Action": "iam:Attach*", "Resource": "*"}]}
        self.assertEqual([x for x in self.audit(doc) if x["id"] == "IAM-010"], [])
        a = stmt(Action="iam:PassRole", Resource="*")
        b = stmt(Action="ec2:RunInstances", Resource="*")
        alone = iam.audit_sources([("a", a), ("b", b)])
        self.assertNotIn("IAM-010", ids(alone))
        combined = iam.audit_sources([("a", a), ("b", b)], combine=True)
        self.assertIn("Privilege escalation path: PassRole + EC2", {x["title"] for x in combined})

    def test_old_version(self):
        self.assertEqual(ids(self.audit({"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/k"}]})), {"IAM-040"})

    def test_cli(self):
        code, out, _ = call_main(iam, [str(EX / "iam" / "privesc_policy.json"), "--json"])
        self.assertEqual(code, 1)
        self.assertEqual(set(json.loads(out)), {"sources", "count", "findings"})
        self.assertEqual(call_main(iam, [str(EX / "iam" / "least_privilege_policy.json")])[0], 0)
        self.assertEqual(call_main(iam, ["-"], stdin="not json")[0], 2)
        self.assertEqual(call_main(iam, ["-"], stdin='{"no": "statement"}')[0], 2)
        self.assertEqual(run_cli("cloud-iac", "iam_policy_audit", "--help").returncode, 0)


if __name__ == "__main__":
    unittest.main()
