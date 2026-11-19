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
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: example.test/app:1.0.0
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: [ALL]
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
        self.assertEqual(found, {"IAC-001", "IAC-002", "IAC-003", "IAC-004", "IAC-005", "IAC-006"})

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

    def test_tls_verification_off(self):
        for run in ("RUN curl -fsSLk https://x.example.test/a -o a", "RUN wget --no-check-certificate https://x.example.test/a",
                    "RUN git config --global http.sslVerify false", "ENV NODE_TLS_REJECT_UNAUTHORIZED=0"):
            f = iac.scan_dockerfile(f"FROM alpine:3.19\n{run}\nUSER 1\n")
            self.assertEqual(ids(f), {"IAC-006"}, run)
        safe = "FROM alpine:3.19\nRUN curl -fsSL -o /tmp/kit.tgz https://x.example.test/kit.tgz && wget -q https://x.example.test/b\nUSER 1\n"
        self.assertEqual(iac.scan_dockerfile(safe), [])


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

    def test_imdsv1_and_ebs(self):
        inst = 'resource "aws_instance" "i" {\n  ami = "ami-1"\n%s}\n'
        self.assertEqual(ids(tf(inst % "")), {"IAC-150"})
        req = '  metadata_options {\n    http_tokens = "required"\n  }\n'
        self.assertEqual(tf(inst % req), [])
        lt = 'resource "aws_launch_template" "t" {\n  metadata_options {\n    http_tokens = "optional"\n  }\n}\n'
        self.assertEqual(ids(tf(lt)), {"IAC-150"})
        enc = inst % (req + '  root_block_device {\n    volume_size = 8\n  }\n')
        self.assertEqual(ids(tf(enc)), {"IAC-151"})
        self.assertEqual(tf(enc + 'resource "aws_ebs_encryption_by_default" "on" {\n  enabled = true\n}\n'), [])
        self.assertEqual(ids(tf('resource "aws_ebs_volume" "v" {\n  size = 1\n}\n')), {"IAC-151"})
        self.assertEqual(tf('resource "aws_ebs_volume" "v" {\n  encrypted = true\n}\n'), [])

    def test_eks_lambda_kms_cloudtrail(self):
        eks = 'resource "aws_eks_cluster" "c" {\n  vpc_config {\n    subnet_ids = ["s"]\n%s  }\n}\n'
        self.assertEqual(ids(tf(eks % "")), {"IAC-152"})
        self.assertEqual(tf(eks % '    public_access_cidrs = ["198.51.100.0/24"]\n'), [])
        self.assertEqual(ids(tf('resource "aws_lambda_function_url" "u" {\n  authorization_type = "NONE"\n}\n')), {"IAC-153"})
        self.assertEqual(tf('resource "aws_lambda_function_url" "u" {\n  authorization_type = "AWS_IAM"\n}\n'), [])
        self.assertEqual(ids(tf('resource "aws_kms_key" "k" {\n  description = "x"\n}\n')), {"IAC-160"})
        self.assertEqual(tf('resource "aws_kms_key" "k" {\n  customer_master_key_spec = "RSA_2048"\n}\n'), [], "asymmetric keys cannot rotate")
        off = tf('resource "aws_cloudtrail" "t" {\n  enable_logging = false\n}\n')
        self.assertEqual([(x["id"], x["severity"]) for x in off], [("IAC-161", "medium")])

    def test_gcp_and_azure(self):
        found = ids(tf((EX / "insecure" / "gcp_azure.tf").read_text()))
        self.assertEqual(found, {"IAC-110", "IAC-170", "IAC-171"})
        self.assertEqual(tf((EX / "secure" / "gcp_azure.tf").read_text()), [])
        fw = 'resource "google_compute_firewall" "f" {\n  source_ranges = ["0.0.0.0/0"]\n  allow {\n    protocol = "all"\n  }\n}\n'
        self.assertEqual(ids(tf(fw)), {"IAC-111"})
        nsg = ('resource "azurerm_network_security_group" "g" {\n  security_rule {\n    direction = "Inbound"\n    access = "Allow"\n'
               '    protocol = "Tcp"\n    source_address_prefix = "*"\n    destination_port_ranges = ["443", "5432"]\n  }\n}\n')
        self.assertEqual(ids(tf(nsg)), {"IAC-112"})
        self.assertEqual(tf(nsg.replace('"Allow"', '"Deny"')), [])
        self.assertEqual(ids(tf('resource "google_project_iam_binding" "b" {\n  members = ["allAuthenticatedUsers"]\n}\n')), {"IAC-170"})

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
        text = POD.replace("drop: [ALL]", "drop: [ALL]\n          add: [SYS_ADMIN]")
        text = text.replace("spec:\n  securityContext", "spec:\n  hostPID: true\n  securityContext")
        self.assertEqual(ids(k8s(text)), {"IAC-208", "IAC-209"})

    def test_docker_sock_hostpath_is_critical(self):
        text = POD + "  volumes:\n    - name: s\n      hostPath:\n        path: /var/run/docker.sock\n"
        f = k8s(text)
        self.assertEqual(f[0]["id"], "IAC-203")
        self.assertEqual(f[0]["severity"], "critical")

    def test_restricted_profile_gaps(self):
        f = k8s(POD.replace("        readOnlyRootFilesystem: true\n", ""))
        self.assertEqual(ids(f), {"IAC-212"})
        self.assertIn("readOnlyRootFilesystem", f[0]["title"])
        no_seccomp = k8s(POD.replace("    seccompProfile:\n      type: RuntimeDefault\n", ""))
        self.assertEqual(ids(no_seccomp), {"IAC-212"})
        unconfined = k8s(POD.replace("type: RuntimeDefault", "type: Unconfined"))
        self.assertEqual(ids(unconfined), {"IAC-211"})
        hostport = k8s(POD.replace("      resources:", "      ports:\n        - containerPort: 80\n          hostPort: 80\n      resources:"))
        self.assertEqual(ids(hostport), {"IAC-213"})
        self.assertEqual(k8s(POD.replace("      resources:", "      ports:\n        - containerPort: 80\n      resources:")), [])

    def test_rbac(self):
        found = ids(k8s((EX / "insecure" / "deployment.yaml").read_text()))
        self.assertTrue({"IAC-220", "IAC-221", "IAC-222"} <= found)
        role = "apiVersion: rbac.authorization.k8s.io/v1\nkind: %s\nmetadata:\n  name: r\nrules:\n  - apiGroups: ['']\n    resources: [%s]\n    verbs: [%s]\n"
        self.assertEqual([(x["id"], x["severity"]) for x in k8s(role % ("ClusterRole", "'*'", "'*'"))], [("IAC-220", "critical")])
        self.assertEqual([(x["id"], x["severity"]) for x in k8s(role % ("Role", "secrets", "get"))], [("IAC-221", "medium")])
        self.assertEqual(ids(k8s(role % ("ClusterRole", "users, groups", "impersonate"))), {"IAC-221"})
        self.assertEqual(k8s(role % ("ClusterRole", "pods, pods/log", "get, list, watch")), [])
        bind = ("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: b\nroleRef:\n  kind: ClusterRole\n"
                "  name: view\nsubjects:\n  - kind: Group\n    name: %s\n")
        self.assertEqual([(x["id"], x["severity"]) for x in k8s(bind % "system:authenticated")], [("IAC-222", "high")])
        self.assertEqual(k8s(bind % "platform-team"), [])


class ComposeTests(unittest.TestCase):
    def scan(self, text):
        out = []
        for doc in iac.load_yaml_docs(text):
            out += iac.scan_compose_doc(doc, "docker-compose.yml")
        return out

    def test_insecure_example(self):
        found = ids(self.scan((EX / "insecure" / "docker-compose.yml").read_text()))
        self.assertEqual(found, {"IAC-301", "IAC-302", "IAC-303", "IAC-304", "IAC-306", "IAC-307"})

    def test_published_data_port(self):
        svc = "services:\n  db:\n    image: redis:7.2\n    ports:\n      - %s\n"
        self.assertEqual(ids(self.scan(svc % '"6379:6379"')), {"IAC-307"})
        self.assertEqual(ids(self.scan(svc % "{target: 6379, published: 6379}")), {"IAC-307"})
        self.assertEqual(self.scan(svc % '"127.0.0.1:6379:6379"'), [])
        self.assertEqual(self.scan(svc % '"8080:80"'), [])

    def test_secure_example_clean(self):
        self.assertEqual(self.scan((EX / "secure" / "docker-compose.yml").read_text()), [])


class IacCliTests(unittest.TestCase):
    def test_json_shape_and_exit_codes(self):
        code, out, _ = call_main(iac, [str(EX / "insecure"), "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(set(data), {"scanned", "count", "findings"})
        self.assertEqual(len(data["scanned"]), 5)
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

    def test_new_escalation_paths(self):
        titles = lambda doc: {x["title"] for x in self.audit(doc) if x["id"] == "IAM-010"}
        self.assertIn("Privilege escalation path: SSM SendCommand", titles(stmt(Action="ssm:SendCommand", Resource="*")))
        ecs = stmt(Action=["iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask"], Resource="*")
        self.assertIn("Privilege escalation path: PassRole + ECS task", titles(ecs))
        cb = stmt(Action=["iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"], Resource="*")
        self.assertIn("Privilege escalation path: PassRole + CodeBuild", titles(cb))
        self.assertEqual(titles(stmt(Action=["ecs:RunTask", "codebuild:StartBuild", "ssm:GetParameter"], Resource="*")), set())

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
