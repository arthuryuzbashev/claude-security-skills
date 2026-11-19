import datetime as dt
import json
import unittest
from unittest import mock

from _helpers import call_main, load_script, run_cli, skill_path

tls = load_script("crypto-tls", "tls_check")
cr = load_script("crypto-tls", "crypto_review")
EX = skill_path("crypto-tls", "examples")
UTC = dt.timezone.utc
NOW = dt.datetime(2027, 1, 1, tzinfo=UTC)  # inside both example certs' validity


def ids(findings):
    return {f["id"] for f in findings}


def example_cert(name):
    return tls.parse_certificate(tls.load_certificates((EX / name).read_bytes())[0])


def base_cert(**over):
    cert = {
        "subject": "CN=www.example.test", "common_name": "www.example.test", "issuer": "CN=CA",
        "self_signed": False, "is_ca": False, "has_san": True, "san_dns": ["www.example.test"], "san_ip": [],
        "not_before": dt.datetime(2026, 12, 1, tzinfo=UTC), "not_after": dt.datetime(2027, 3, 1, tzinfo=UTC),
        "signature_algorithm": "sha256WithRSAEncryption", "key_type": "RSA", "key_size": 2048, "curve": None,
    }
    cert.update(over)
    return cert


class DerReaderTests(unittest.TestCase):
    def test_oid_decoding(self):
        self.assertEqual(tls.decode_oid(bytes.fromhex("2a864886f70d01010b")), "1.2.840.113549.1.1.11")
        self.assertEqual(tls.decode_oid(bytes.fromhex("550403")), "2.5.4.3")

    def test_long_form_length(self):
        tag, value, nxt = tls.read_tlv(b"\x04\x81\x03abc", 0)
        self.assertEqual((tag, value, nxt), (0x04, b"abc", 6))
        with self.assertRaises(ValueError):
            tls.read_tlv(b"\x04\x05ab", 0)

    def test_modern_example_fields(self):
        c = example_cert("modern_leaf.pem")
        self.assertEqual((c["key_type"], c["key_size"], c["curve"]), ("EC", 256, "P-256"))
        self.assertEqual(c["signature_algorithm"], "ecdsa-with-SHA256")
        self.assertIn("www.example.test", c["san_dns"])
        self.assertIn("192.0.2.10", c["san_ip"])
        self.assertFalse(c["self_signed"])
        self.assertFalse(c["is_ca"])

    def test_legacy_example_fields(self):
        c = example_cert("legacy_wildcard.pem")
        self.assertEqual((c["key_type"], c["key_size"]), ("RSA", 1024))
        self.assertEqual(c["signature_algorithm"], "sha1WithRSAEncryption")
        self.assertTrue(c["self_signed"])

    def test_der_input_and_junk(self):
        der = tls.load_certificates((EX / "modern_leaf.pem").read_bytes())[0]
        self.assertEqual(tls.load_certificates(der), [der])
        with self.assertRaises(ValueError):
            tls.load_certificates(b"hello")
        with self.assertRaises(ValueError):
            tls.parse_certificate(b"\x30\x03\x02\x01\x01")


class CertGradingTests(unittest.TestCase):
    def test_modern_example_is_clean(self):
        self.assertEqual(tls.grade_certificate(example_cert("modern_leaf.pem"), "example.test", NOW), [])

    def test_legacy_example_flags(self):
        found = ids(tls.grade_certificate(example_cert("legacy_wildcard.pem"), "a.legacy.example.test", NOW))
        self.assertTrue({"TLS-010", "TLS-020", "TLS-030", "TLS-050", "TLS-060"} <= found)
        self.assertNotIn("TLS-040", found, "wildcard covers one label")

    def test_expiry_bands(self):
        c = base_cert()
        self.assertIn("TLS-001", ids(tls.grade_certificate(c, now=dt.datetime(2027, 3, 2, tzinfo=UTC))))
        self.assertIn("TLS-002", ids(tls.grade_certificate(c, now=dt.datetime(2027, 2, 20, tzinfo=UTC))))
        self.assertIn("TLS-003", ids(tls.grade_certificate(c, now=dt.datetime(2027, 2, 5, tzinfo=UTC))))
        self.assertIn("TLS-004", ids(tls.grade_certificate(c, now=dt.datetime(2026, 11, 1, tzinfo=UTC))))
        self.assertEqual(tls.grade_certificate(c, now=NOW), [])

    def test_hostname_rules(self):
        c = base_cert(san_dns=["*.example.test"])
        self.assertTrue(tls.hostname_matches("api.example.test", c))
        self.assertFalse(tls.hostname_matches("a.b.example.test", c))
        self.assertFalse(tls.hostname_matches("example.test", c))
        self.assertIn("TLS-040", ids(tls.grade_certificate(c, "example.test", NOW)))

    def test_lifetime_cap_by_issue_date(self):
        old = base_cert(not_before=dt.datetime(2025, 1, 1, tzinfo=UTC), not_after=dt.datetime(2026, 1, 20, tzinfo=UTC))
        self.assertNotIn("TLS-060", ids(tls.grade_certificate(old, now=dt.datetime(2025, 6, 1, tzinfo=UTC))))
        new = base_cert(not_before=dt.datetime(2026, 6, 1, tzinfo=UTC), not_after=dt.datetime(2027, 6, 1, tzinfo=UTC))
        self.assertIn("TLS-060", ids(tls.grade_certificate(new, now=NOW)))

    def test_root_ca_is_info_only(self):
        root = base_cert(self_signed=True, is_ca=True, signature_algorithm="sha1WithRSAEncryption")
        self.assertEqual(ids(tls.grade_certificate(root, now=NOW)), {"TLS-031"})


class ConnectionGradingTests(unittest.TestCase):
    def test_modern_connection_clean(self):
        conn = {"protocol": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256",
                "legacy": {"TLSv1": "not supported", "TLSv1.1": "not supported"}}
        self.assertEqual(tls.grade_connection(conn), [])

    def test_legacy_and_weak_cipher(self):
        conn = {"protocol": "TLSv1.2", "cipher": "AES128-SHA", "legacy": {"TLSv1": "supported", "TLSv1.1": "supported"},
                "verify_error": "unable to get local issuer certificate"}
        found = ids(tls.grade_connection(conn))
        self.assertTrue({"TLS-070", "TLS-071", "TLS-073", "TLS-081", "TLS-082", "TLS-032"} <= found)
        self.assertIn("TLS-080", ids(tls.grade_connection({"protocol": "TLSv1.2", "cipher": "DES-CBC3-SHA"})))

    def test_untested_legacy_is_reported_not_hidden(self):
        found = tls.grade_connection({"protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
                                      "legacy": {"TLSv1": "could not test", "TLSv1.1": "not supported"}})
        self.assertEqual(ids(found), {"TLS-074"})

    def test_probe_without_local_support(self):
        with mock.patch.object(tls.ssl, "HAS_TLSv1", False):
            status, note = tls.probe_protocol("192.0.2.1", 443, "TLSv1", 1, None)
        self.assertEqual(status, "could not test")
        self.assertIn("without TLSv1", note)

    def test_split_target(self):
        self.assertEqual(tls.split_target("https://app.example.test/login", 443), ("app.example.test", 443))
        self.assertEqual(tls.split_target("app.example.test:8443", 443), ("app.example.test", 8443))
        self.assertEqual(tls.split_target("[2001:db8::1]:9443", 443), ("2001:db8::1", 9443))


class TlsCliTests(unittest.TestCase):
    def test_json_shape_and_exit(self):
        code, out, _ = call_main(tls, ["--cert", str(EX / "legacy_wildcard.pem"), "--now", "2027-01-01", "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(set(data), {"target", "mode", "chain_length", "connection", "certificate", "findings"})
        self.assertEqual(data["mode"], "file")
        self.assertEqual(data["certificate"]["key_size"], 1024)
        code, _, _ = call_main(tls, ["--cert", str(EX / "modern_leaf.pem"), "--now", "2027-01-01",
                                     "--hostname", "www.example.test"])
        self.assertEqual(code, 0)
        code, _, _ = call_main(tls, ["--cert", str(EX / "modern_leaf.pem"), "--now", "2027-05-10", "--fail-on", "never"])
        self.assertEqual(code, 0)

    def test_bad_input(self):
        code, _, err = call_main(tls, ["--cert", str(EX / "hashes.txt")])
        self.assertEqual(code, 2)
        self.assertIn("error", err)

    def test_help_subprocess(self):
        self.assertEqual(run_cli("crypto-tls", "tls_check", "--help").returncode, 0)


class CryptoReviewTests(unittest.TestCase):
    def test_each_rule_positive(self):
        cases = {
            "CRY-001": "h = hashlib.sha1(password.encode()).hexdigest()",
            "CRY-002": "etag = hashlib.md5(body).hexdigest()",
            "CRY-003": 'MessageDigest.getInstance("SHA-1")',
            "CRY-010": 'Cipher.getInstance("AES/ECB/PKCS5Padding")',
            "CRY-011": "iv = bytes(16)",
            "CRY-020": 'ENCRYPTION_KEY = "Zm9vYmFyYmF6cXV4MTIzNDU2"',
            "CRY-021": "-----BEGIN RSA PRIVATE KEY-----",
            "CRY-030": "token = str(random.random())",
            "CRY-040": 'Cipher.getInstance("RC4")',
            "CRY-041": 'Cipher.getInstance("DESede/CBC/PKCS5Padding")',
            "CRY-050": "key = RSA.generate(1024)",
            "CRY-060": 'tls.Config{InsecureSkipVerify: true}',
            "CRY-070": "jwt.verify(t, k, { algorithms: ['none'] })",
            "CRY-071": 'jwt.decode(t, options={"verify_signature": False})',
        }
        for rule, line in cases.items():
            with self.subTest(rule=rule):
                self.assertIn(rule, ids(cr.scan_text(line)))

    def test_safe_lines_are_quiet(self):
        safe = [
            "hashed = ph.hash(password)",
            "dk = hashlib.pbkdf2_hmac('sha256', password, salt, 600000)",
            "token = secrets.token_urlsafe(32)",
            "x = random.choice(colors)",
            "nonce = os.urandom(12)",
            "API_SECRET = os.environ['API_SECRET']",
            'SECRET_KEY = "change-me-in-production-please"',
            "key = rsa.generate_private_key(public_exponent=65537, key_size=3072)",
            "requests.get(url, verify=True)",
            "jwt.decode(token, key, algorithms=['RS256'])",
            'DESIGN = "ok"',
        ]
        for line in safe:
            with self.subTest(line=line):
                self.assertEqual(cr.scan_text(line), [])

    def test_secrets_masked_and_key_body_skipped(self):
        text = 'aes_key = "SuperSecretValue1234567"\n-----BEGIN PRIVATE KEY-----\nMIIEvQ...\n-----END PRIVATE KEY-----\n'
        found = cr.scan_text(text, "x.py")
        self.assertEqual([f["id"] for f in found], ["CRY-020", "CRY-021"])
        self.assertNotIn("SuperSecretValue", json.dumps(found))
        self.assertIn("Supe...", found[0]["evidence"])

    def test_suppression_comment(self):
        self.assertEqual(cr.scan_text("requests.get(u, verify=False)  # secskills-ignore: test fixture"), [])

    def test_examples(self):
        res = cr.scan_paths([str(EX / "weak_app")])
        found = ids(res["findings"])
        self.assertTrue({"CRY-001", "CRY-010", "CRY-011", "CRY-020", "CRY-030", "CRY-040", "CRY-050",
                         "CRY-060", "CRY-070", "CRY-071"} <= found)
        self.assertNotIn("fAkE0nlyK3y", json.dumps(res))
        self.assertEqual(cr.scan_paths([str(EX / "clean_app.py")])["findings"], [])

    def test_cli_exit_codes_and_json(self):
        code, out, _ = call_main(cr, [str(EX / "weak_app"), "--json"])
        self.assertEqual(code, 1)
        self.assertEqual(set(json.loads(out)), {"mode", "files_scanned", "findings"})
        self.assertEqual(call_main(cr, [str(EX / "clean_app.py")])[0], 0)
        self.assertEqual(call_main(cr, [str(EX / "weak_app"), "--fail-on", "never"])[0], 0)
        self.assertEqual(call_main(cr, [str(EX / "nope")])[0], 2)
        self.assertEqual(call_main(cr, [])[0], 2)


class HashIdTests(unittest.TestCase):
    def test_formats(self):
        cases = {
            "5f4dcc3b5aa765d61d8327deb882cf99": "MD5",
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12": "SHA-1",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "SHA-256",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e": "SHA-512",
            "$2b$12$C6UzMDM.H6dfI/f/IKcEeO5RSLnWfSqGXeyXPbKNbsJuSHhGVrS6e": "bcrypt",
            "$1$abcdefgh$G//4keteveJwXGwYz8Qi71": "md5crypt",
            "$y$j9T$saltsalt$hashhashhash": "yescrypt",
        }
        for value, name in cases.items():
            with self.subTest(name=name):
                self.assertEqual(cr.identify_hash(value)["candidates"][0], name)
        self.assertIn("NTLM", cr.identify_hash("5f4dcc3b5aa765d61d8327deb882cf99")["candidates"])

    def test_params_and_strength(self):
        a = cr.identify_hash("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub")
        self.assertEqual((a["candidates"], a["password_storage"]), (["argon2id"], "strong"))
        self.assertEqual(a["params"]["memory_kib"], 65536)
        weak_a = cr.identify_hash("$argon2i$v=19$m=4096,t=1,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub")
        self.assertEqual(weak_a["password_storage"], "ok")
        b = cr.identify_hash("$2a$08$" + "a" * 53)
        self.assertEqual((b["params"]["cost"], b["password_storage"]), (8, "ok"))
        self.assertEqual(cr.identify_hash("zzzz")["candidates"], [])

    def test_cli_masks_input(self):
        code, out, _ = call_main(cr, ["--hash-id", "-", "--json"], stdin=(EX / "hashes.txt").read_text())
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(len(data["results"]), 8)
        self.assertNotIn("5f4dcc3b5aa765d61d8327deb882cf99", out)
        self.assertEqual(call_main(cr, ["--hash-id", "-"], stdin="\n")[0], 2)

    def test_help_subprocess(self):
        self.assertEqual(run_cli("crypto-tls", "crypto_review", "--help").returncode, 0)


if __name__ == "__main__":
    unittest.main()
