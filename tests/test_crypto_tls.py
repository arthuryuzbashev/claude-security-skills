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


def server_hello(group, hrr=False, version=0x0304):
    """Synthetic ServerHello record (TLS 1.3 shape) for parser tests."""
    rnd = tls.HRR_RANDOM if hrr else bytes(range(32))
    share = group.to_bytes(2, "big") if hrr else group.to_bytes(2, "big") + (32).to_bytes(2, "big") + bytes(32)
    exts = (b"\x00\x2b\x00\x02" + version.to_bytes(2, "big")
            + b"\x00\x33" + len(share).to_bytes(2, "big") + share)
    body = b"\x03\x03" + rnd + b"\x00" + b"\x13\x01" + b"\x00" + len(exts).to_bytes(2, "big") + exts
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs


class FakeSock:
    def __init__(self, reply):
        self.reply, self.sent = [reply[:7], reply[7:]], b""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def sendall(self, data):
        self.sent += data

    def recv(self, n):
        return self.reply.pop(0) if self.reply else b""


class PostQuantumProbeTests(unittest.TestCase):
    def test_grade_pq(self):
        base = {"protocol": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256"}
        self.assertEqual(ids(tls.grade_connection(dict(base, pq_hybrid=False, key_exchange_group="x25519"))), {"TLS-090"})
        self.assertEqual(tls.grade_connection(dict(base, pq_hybrid=True, key_exchange_group="X25519MLKEM768")), [])
        self.assertEqual(tls.grade_connection(dict(base, pq_hybrid=None, key_exchange_group=None)), [])

    def test_client_hello_shape(self):
        rec = tls.build_pq_client_hello("www.example.test")
        self.assertEqual(rec[:3], b"\x16\x03\x01")
        self.assertEqual(int.from_bytes(rec[3:5], "big"), len(rec) - 5)
        self.assertEqual(rec[5], 1)
        self.assertIn(b"www.example.test", rec)
        # X25519MLKEM768 share: group 0x11EC, length 1216 (1184-byte ML-KEM-768 key + 32-byte X25519)
        self.assertIn(b"\x11\xec\x04\xc0", rec)
        self.assertIn(b"\x00\x2b\x00\x03\x02\x03\x04", rec)
        self.assertNotIn(b"www.example.test", tls.build_pq_client_hello(None))

    def test_parse_server_hello(self):
        self.assertEqual(tls.parse_server_hello(server_hello(0x11EC))["group"], 0x11EC)
        hrr = tls.parse_server_hello(server_hello(0x0017, hrr=True))
        self.assertEqual((hrr["hrr"], hrr["group"]), (True, 0x0017))
        self.assertEqual(tls.parse_server_hello(b"\x15\x03\x03\x00\x02\x02\x28")["status"], "alert")
        self.assertEqual(tls.parse_server_hello(server_hello(0x001D)[:20])["status"], "incomplete")

    def test_probe_end_to_end_offline(self):
        fake = FakeSock(server_hello(0x001D))
        with mock.patch.object(tls.socket, "create_connection", return_value=fake):
            res = tls.probe_pq("192.0.2.10", 443, 1, "192.0.2.10")
        self.assertEqual((res["key_exchange_group"], res["pq_hybrid"]), ("x25519", False))
        self.assertNotIn(b"192.0.2.10", fake.sent, "no SNI for IP literals")
        with mock.patch.object(tls.socket, "create_connection", return_value=FakeSock(server_hello(0x11EC))):
            self.assertTrue(tls.probe_pq("h.example.test", 443, 1, "h.example.test")["pq_hybrid"])
        with mock.patch.object(tls.socket, "create_connection", return_value=FakeSock(server_hello(0x001D, version=0x0303))):
            self.assertIsNone(tls.probe_pq("h.example.test", 443, 1, "h.example.test")["pq_hybrid"])
        with mock.patch.object(tls.socket, "create_connection", side_effect=OSError("refused")):
            self.assertIn("probe failed", tls.probe_pq("h.example.test", 443, 1, "h.example.test")["pq_note"])


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
        res = run_cli("crypto-tls", "tls_check", "--help")
        self.assertEqual(res.returncode, 0)
        for flag in ("--cert", "--no-legacy", "--no-pq", "--now", "--json", "--fail-on"):
            self.assertIn(flag, res.stdout)


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

    def test_rsa_ecb_label_is_not_ecb(self):
        self.assertNotIn("CRY-010", ids(cr.scan_text('Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")')))
        self.assertEqual(ids(cr.scan_text('Cipher.getInstance("RSA/ECB/PKCS1Padding")')), {"CRY-012"})

    def test_rsa_encryption_padding(self):
        bad = {
            'Cipher.getInstance("RSA/ECB/NoPadding")': "high",
            "ct = pub.encrypt(msg, padding.PKCS1v15())": "medium",
            "crypto.publicEncrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, buf)": "medium",
            "ct, err := rsa.EncryptPKCS1v15(rand.Reader, pub, msg)": "medium",
            "from Crypto.Cipher import PKCS1_v1_5": "medium",
            "rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1)": "medium",
        }
        for line, sev in bad.items():
            with self.subTest(line=line):
                hit = [f for f in cr.scan_text(line) if f["id"] == "CRY-012"]
                self.assertEqual([f["severity"] for f in hit], [sev])
        for line in ["sig = key.sign(msg, padding.PKCS1v15(), hashes.SHA256())",
                     "from Crypto.Signature import PKCS1_v1_5",
                     "ct = pub.encrypt(msg, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))",
                     "crypto.publicEncrypt({ key, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, buf)"]:
            with self.subTest(line=line):
                self.assertNotIn("CRY-012", ids(cr.scan_text(line)))

    def test_pbkdf2_iterations(self):
        low = {
            "dk = hashlib.pbkdf2_hmac('sha256', pw, salt, 100000)": "medium",
            "kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=1000)": "high",
            "crypto.pbkdf2Sync(pw, salt, 100000, 64, 'sha512')": "medium",
            "dk := pbkdf2.Key(pw, salt, 4096, 32, sha256.New)": "high",
            "KeySpec spec = new PBEKeySpec(pw, salt, 65536, 256);": "medium",
            "dk = hashlib.pbkdf2_hmac('sha1', pw, salt, 600000)": "medium",
        }
        for line, sev in low.items():
            with self.subTest(line=line):
                hit = [f for f in cr.scan_text(line) if f["id"] == "CRY-051"]
                self.assertEqual([f["severity"] for f in hit], [sev])
        for line in ["dk = hashlib.pbkdf2_hmac('sha256', pw, salt, 600_000)",
                     "crypto.pbkdf2Sync(pw, salt, 220000, 64, 'sha512')",
                     "dk = hashlib.pbkdf2_hmac('sha1', pw, salt, 1400000)",
                     "for i in range(iterations=3): pass"]:
            with self.subTest(line=line):
                self.assertNotIn("CRY-051", ids(cr.scan_text(line)))

    def test_bcrypt_cost(self):
        for line in ["salt = bcrypt.gensalt(rounds=8)", "const h = await bcrypt.hash(pw, 8);",
                     "h, _ := bcrypt.GenerateFromPassword(pw, bcrypt.MinCost)", "new BCryptPasswordEncoder(6)",
                     "BCRYPT_ROUNDS=4", "password_hash($pw, PASSWORD_BCRYPT, ['cost' => 9]);"]:
            with self.subTest(line=line):
                self.assertIn("CRY-052", ids(cr.scan_text(line)))
        for line in ["salt = bcrypt.gensalt(12)", "const h = await bcrypt.hash(pw, 12);",
                     "h, _ := bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)", "new BCryptPasswordEncoder(12)",
                     "BCRYPT_ROUNDS=12"]:
            with self.subTest(line=line):
                self.assertNotIn("CRY-052", ids(cr.scan_text(line)))

    def test_old_tls_pin(self):
        for line in ["ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)", "ctx.minimum_version = ssl.TLSVersion.TLSv1",
                     "cfg := &tls.Config{MinVersion: tls.VersionTLS10}", "https.request({ host, minVersion: 'TLSv1' })",
                     "ssl_protocols TLSv1 TLSv1.1 TLSv1.2;", 'SSLContext.getInstance("TLSv1")',
                     "ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;"]:
            with self.subTest(line=line):
                self.assertIn("CRY-061", ids(cr.scan_text(line)))
        for line in ["ctx.minimum_version = ssl.TLSVersion.TLSv1_2", "cfg := &tls.Config{MinVersion: tls.VersionTLS12}",
                     "https.request({ host, minVersion: 'TLSv1.2' })", "ssl_protocols TLSv1.2 TLSv1.3;",
                     'SSLContext.getInstance("TLSv1.3")', 'SSLContext.getInstance("TLS")', "ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;"]:
            with self.subTest(line=line):
                self.assertNotIn("CRY-061", ids(cr.scan_text(line)))

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
        self.assertTrue({"CRY-001", "CRY-010", "CRY-011", "CRY-012", "CRY-020", "CRY-030", "CRY-040", "CRY-050",
                         "CRY-051", "CRY-052", "CRY-060", "CRY-061", "CRY-070", "CRY-071"} <= found)
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

    def test_pbkdf2_thresholds_per_prf(self):
        self.assertEqual(cr.identify_hash("pbkdf2_sha256$600000$s$aGFzaA==")["password_storage"], "strong")
        sha1 = cr.identify_hash("pbkdf2_sha1$600000$s$aGFzaA==")
        self.assertEqual((sha1["password_storage"], sha1["params"]["prf"]), ("ok", "HMAC-SHA1"))
        self.assertEqual(cr.identify_hash("$pbkdf2-sha512$220000$c2FsdA$aGFzaA")["password_storage"], "strong")

    def test_cms_and_directory_formats(self):
        cases = {
            "$P$B" + "a" * 30: ("phpass (portable, iterated MD5)", "weak"),
            "$wp$2y$10$" + "b" * 53: ("bcrypt (WordPress 6.8+)", "strong"),
            "$S$D" + "c" * 51: ("Drupal 7 (iterated SHA-512)", "ok"),
            "{SSHA}RkFLRWZha2VGQUtFc2FsdA==": ("LDAP {SSHA}", "weak"),
            "{CRYPT}$2b$12$" + "d" * 53: ("LDAP {CRYPT}: bcrypt", "strong"),
            "bcrypt_sha256$$2b$12$" + "e" * 53: ("Django bcrypt_sha256: bcrypt", "strong"),
            "argon2$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g": ("Django argon2: argon2id", "strong"),
        }
        for value, (name, storage) in cases.items():
            with self.subTest(name=name):
                r = cr.identify_hash(value)
                self.assertEqual((r["candidates"], r["password_storage"]), ([name], storage))
                self.assertNotIn(value[8:], r["input"])
        for value in ["$P$tooShort", "{CRYPT}", "{CRYPT}plainvalue", "$wp$2y$10$short"]:
            with self.subTest(value=value):
                self.assertEqual(cr.identify_hash(value)["candidates"], [])

    def test_cli_masks_input(self):
        code, out, _ = call_main(cr, ["--hash-id", "-", "--json"], stdin=(EX / "hashes.txt").read_text())
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(len(data["results"]), 11)
        self.assertNotIn("5f4dcc3b5aa765d61d8327deb882cf99", out)
        self.assertEqual(call_main(cr, ["--hash-id", "-"], stdin="\n")[0], 2)

    def test_help_subprocess(self):
        self.assertEqual(run_cli("crypto-tls", "crypto_review", "--help").returncode, 0)


if __name__ == "__main__":
    unittest.main()
