import base64
import json
import unittest

from _helpers import call_main, load_script, run_cli, skill_path

headers = load_script("web-appsec", "header_audit")
jwt = load_script("web-appsec", "jwt_inspect")
EX = skill_path("web-appsec", "examples")


def ids(findings):
    return {f["id"] for f in findings}


def make_jwt(header, payload, sig="c2ln"):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc(header)}.{enc(payload)}.{sig}"


class HeaderAuditTests(unittest.TestCase):
    def test_weak_example_flags_the_big_ones(self):
        raw = (EX / "weak_headers.txt").read_text()
        h, status = headers.parse_raw_headers(raw)
        self.assertEqual(status, 200, "should grade the final response after the redirect")
        found = ids(headers.audit(h))
        for expected in ("HDR-001", "HDR-012", "HDR-014", "HDR-020", "HDR-040", "HDR-050", "CK-001"):
            self.assertIn(expected, found)

    def test_strong_example_is_clean(self):
        h, _ = headers.parse_raw_headers((EX / "strong_headers.txt").read_text())
        findings = headers.audit(h)
        self.assertEqual(findings, [])
        self.assertEqual(headers.score(findings), (100, "A"))

    def test_short_hsts(self):
        h = {"strict-transport-security": ["max-age=3600"]}
        self.assertIn("HDR-002", ids(headers.check_hsts(h, True)))
        self.assertEqual(headers.check_hsts({}, False), [], "no HSTS check on plain http")

    def test_nonce_keeps_unsafe_inline_quiet(self):
        h = {"content-security-policy": ["script-src 'self' 'unsafe-inline' 'nonce-abc'; object-src 'none'"]}
        self.assertNotIn("HDR-012", ids(headers.check_csp(h)))

    def test_session_cookie_is_medium(self):
        f = headers.check_cookies({"set-cookie": ["sessionid=1; Path=/"]}, True)
        self.assertEqual(f[0]["severity"], "medium")

    def test_cli_json_and_exit_codes(self):
        code, out, _ = call_main(headers, ["--file", str(EX / "weak_headers.txt"), "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(set(data), {"target", "status", "score", "grade", "findings"})
        code, _, _ = call_main(headers, ["--file", str(EX / "strong_headers.txt")])
        self.assertEqual(code, 0)
        code, _, _ = call_main(headers, ["--file", "-"], stdin="garbage")
        self.assertEqual(code, 2)

    def test_help_subprocess(self):
        self.assertEqual(run_cli("web-appsec", "header_audit", "--help").returncode, 0)

    def test_hsts_without_subdomains(self):
        self.assertIn("HDR-003", ids(headers.check_hsts({"strict-transport-security": ["max-age=63072000"]}, True)))
        self.assertEqual(headers.check_hsts({"strict-transport-security": ["max-age=63072000; includeSubDomains"]}, True), [])

    def test_strict_dynamic_is_not_a_wildcard(self):
        strict = {"content-security-policy": ["script-src 'nonce-abc' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'"]}
        self.assertEqual(headers.check_csp(strict), [])
        loose = {"content-security-policy": ["script-src 'self' 'strict-dynamic' https:; object-src 'none'"]}
        self.assertIn("HDR-014", ids(headers.check_csp(loose)), "strict-dynamic without a nonce does not neutralize https:")

    def test_nonce_policy_needs_base_uri(self):
        h = {"content-security-policy": ["script-src 'nonce-abc'; object-src 'none'"]}
        self.assertIn("HDR-017", ids(headers.check_csp(h)))
        h = {"content-security-policy": ["default-src 'self'; object-src 'none'"]}
        self.assertNotIn("HDR-017", ids(headers.check_csp(h)), "host-based policies do not need it")

    def test_xss_protection_header(self):
        self.assertIn("HDR-033", ids(headers.check_simple({"x-xss-protection": ["1; mode=block"]})))
        self.assertNotIn("HDR-033", ids(headers.check_simple({"x-xss-protection": ["0"]})))

    def test_coop_only_on_html(self):
        self.assertIn("HDR-034", ids(headers.check_simple({"content-type": ["text/html"]})))
        self.assertNotIn("HDR-034", ids(headers.check_simple({"content-type": ["application/json"]})))
        self.assertNotIn("HDR-034", ids(headers.check_simple({"content-type": ["text/html"], "cross-origin-opener-policy": ["same-origin"]})))

    def test_null_origin(self):
        f = headers.check_simple({"access-control-allow-origin": ["null"], "access-control-allow-credentials": ["true"]})
        self.assertEqual([x["severity"] for x in f if x["id"] == "HDR-042"], ["high"])
        f = headers.check_simple({"access-control-allow-origin": ["https://app.example.test"]})
        self.assertNotIn("HDR-042", ids(f))

    def test_source_map_and_extra_version_headers(self):
        found = ids(headers.check_simple({"sourcemap": ["/static/app.js.map"], "x-generator": ["Drupal 10"]}))
        self.assertTrue({"HDR-052", "HDR-050"} <= found)
        self.assertFalse({"HDR-052", "HDR-050"} & ids(headers.check_simple({"server": ["nginx"]})))

    def test_cookie_prefix_rules(self):
        bad = headers.check_cookies({"set-cookie": ["__Host-sid=1; Path=/app; Domain=example.test; Secure; HttpOnly; SameSite=Lax"]}, True)
        self.assertIn("CK-003", ids(bad))
        bad = headers.check_cookies({"set-cookie": ["__Secure-id=1; Path=/; HttpOnly; SameSite=Lax"]}, False)
        self.assertIn("CK-003", ids(bad))
        good = headers.check_cookies({"set-cookie": ["__Host-sid=1; Path=/; Secure; HttpOnly; SameSite=Lax"]}, True)
        self.assertEqual(good, [])


class JwtInspectTests(unittest.TestCase):
    def test_unsigned_example(self):
        token = (EX / "unsigned.jwt").read_text()
        h, p, sig = jwt.decode(token)
        found = ids(jwt.analyze(h, p, sig))
        self.assertTrue({"JWT-001", "JWT-010", "JWT-020"} <= found)

    def test_password_is_masked_in_output(self):
        code, out, _ = call_main(jwt, ["--file", str(EX / "unsigned.jwt"), "--json"])
        self.assertEqual(code, 1)
        self.assertNotIn("hunter2", out)
        self.assertEqual(json.loads(out)["payload"]["password"], "hunt...")

    def test_good_token_is_quiet(self):
        t = make_jwt({"alg": "RS256", "kid": "k1"}, {"iss": "a", "aud": "b", "iat": 1000, "exp": 1900})
        h, p, s = jwt.decode("Bearer " + t)
        self.assertEqual(jwt.analyze(h, p, s, now=1500), [])

    def test_remote_key_and_kid_injection(self):
        t = make_jwt({"alg": "RS256", "jku": "https://evil.test/k", "kid": "../../dev/null"}, {"exp": 2, "iss": "a", "aud": "b"})
        found = ids(jwt.analyze(*jwt.decode(t), now=1))
        self.assertTrue({"JWT-003", "JWT-005"} <= found)

    def test_x5c_header(self):
        t = make_jwt({"alg": "RS256", "x5c": ["MIIfake"]}, {"exp": 2, "iss": "a", "aud": "b"})
        self.assertIn("JWT-006", ids(jwt.analyze(*jwt.decode(t), now=1)))

    def test_future_iat(self):
        t = make_jwt({"alg": "RS256"}, {"iss": "a", "aud": "b", "iat": 5000, "exp": 6000})
        self.assertIn("JWT-014", ids(jwt.analyze(*jwt.decode(t), now=1000)))
        self.assertNotIn("JWT-014", ids(jwt.analyze(*jwt.decode(t), now=4900)), "inside the 5 minute skew")

    def test_bad_input(self):
        code, _, err = call_main(jwt, ["not-a-token"])
        self.assertEqual(code, 2)
        self.assertIn("expected 3", err)


if __name__ == "__main__":
    unittest.main()
