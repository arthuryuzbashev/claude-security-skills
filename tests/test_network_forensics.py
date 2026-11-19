import json
import os
import struct
import ipaddress
import tempfile
import unittest

from _helpers import call_main, load_script, run_cli, skill_path

pcapsum = load_script("network-forensics", "pcap_summary")
beacon = load_script("network-forensics", "beacon_detect")
EX = skill_path("network-forensics", "examples")
T0 = 1772611200.0  # 2026-03-04T08:00:00Z


def ids(findings):
    return {f["id"] for f in findings}


# ---------------------------------------------------------------- tiny packet builders

def eth(payload, etype=0x0800):
    return b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + struct.pack(">H", etype) + payload

def ipv4(src, dst, proto, payload):
    total = 20 + len(payload)
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, proto, 0,
                       ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed) + payload

def udp(sport, dport, payload):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload

def tcp(sport, dport, payload=b"", flags=0x18):
    return struct.pack(">HHIIBBHHH", sport, dport, 1, 1, 5 << 4, flags, 65535, 0, 0) + payload

def dns_query(name, qtype=1, qid=1, response=False, rcode=0):
    flags = 0x0100 | (0x8000 if response else 0) | rcode
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0) + q + struct.pack(">HH", qtype, 1)

def http_get(host, ua, path="/"):
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: */*\r\n\r\n".encode()

def client_hello(sni):
    name = sni.encode()
    sni_ext = struct.pack(">HBH", len(name) + 3, 0, len(name)) + name
    exts = struct.pack(">HH", 0, len(sni_ext)) + sni_ext
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00" + struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs

def full_client_hello(sni="www.example.test", alpn=(b"h2", b"http/1.1"), grease=True):
    """ClientHello with the cipher and extension set of the JA4 spec example."""
    ciphers = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
               0x009c, 0x009d, 0x002f, 0x0035]
    if grease:
        ciphers = [0x0a0a] + ciphers
    def ext(t, body=b""):
        return struct.pack(">HH", t, len(body)) + body
    exts = ext(0x2a2a) if grease else b""
    if sni is not None:
        name = sni.encode()
        exts += ext(0, struct.pack(">HBH", len(name) + 3, 0, len(name)) + name)
    for t in (0x0017, 0xff01, 0x000a, 0x000b, 0x0023):
        exts += ext(t)
    if alpn:
        lst = b"".join(bytes([len(a)]) + a for a in alpn)
        exts += ext(0x0010, struct.pack(">H", len(lst)) + lst)
    exts += ext(0x0005)
    sigs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    exts += ext(0x000d, struct.pack(">H", 2 * len(sigs)) + b"".join(struct.pack(">H", x) for x in sigs))
    for t in (0x0012, 0x0033, 0x002d):
        exts += ext(t)
    exts += ext(0x002b, bytes([6]) + struct.pack(">HHH", 0x3a3a, 0x0304, 0x0303))
    for t in (0x001b, 0x4469, 0x0015):
        exts += ext(t)
    cs = b"".join(struct.pack(">H", c) for c in ciphers)
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack(">H", len(cs)) + cs + b"\x01\x00" + \
        struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def pcap(packets, linktype=1):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for ts, frame in packets:
        out += struct.pack("<IIII", int(ts), int(round((ts % 1) * 1e6)), len(frame), len(frame)) + frame
    return out

def pcapng(packets, linktype=1):
    def block(btype, body):
        body += b"\x00" * (-len(body) % 4)
        ln = 12 + len(body)
        return struct.pack("<II", btype, ln) + body + struct.pack("<I", ln)
    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack("<HHI", linktype, 0, 65535))
    for ts, frame in packets:
        t = int(round(ts * 1e6))
        out += block(6, struct.pack("<IIIII", 0, t >> 32, t & 0xFFFFFFFF, len(frame), len(frame)) + frame)
    return out


def write_tmp(test, data, suffix):
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)
    test.addCleanup(os.remove, path)
    return path


def dns_pkt(name, qtype=1, ts=T0, src="192.0.2.10", resp=False, rcode=0):
    a, b = ("192.0.2.53", src) if resp else (src, "192.0.2.53")
    return ts, eth(ipv4(a, b, 17, udp(53 if resp else 53000, 53000 if resp else 53, dns_query(name, qtype, response=resp, rcode=rcode))))


class PcapParsingTests(unittest.TestCase):
    def test_pcap_and_pcapng_give_same_counts(self):
        pk = [dns_pkt("www.example.test", ts=T0 + i) for i in range(3)]
        a, b = pcapsum.summarize(pcap(pk)), pcapsum.summarize(pcapng(pk))
        self.assertEqual((a["format"], b["format"]), ("pcap", "pcapng"))
        self.assertEqual(a["packets"], 3)
        self.assertEqual(b["packets"], 3)
        self.assertEqual(a["first_ts"], "2026-03-04T08:00:00.000Z")
        self.assertEqual(b["duration_s"], 2.0)
        self.assertEqual(a["dns_queries"], [{"name": "www.example.test", "type": "A", "count": 3}])

    def test_big_endian_and_raw_ip(self):
        frame = ipv4("192.0.2.1", "192.0.2.2", 17, udp(1234, 53, dns_query("a.example.test")))
        data = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
        data += struct.pack(">IIII", int(T0), 0, len(frame), len(frame)) + frame
        r = pcapsum.summarize(data)
        self.assertEqual(r["linktypes"], {"raw": 1})
        self.assertEqual(r["dns_queries"][0]["name"], "a.example.test")

    def test_vlan_tag(self):
        inner = ipv4("192.0.2.1", "192.0.2.2", 6, tcp(5000, 80, http_get("www.example.test", "Mozilla/5.0")))
        frame = eth(struct.pack(">HH", 10, 0x0800) + inner, etype=0x8100)
        r = pcapsum.summarize(pcap([(T0, frame)]))
        self.assertEqual(r["http_requests"][0]["host"], "www.example.test")

    def test_rejects_non_capture(self):
        with self.assertRaises(pcapsum.CaptureError):
            pcapsum.summarize(b"this is not a capture file at all, sorry")
        with self.assertRaises(pcapsum.CaptureError):
            pcapsum.summarize(pcap([]))

    def test_tls_sni(self):
        self.assertEqual(pcapsum.parse_tls_sni(client_hello("portal.example.test")), "portal.example.test")
        self.assertIsNone(pcapsum.parse_tls_sni(b"\x17\x03\x03" + b"\x00" * 60))

    def test_dns_compression_pointer(self):
        msg = struct.pack(">HHHHHH", 1, 0x0100, 2, 0, 0, 0)
        msg += b"\x03www\x07example\x04test\x00" + struct.pack(">HH", 1, 1)
        msg += b"\x04mail\xc0\x10" + struct.pack(">HH", 28, 1)  # pointer to "example.test"
        d = pcapsum.parse_dns(msg)
        self.assertEqual(d["questions"], [("www.example.test", "A"), ("mail.example.test", "AAAA")])


class PcapFindingTests(unittest.TestCase):
    def test_dns_tunnel_names(self):
        pk = [dns_pkt(f"{'ab12cd34ef56' * 4}{i}.t.example.test", qtype=16, ts=T0 + i) for i in range(12)]
        found = ids(pcapsum.summarize(pcap(pk))["findings"])
        self.assertIn("NET-001", found)
        self.assertIn("NET-003", found)

    def test_normal_dns_is_quiet(self):
        pk = [dns_pkt(n, ts=T0 + i) for i, n in enumerate(["www.example.test", "mail.example.test", "cdn.example.test"])]
        self.assertEqual(pcapsum.summarize(pcap(pk))["findings"], [])

    def test_many_subdomains_and_nxdomain(self):
        pk = [dns_pkt(f"host{i}.example.test", ts=T0 + i) for i in range(30)]
        pk += [dns_pkt(f"qz{i}x.example.test", ts=T0 + 40 + i, resp=True, rcode=3) for i in range(20)]
        found = ids(pcapsum.summarize(pcap(pk))["findings"])
        self.assertIn("NET-002", found)
        self.assertIn("NET-004", found)

    def test_suspicious_port_and_scan(self):
        pk = [(T0 + i, eth(ipv4("192.0.2.10", "192.0.2.99", 6, tcp(40000, p, flags=0x02)))) for i, p in enumerate(range(1, 25))]
        pk.append((T0 + 30, eth(ipv4("192.0.2.10", "203.0.113.50", 6, tcp(40001, 4444, flags=0x02)))))
        r = pcapsum.summarize(pcap(pk))
        found = ids(r["findings"])
        self.assertIn("NET-030", found)
        self.assertIn("NET-010", found)
        self.assertEqual(r["findings"][0]["severity"], "high", "findings sorted by severity")

    def test_few_syns_is_not_a_scan(self):
        pk = [(T0 + i, eth(ipv4("192.0.2.10", "192.0.2.99", 6, tcp(40000, p, flags=0x02)))) for i, p in enumerate((80, 443, 22))]
        self.assertNotIn("NET-030", ids(pcapsum.summarize(pcap(pk))["findings"]))

    def test_http_to_ip_with_tool_ua(self):
        pk = [(T0, eth(ipv4("192.0.2.10", "198.51.100.23", 6, tcp(49200, 80, http_get("198.51.100.23", "curl/8.5.0")))))]
        found = ids(pcapsum.summarize(pcap(pk))["findings"])
        self.assertIn("NET-020", found)
        self.assertIn("NET-021", found)

    def test_http_to_internal_ip_and_browser_is_quiet(self):
        pk = [(T0, eth(ipv4("192.168.1.10", "192.168.1.20", 6, tcp(49200, 80, http_get("192.168.1.20", "Mozilla/5.0")))))]
        self.assertEqual(pcapsum.summarize(pcap(pk))["findings"], [])

    def test_odd_sni(self):
        pk = [(T0, eth(ipv4("192.0.2.10", "203.0.113.66", 6, tcp(49202, 443, client_hello("x7k2q9v4m1z8w3n6p5r0t2y7.example.test")))))]
        self.assertIn("NET-040", ids(pcapsum.summarize(pcap(pk))["findings"]))
        pk = [(T0, eth(ipv4("192.0.2.10", "203.0.113.66", 6, tcp(49202, 443, client_hello("www.example.test")))))]
        self.assertEqual(pcapsum.summarize(pcap(pk))["findings"], [])

    def test_example_capture(self):
        r = pcapsum.summarize((EX / "sample.pcap").read_bytes())
        self.assertEqual(r["packets"], 19)
        self.assertTrue({"NET-001", "NET-010", "NET-020", "NET-021", "NET-040"} <= ids(r["findings"]))


class Ja4Tests(unittest.TestCase):
    def test_spec_example(self):
        hello = pcapsum.parse_client_hello(full_client_hello())
        self.assertEqual(hello["sni"], "www.example.test")
        self.assertEqual(hello["alpn"][0], b"h2")
        self.assertEqual(pcapsum.ja4(hello), "t13d1516h2_8daaf6152771_e5627efa2ab1")

    def test_grease_is_ignored(self):
        a = pcapsum.ja4(pcapsum.parse_client_hello(full_client_hello(grease=True)))
        b = pcapsum.ja4(pcapsum.parse_client_hello(full_client_hello(grease=False)))
        self.assertEqual(a, b)

    def test_no_sni_no_alpn(self):
        fp = pcapsum.ja4(pcapsum.parse_client_hello(full_client_hello(sni=None, alpn=())))
        self.assertTrue(fp.startswith("t13i151400_8daaf6152771_"), fp)

    def test_non_alnum_alpn_uses_hex(self):
        fp = pcapsum.ja4(pcapsum.parse_client_hello(full_client_hello(alpn=(b"\xab\xcd",))))
        self.assertEqual(fp.split("_")[0][-2:], "ad")

    def test_minimal_hello_and_not_tls(self):
        hello = pcapsum.parse_client_hello(client_hello("a.example.test"))
        self.assertEqual(pcapsum.ja4(hello), "t12d010100_" + pcapsum._sha12("1301") + "_000000000000")
        self.assertIsNone(pcapsum.parse_client_hello(b"GET / HTTP/1.1\r\n" + b"x" * 40))

    def test_summary_lists_ja4(self):
        pk = [(T0, eth(ipv4("192.0.2.10", "203.0.113.80", 6, tcp(49300, 443, full_client_hello()))))]
        r = pcapsum.summarize(pcap(pk))
        self.assertEqual(r["tls_ja4"][0]["ja4"], "t13d1516h2_8daaf6152771_e5627efa2ab1")
        self.assertEqual(r["tls_ja4"][0]["alpn"], ["h2"])
        self.assertEqual(r["findings"], [])


class EncryptedDnsAndSniTests(unittest.TestCase):
    def test_doh_sni_flagged(self):
        pk = [(T0, eth(ipv4("192.0.2.10", "203.0.113.9", 6, tcp(49301, 443, full_client_hello("dns.google")))))]
        self.assertIn("NET-041", ids(pcapsum.summarize(pcap(pk))["findings"]))

    def test_dot_port_flagged_only_to_public(self):
        pk = [(T0, eth(ipv4("192.168.1.10", "9.9.9.9", 6, tcp(49302, 853, b"", flags=0x02))))]
        self.assertIn("NET-041", ids(pcapsum.summarize(pcap(pk))["findings"]))
        pk = [(T0, eth(ipv4("192.168.1.10", "192.168.1.1", 6, tcp(49302, 853, b"", flags=0x02))))]
        self.assertNotIn("NET-041", ids(pcapsum.summarize(pcap(pk))["findings"]))

    def test_no_sni_to_public_ip(self):
        pk = [(T0, eth(ipv4("192.168.1.10", "198.51.100.7", 6, tcp(49303, 443, full_client_hello(sni=None)))))]
        r = pcapsum.summarize(pcap(pk))
        self.assertIn("NET-042", ids(r["findings"]))
        self.assertEqual(r["tls_no_sni"][0]["dst"], "198.51.100.7")
        pk = [(T0, eth(ipv4("192.168.1.10", "192.168.1.20", 6, tcp(49303, 443, full_client_hello(sni=None)))))]
        self.assertNotIn("NET-042", ids(pcapsum.summarize(pcap(pk))["findings"]))


class PcapCliTests(unittest.TestCase):
    def test_json_shape_and_exit_codes(self):
        code, out, _ = call_main(pcapsum, [str(EX / "sample.pcap"), "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        for key in ("format", "packets", "bytes", "first_ts", "last_ts", "protocols", "top_talkers",
                    "dns_queries", "http_requests", "tls_sni", "findings"):
            self.assertIn(key, data)
        for f in data["findings"]:
            self.assertTrue({"id", "severity", "title", "detail", "fix"} <= set(f))
        code, _, _ = call_main(pcapsum, [str(EX / "sample.pcap"), "--fail-on", "never"])
        self.assertEqual(code, 0)

    def test_clean_capture_exit_zero(self):
        path = write_tmp(self, pcap([dns_pkt("www.example.test")]), ".pcap")
        code, out, _ = call_main(pcapsum, [path])
        self.assertEqual(code, 0)
        self.assertIn("No findings", out)

    def test_bad_input_exit_two(self):
        path = write_tmp(self, b"not a pcap" * 5, ".pcap")
        self.assertEqual(call_main(pcapsum, [path])[0], 2)
        self.assertEqual(call_main(pcapsum, ["/nonexistent/x.pcap"])[0], 2)

    def test_stdin_and_help_subprocess(self):
        self.assertEqual(run_cli("network-forensics", "pcap_summary", "--help").returncode, 0)
        import subprocess, sys
        p = subprocess.run([sys.executable, str(skill_path("network-forensics", "scripts", "pcap_summary.py")), "-"],
                           input=(EX / "sample.pcap").read_bytes(), capture_output=True, timeout=60)
        self.assertEqual(p.returncode, 1)
        self.assertIn(b"NET-001", p.stdout)


def conn_rows(src, dst, port, start, every, n, jitter=(0,), size=300):
    rows = []
    t = start
    for i in range(n):
        rows.append({"ts": t, "src": src, "dst": dst, "dport": port, "bytes": size})
        t += every + jitter[i % len(jitter)]
    return rows


class BeaconTests(unittest.TestCase):
    def test_regular_flow_scores_high(self):
        recs = conn_rows("192.0.2.10", "203.0.113.50", 443, T0, 60, 40, jitter=(-2, 1, 3, -1))
        r = beacon.detect(recs)
        self.assertEqual(r["findings"][0]["id"], "BCN-001")
        self.assertEqual(r["findings"][0]["severity"], "high")
        self.assertGreaterEqual(r["candidates"][0]["score"], 80)

    def test_irregular_flow_is_quiet(self):
        gaps = (5, 400, 30, 900, 12, 250, 2, 700, 60, 1500)
        recs, t = [], T0
        for i, g in enumerate(gaps * 2):
            recs.append({"ts": t, "src": "192.0.2.10", "dst": "198.51.100.7", "dport": 443, "bytes": 200 + i * 997 % 50000})
            t += g
        r = beacon.detect(recs)
        self.assertEqual(r["findings"], [])
        self.assertLess(r["candidates"][0]["score"], 50)

    def test_min_conns_and_allow(self):
        recs = conn_rows("192.0.2.10", "203.0.113.50", 443, T0, 60, 5)
        self.assertEqual(beacon.detect(recs)["candidates"], [], "5 connections is below the default of 6")
        recs = conn_rows("192.0.2.10", "203.0.113.50", 443, T0, 60, 30)
        r = beacon.detect(recs, allow=beacon.parse_allow(["203.0.113.0/24"]))
        self.assertEqual((r["findings"], r["ignored_by_allow"]), ([], 30))
        r = beacon.detect(recs, allow=beacon.parse_allow(["updates.example.test,192.0.2.99"]))
        self.assertEqual(len(r["findings"]), 1)

    def test_time_parsing(self):
        self.assertEqual(beacon.parse_time("2026-03-04T08:00:00Z"), T0)
        self.assertEqual(beacon.parse_time(str(T0 * 1000)), T0)
        self.assertEqual(beacon.parse_time("-"), None)
        self.assertIsNone(beacon.parse_time("yesterday"))

    def test_formats(self):
        z = (EX / "conn.log").read_text()
        recs, skipped, fmt = beacon.load_records(z)
        self.assertEqual((fmt, skipped), ("zeek", 0))
        self.assertTrue(all(r["dport"] is not None for r in recs))
        jl = "\n".join(json.dumps({"timestamp": T0 + i * 60, "src_ip": "192.0.2.1", "dst_ip": "192.0.2.2"}) for i in range(8))
        self.assertEqual(beacon.load_records(jl + "\nnot json\n")[1:], (1, "jsonl"))
        arr = json.dumps([{"ts": T0, "src": "a", "dst": "b"}, {"src": "a"}])
        self.assertEqual(beacon.load_records(arr)[1:], (1, "json"))
        with self.assertRaises(beacon.InputError):
            beacon.load_records("a,b,c\n1,2,3\n")
        with self.assertRaises(beacon.InputError):
            beacon.load_records("   ")

    def test_examples(self):
        for name, dst in (("conn.log", "203.0.113.50"), ("conns.csv", "198.51.100.99")):
            recs, _, _ = beacon.load_records((EX / name).read_text())
            r = beacon.detect(recs)
            self.assertEqual(len(r["findings"]), 1, name)
            self.assertIn(dst, r["findings"][0]["title"])

    def test_cli_json_and_exit_codes(self):
        code, out, _ = call_main(beacon, [str(EX / "conn.log"), "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertTrue({"format", "records", "skipped", "groups", "candidates", "findings"} <= set(data))
        self.assertTrue({"id", "severity", "title", "detail", "fix", "location"} <= set(data["findings"][0]))
        code, _, _ = call_main(beacon, [str(EX / "conn.log"), "--allow", "203.0.113.50"])
        self.assertEqual(code, 0)
        code, _, err = call_main(beacon, ["-"], stdin="")
        self.assertEqual(code, 2)
        self.assertIn("empty", err)
        csv_text = (EX / "conns.csv").read_text()
        self.assertEqual(call_main(beacon, ["-", "--fail-on", "never"], stdin=csv_text)[0], 0)

    def test_help_subprocess(self):
        self.assertEqual(run_cli("network-forensics", "beacon_detect", "--help").returncode, 0)
        p = run_cli("network-forensics", "beacon_detect", str(EX / "conns.csv"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("BCN-001", p.stdout)


def eve_lines(n, gap=120.0, extra_events=True):
    out = []
    for i in range(n):
        start = T0 + i * gap
        flow = {"timestamp": f"2026-03-04T09:00:{i % 60:02d}.000000+0000", "event_type": "flow",
                "src_ip": "192.0.2.30", "src_port": 50000 + i, "dest_ip": "198.51.100.44", "dest_port": 443,
                "proto": "TCP", "flow": {"start": start, "end": start + 2, "age": 2, "bytes_toserver": 640,
                                         "bytes_toclient": 1200}}
        out.append(json.dumps(flow))
        if extra_events:
            out.append(json.dumps({"timestamp": start, "event_type": "tls", "src_ip": "192.0.2.30",
                                   "dest_ip": "198.51.100.44", "dest_port": 443, "tls": {"sni": "c2.example.test"}}))
    return "\n".join(out) + "\n"


class BeaconInputTests(unittest.TestCase):
    def test_suricata_eve_flows_only(self):
        recs, skipped, fmt = beacon.load_records(eve_lines(30))
        self.assertEqual(fmt, "jsonl")
        self.assertEqual(recs[0]["bytes"], 640)
        self.assertEqual(recs[0]["duration"], 2)
        r = beacon.detect(recs)
        self.assertEqual(r["other_events_skipped"], 30)
        self.assertEqual(r["candidates"][0]["connections"], 30)
        self.assertIn("BCN-001", ids(r["findings"]))

    def test_eve_without_flow_events_keeps_all(self):
        recs, _, _ = beacon.load_records(json.dumps({"timestamp": T0, "event_type": "alert", "src_ip": "192.0.2.1",
                                                     "dest_ip": "192.0.2.2", "dest_port": 80}))
        self.assertEqual(beacon.detect(recs)["other_events_skipped"], 0)

    def test_flatten_dns_v3(self):
        row = {"dns": {"queries": [{"rrname": "A.Example.Test.", "rrtype": "A"}]}, "src_ip": "192.0.2.5",
               "dest_ip": "192.0.2.53", "timestamp": T0}
        recs, _ = beacon.normalize([row])
        self.assertEqual(recs[0]["name"], "a.example.test")


class LongConnectionTests(unittest.TestCase):
    def rows(self, duration):
        recs = [{"ts": T0 + i * 977.0, "src": "192.0.2.10", "dst": "198.51.100.%d" % i, "dport": 443,
                 "bytes": 100, "duration": 5.0} for i in range(10)]
        recs.append({"ts": T0, "src": "192.0.2.11", "dst": "203.0.113.9", "dport": 8443, "bytes": 900,
                     "duration": duration})
        return recs

    def test_long_connection_flagged(self):
        r = beacon.detect(self.rows(5 * 3600.0))
        f = [x for x in r["findings"] if x["id"] == "BCN-002"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "low")
        self.assertEqual(r["long_connections"][0]["dst"], "203.0.113.9")
        r = beacon.detect(self.rows(10 * 3600.0))
        self.assertEqual([x for x in r["findings"] if x["id"] == "BCN-002"][0]["severity"], "medium")

    def test_short_or_allowed_is_quiet(self):
        self.assertNotIn("BCN-002", ids(beacon.detect(self.rows(1800.0))["findings"]))
        allow = beacon.parse_allow(["203.0.113.0/24"])
        self.assertNotIn("BCN-002", ids(beacon.detect(self.rows(9 * 3600.0), allow=allow)["findings"]))
        self.assertNotIn("BCN-002", ids(beacon.detect(self.rows(9 * 3600.0), long_conn=0)["findings"]))

    def test_cli_long_conn_flag(self):
        lines = "\n".join(json.dumps({"ts": T0 + i, "src": "192.0.2.11", "dst": "203.0.113.9", "dport": 22,
                                       "duration": 7200 if i == 0 else 3}) for i in range(3))
        code, out, _ = call_main(beacon, ["-", "--json", "--fail-on", "low"], stdin=lines)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["long_connections"][0]["longest_s"], 7200)
        code, _, _ = call_main(beacon, ["-", "--long-conn", "10000", "--fail-on", "low"], stdin=lines)
        self.assertEqual(code, 0)


class ByNameTests(unittest.TestCase):
    def test_rotating_ips_found_by_name(self):
        recs = [{"ts": T0 + i * 300.0, "src": "192.0.2.10", "dst": "198.51.100.%d" % (i % 7), "dport": 443,
                 "bytes": 512, "name": "cdn-c2.example.test"} for i in range(30)]
        self.assertEqual(beacon.detect(recs)["findings"], [])
        r = beacon.detect(recs, by_name=True)
        self.assertEqual(r["grouped_by"], "name")
        self.assertIn("BCN-001", ids(r["findings"]))
        self.assertIn("cdn-c2.example.test", r["findings"][0]["title"])

    def test_by_name_needs_names(self):
        recs = [{"ts": T0 + i, "src": "192.0.2.10", "dst": "198.51.100.1", "dport": 443, "bytes": 1} for i in range(8)]
        with self.assertRaises(beacon.InputError):
            beacon.detect(recs, by_name=True)


if __name__ == "__main__":
    unittest.main()
