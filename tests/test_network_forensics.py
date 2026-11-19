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


if __name__ == "__main__":
    unittest.main()
