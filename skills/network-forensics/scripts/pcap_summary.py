#!/usr/bin/env python3
"""Summarize a packet capture (pcap or pcapng) without tshark or scapy.

Pure-Python parser for classic pcap (microsecond and nanosecond, both byte
orders) and pcapng (SHB, IDB, EPB, SPB), with Ethernet (incl. VLAN tags),
Linux cooked capture v1/v2, raw IP and BSD loopback link types, IPv4/IPv6,
TCP and UDP. Reports top talkers, protocols, ports, DNS queries, HTTP
Host/User-Agent from cleartext requests, TLS SNI and the JA4 client
fingerprint from ClientHello, and flags long or random-looking DNS names
(possible tunneling), encrypted DNS to public resolvers, TLS without SNI
and odd ports.

Reads a saved file only; it never captures traffic.

Usage:
  pcap_summary.py capture.pcap
  pcap_summary.py capture.pcapng --top 20 --json
  pcap_summary.py capture.pcap --fail-on medium
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import re
import struct
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

LINKTYPES = {0: "null", 1: "ethernet", 101: "raw", 113: "linux_sll", 228: "ipv4", 229: "ipv6", 276: "linux_sll2"}
IP_PROTOS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6", 132: "SCTP"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
             64: "SVCB", 65: "HTTPS", 255: "ANY", 10: "NULL"}
COMMON_PORTS = {20, 21, 22, 23, 25, 53, 67, 68, 80, 88, 110, 123, 135, 137, 138, 139, 143, 161, 162, 389, 443, 445,
                465, 514, 587, 636, 853, 993, 995, 1194, 1433, 1521, 1900, 3306, 3389, 5060, 5061, 5222, 5353, 5355,
                5432, 5900, 5985, 5986, 6379, 8000, 8008, 8080, 8443, 8888, 9200, 27017, 51820}
SUSPICIOUS_PORTS = {
    4444: "Metasploit default handler", 1337: "common backdoor/test port", 31337: "classic backdoor port",
    6667: "IRC (old botnet C2)", 6697: "IRC over TLS", 9001: "Tor ORPort default", 9050: "Tor SOCKS",
    9150: "Tor Browser SOCKS", 5555: "Android debug bridge", 2323: "alt telnet (IoT botnets)", 23: "telnet",
}
HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")
TOOL_UA = re.compile(r"(?i)^(curl|wget|python-requests|python-urllib|go-http-client|powershell|winhttp|java/|"
                     r"libwww-perl|okhttp|aiohttp|httpie|nmap|masscan|sqlmap|nikto)|WindowsPowerShell|^$")


class CaptureError(ValueError):
    pass


def finding(fid: str, severity: str, title: str, detail: str, fix: str, location: str = "") -> Dict[str, str]:
    f = {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}
    if location:
        f["location"] = location
    return f


# ---------------------------------------------------------------- file formats

def read_packets(data: bytes) -> Tuple[str, Iterator[Tuple[float, int, bytes, int]]]:
    """Return (format, iterator of (timestamp, linktype, frame bytes, original length))."""
    if len(data) < 24:
        raise CaptureError("file too short to be a capture")
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return "pcap", _pcap(data)
    if magic == b"\x0a\x0d\x0d\x0a":
        return "pcapng", _pcapng(data)
    raise CaptureError("not a pcap or pcapng file (unknown magic)")


def _pcap(data: bytes) -> Iterator[Tuple[float, int, bytes, int]]:
    magic = data[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack_from(endian + "I", data, 20)[0] & 0xFFFF  # upper bits may carry FCS info
    off = 24
    while off + 16 <= len(data):
        sec, frac, incl, orig = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        if incl > len(data) - off:
            break  # truncated last packet
        yield sec + frac / (1e9 if nano else 1e6), linktype, data[off:off + incl], orig
        off += incl


def _pcapng(data: bytes) -> Iterator[Tuple[float, int, bytes, int]]:
    off = 0
    endian = "<"
    interfaces: List[Tuple[int, float]] = []  # (linktype, seconds per tick)
    while off + 12 <= len(data):
        btype_raw = data[off:off + 4]
        if btype_raw == b"\x0a\x0d\x0d\x0a":
            bom = data[off + 8:off + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            interfaces = []  # a new section resets interface ids
        btype, blen = struct.unpack_from(endian + "II", data, off)
        if blen < 12 or off + blen > len(data):
            break
        body = data[off + 8:off + blen - 4]
        if btype == 1 and len(body) >= 8:  # Interface Description Block
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            resol = 1e-6
            opt = 8
            while opt + 4 <= len(body):
                code, olen = struct.unpack_from(endian + "HH", body, opt)
                if code == 0:
                    break
                if code == 9 and olen >= 1:  # if_tsresol
                    v = body[opt + 4]
                    resol = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                opt += 4 + olen + (-olen % 4)
            interfaces.append((linktype, resol))
        elif btype == 6 and len(body) >= 20:  # Enhanced Packet Block
            iface, ts_hi, ts_lo, cap, orig = struct.unpack_from(endian + "IIIII", body, 0)
            if iface < len(interfaces):
                lt, resol = interfaces[iface]
                yield ((ts_hi << 32) | ts_lo) * resol, lt, body[20:20 + cap], orig
        elif btype == 3 and len(body) >= 4 and interfaces:  # Simple Packet Block, no timestamp
            orig = struct.unpack_from(endian + "I", body, 0)[0]
            lt, _ = interfaces[0]
            yield 0.0, lt, body[4:4 + orig], orig
        elif btype == 2 and len(body) >= 20:  # obsolete Packet Block
            iface, _, ts_hi, ts_lo, cap = struct.unpack_from(endian + "HHIII", body, 0)
            orig = struct.unpack_from(endian + "I", body, 16)[0] if len(body) >= 20 else cap
            if iface < len(interfaces):
                lt, resol = interfaces[iface]
                yield ((ts_hi << 32) | ts_lo) * resol, lt, body[20:20 + cap], orig
        off += blen


# ---------------------------------------------------------------- decoding

def decode_link(linktype: int, frame: bytes) -> Tuple[Optional[int], bytes]:
    """Return (ethertype, network-layer bytes)."""
    if linktype == 1:
        if len(frame) < 14:
            return None, b""
        etype = struct.unpack_from(">H", frame, 12)[0]
        off = 14
        while etype in (0x8100, 0x88A8, 0x9100) and len(frame) >= off + 4:
            etype = struct.unpack_from(">H", frame, off + 2)[0]
            off += 4
        return etype, frame[off:]
    if linktype == 113:
        return (struct.unpack_from(">H", frame, 14)[0], frame[16:]) if len(frame) >= 16 else (None, b"")
    if linktype == 276:
        return (struct.unpack_from(">H", frame, 0)[0], frame[20:]) if len(frame) >= 20 else (None, b"")
    if linktype in (101, 228, 229):
        if not frame:
            return None, b""
        ver = frame[0] >> 4
        return (0x0800 if ver == 4 else 0x86DD if ver == 6 else None), frame
    if linktype == 0:
        if len(frame) < 4:
            return None, b""
        fam = struct.unpack_from("<I", frame, 0)[0]
        if fam > 0xFFFF:
            fam = struct.unpack_from(">I", frame, 0)[0]
        return (0x0800 if fam == 2 else 0x86DD if fam in (10, 24, 28, 30) else None), frame[4:]
    return None, b""


def decode_ip(etype: Optional[int], pkt: bytes) -> Optional[Dict]:
    if etype == 0x0800 and len(pkt) >= 20 and pkt[0] >> 4 == 4:
        ihl = (pkt[0] & 0x0F) * 4
        total = struct.unpack_from(">H", pkt, 2)[0]
        frag = struct.unpack_from(">H", pkt, 6)[0] & 0x1FFF
        proto = pkt[9]
        end = min(len(pkt), total) if total >= ihl else len(pkt)
        return {"ver": 4, "src": str(ipaddress.IPv4Address(pkt[12:16])), "dst": str(ipaddress.IPv4Address(pkt[16:20])),
                "proto": proto, "payload": pkt[ihl:end] if frag == 0 else b"", "len": total or len(pkt)}
    if etype == 0x86DD and len(pkt) >= 40 and pkt[0] >> 4 == 6:
        plen = struct.unpack_from(">H", pkt, 4)[0]
        nxt, off = pkt[6], 40
        fragmented = False
        for _ in range(8):  # extension headers
            if nxt in (0, 43, 60) and off + 2 <= len(pkt):
                nxt, off = pkt[off], off + (pkt[off + 1] + 1) * 8
            elif nxt == 44 and off + 8 <= len(pkt):
                fragmented = (struct.unpack_from(">H", pkt, off + 2)[0] >> 3) != 0
                nxt, off = pkt[off], off + 8
            else:
                break
        return {"ver": 6, "src": str(ipaddress.IPv6Address(pkt[8:24])), "dst": str(ipaddress.IPv6Address(pkt[24:40])),
                "proto": nxt, "payload": b"" if fragmented else pkt[off:40 + plen], "len": 40 + plen}
    return None


def decode_l4(proto: int, seg: bytes) -> Optional[Dict]:
    if proto == 6 and len(seg) >= 20:
        sport, dport = struct.unpack_from(">HH", seg, 0)
        doff = (seg[12] >> 4) * 4
        flags = seg[13]
        return {"sport": sport, "dport": dport, "flags": flags, "payload": seg[doff:] if doff >= 20 else b""}
    if proto == 17 and len(seg) >= 8:
        sport, dport, ulen = struct.unpack_from(">HHH", seg, 0)
        return {"sport": sport, "dport": dport, "flags": 0, "payload": seg[8:ulen] if ulen >= 8 else seg[8:]}
    return None


def _dns_name(msg: bytes, off: int, depth: int = 0) -> Tuple[str, int]:
    labels, jumped, end = [], False, off
    for _ in range(128):
        if off >= len(msg):
            raise ValueError("name runs past message")
        ln = msg[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(msg) or depth > 10:
                raise ValueError("bad pointer")
            ptr = ((ln & 0x3F) << 8) | msg[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            name, _ = _dns_name(msg, ptr, depth + 1)
            labels.append(name)
            break
        off += 1
        labels.append(msg[off:off + ln].decode("latin-1"))
        off += ln
    return ".".join(l for l in labels if l), (end if jumped else off)


def parse_dns(msg: bytes) -> Optional[Dict]:
    """Return {'qr': bool, 'rcode': int, 'questions': [(name, qtype)]} or None."""
    if len(msg) < 12:
        return None
    _, flags, qd, an, ns, ar = struct.unpack_from(">HHHHHH", msg, 0)
    if qd == 0 or qd > 16:
        return None
    off, questions = 12, []
    try:
        for _ in range(qd):
            name, off = _dns_name(msg, off)
            if off + 4 > len(msg):
                return None
            qtype = struct.unpack_from(">H", msg, off)[0]
            off += 4
            questions.append((name.lower(), DNS_TYPES.get(qtype, str(qtype))))
    except ValueError:
        return None
    return {"qr": bool(flags & 0x8000), "rcode": flags & 0x000F, "questions": questions}


def parse_http_request(payload: bytes) -> Optional[Dict]:
    if not payload.startswith(HTTP_METHODS):
        return None
    head = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    lines = head.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) < 3 or not parts[2].startswith("HTTP/"):
        return None
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {"method": parts[0], "path": parts[1][:200], "host": headers.get("host", ""),
            "user_agent": headers.get("user-agent", "")}


def _is_grease(v: int) -> bool:
    """GREASE values (RFC 8701): 0x0a0a, 0x1a1a ... 0xfafa."""
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def parse_client_hello(payload: bytes) -> Optional[Dict]:
    """Fields of a TLS ClientHello that starts one TCP segment, or None.

    Returns {version, ciphers, extensions, sni, alpn, sig_algs, supported_versions}.
    A hello cut off by the segment end still returns what was read so far.
    """
    if len(payload) < 43 or payload[0] != 0x16 or payload[1] != 0x03 or payload[5] != 0x01:
        return None
    out = {"version": 0, "ciphers": [], "extensions": [], "sni": None, "alpn": [], "sig_algs": [],
           "supported_versions": []}
    try:
        out["version"] = struct.unpack_from(">H", payload, 9)[0]
        off = 5 + 4 + 2 + 32               # record hdr, handshake hdr, version, random
        off += 1 + payload[off]            # session id
        cs_len = struct.unpack_from(">H", payload, off)[0]
        cs_end = min(len(payload), off + 2 + cs_len)
        out["ciphers"] = [struct.unpack_from(">H", payload, i)[0] for i in range(off + 2, cs_end - 1, 2)]
        off += 2 + cs_len
        off += 1 + payload[off]            # compression methods
        ext_total = struct.unpack_from(">H", payload, off)[0]
        off += 2
        end = min(len(payload), off + ext_total)
        while off + 4 <= end:
            etype, elen = struct.unpack_from(">HH", payload, off)
            off += 4
            body = payload[off:off + elen]
            out["extensions"].append(etype)
            if etype == 0 and len(body) >= 5 and out["sni"] is None:
                list_len = struct.unpack_from(">H", body, 0)[0]
                p, lend = 2, min(len(body), 2 + list_len)
                while p + 3 <= lend:
                    ntype, nlen = body[p], struct.unpack_from(">H", body, p + 1)[0]
                    if ntype == 0:
                        out["sni"] = body[p + 3:p + 3 + nlen].decode("ascii", "replace").lower()
                        break
                    p += 3 + nlen
            elif etype == 16 and len(body) >= 2:          # ALPN protocol list
                p, lend = 2, min(len(body), 2 + struct.unpack_from(">H", body, 0)[0])
                while p < lend:
                    n = body[p]
                    out["alpn"].append(bytes(body[p + 1:p + 1 + n]))
                    p += 1 + n
            elif etype == 13 and len(body) >= 2:          # signature_algorithms
                lend = min(len(body), 2 + struct.unpack_from(">H", body, 0)[0])
                out["sig_algs"] = [struct.unpack_from(">H", body, i)[0] for i in range(2, lend - 1, 2)]
            elif etype == 43 and len(body) >= 1:          # supported_versions (client form)
                lend = min(len(body), 1 + body[0])
                out["supported_versions"] = [struct.unpack_from(">H", body, i)[0] for i in range(1, lend - 1, 2)]
            off += elen
    except (struct.error, IndexError):
        pass
    return out


def parse_tls_sni(payload: bytes) -> Optional[str]:
    """Server name from a TLS ClientHello in one TCP segment."""
    hello = parse_client_hello(payload)
    return hello["sni"] if hello else None


TLS_VERSION_CODES = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2",
                     0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3"}


def _sha12(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12] if text else "000000000000"


def ja4(hello: Dict, transport: str = "t") -> str:
    """JA4 TLS client fingerprint (FoxIO JA4 spec, BSD 3-Clause), computed from parsed hello fields.

    a: transport, TLS version, SNI d/i, cipher count, extension count, ALPN first+last char
    b: sha256 of the sorted cipher list, first 12 hex chars
    c: sha256 of the sorted extensions (without SNI and ALPN) + "_" + signature algorithms in order
    GREASE values are ignored everywhere.
    """
    ciphers = [c for c in hello["ciphers"] if not _is_grease(c)]
    exts = [e for e in hello["extensions"] if not _is_grease(e)]
    versions = [v for v in hello.get("supported_versions", []) if not _is_grease(v)]
    version = TLS_VERSION_CODES.get(max(versions) if versions else hello["version"], "00")
    alpn = "00"
    if hello["alpn"] and hello["alpn"][0]:
        first = hello["alpn"][0]
        a, b = first[0], first[-1]
        if all(48 <= x <= 57 or 65 <= x <= 90 or 97 <= x <= 122 for x in (a, b)):
            alpn = chr(a) + chr(b)
        else:
            alpn = f"{a:02x}"[0] + f"{b:02x}"[-1]
    part_a = (f"{transport}{version}{'d' if 0 in exts else 'i'}"
              f"{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}{alpn}")
    part_b = _sha12(",".join(sorted(f"{c:04x}" for c in ciphers)))
    ext_text = ",".join(sorted(f"{e:04x}" for e in exts if e not in (0x0000, 0x0010)))
    sigs = ",".join(f"{x:04x}" for x in hello["sig_algs"] if not _is_grease(x))
    part_c = _sha12(ext_text + ("_" + sigs if sigs and ext_text else ""))
    return f"{part_a}_{part_b}_{part_c}"


# Public DNS-over-HTTPS resolver names. Seeing one in SNI means DNS is leaving the network
# where the local resolver, DNS logs and DNS filtering cannot see it.
DOH_SNI = {
    "dns.google", "dns.google.com", "8888.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com",
    "chrome.cloudflare-dns.com", "security.cloudflare-dns.com", "family.cloudflare-dns.com",
    "1dot1dot1dot1.cloudflare-dns.com", "one.one.one.one", "dns.quad9.net", "dns9.quad9.net",
    "dns10.quad9.net", "dns11.quad9.net", "doh.opendns.com", "doh.familyshield.opendns.com",
    "dns.nextdns.io", "doh.cleanbrowsing.org", "dns.adguard-dns.com", "dns.adguard.com",
    "doh.dns.sb", "dns.alidns.com", "doh.pub", "dns.mullvad.net", "doh.mullvad.net",
}


# ---------------------------------------------------------------- analysis

def label_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def base_domain(name: str) -> str:
    parts = name.rstrip(".").split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "net", "org", "gov", "ac", "edu"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def odd_dns(name: str) -> Optional[str]:
    """Reason a DNS name looks like tunneling or DGA output, or None."""
    labels = name.split(".")
    if name.endswith((".arpa", ".local")):
        return None
    if len(name) > 100:
        return f"very long name ({len(name)} chars)"
    longest = max(labels, key=len) if labels else ""
    if len(longest) >= 40:
        return f"label of {len(longest)} chars"
    sub = ".".join(labels[:-2])
    if len(sub) >= 20 and label_entropy(sub.replace(".", "")) >= 3.8:
        return f"random-looking subdomain (entropy {label_entropy(sub.replace('.', '')):.1f})"
    return None


def service_port(sport: int, dport: int, flags: int, proto: int) -> int:
    if proto == 6 and flags & 0x02 and not flags & 0x10:  # SYN without ACK: dport is the service
        return dport
    for p in (dport, sport):
        if p in COMMON_PORTS or p in SUSPICIOUS_PORTS:
            return p
    return min(sport, dport)


# Internal or non-routable ranges. Documentation ranges (RFC 5737, 3849) are left
# out on purpose so sample captures that use them behave like internet traffic.
INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8")]


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(a.version == n.version and a in n for n in INTERNAL_NETS)


def summarize(data: bytes, top: int = 10) -> Dict:
    fmt, packets = read_packets(data)
    n = total_bytes = undecoded = 0
    first = last = None
    linktypes = Counter()
    protos, ports = Counter(), Counter()
    talkers = Counter()
    convs = Counter()
    dns = Counter()
    dns_nx = Counter()
    http = Counter()
    sni = Counter()
    ja4s: Dict[str, Dict] = {}
    no_sni = Counter()
    port_peers: Dict[int, set] = defaultdict(set)
    syn_targets: Dict[Tuple[str, str], set] = defaultdict(set)
    for ts, lt, frame, orig in packets:
        n += 1
        total_bytes += orig
        linktypes[LINKTYPES.get(lt, str(lt))] += 1
        if ts:
            first = ts if first is None else min(first, ts)
            last = ts if last is None else max(last, ts)
        etype, net = decode_link(lt, frame)
        ip = decode_ip(etype, net)
        if not ip:
            protos["ARP" if etype == 0x0806 else "non-IP"] += 1
            if etype != 0x0806:
                undecoded += 1
            continue
        pname = IP_PROTOS.get(ip["proto"], f"ip-proto-{ip['proto']}")
        talkers[ip["src"]] += orig
        talkers[ip["dst"]] += orig
        convs[tuple(sorted((ip["src"], ip["dst"])))] += orig
        l4 = decode_l4(ip["proto"], ip["payload"])
        if not l4:
            protos[pname] += 1
            continue
        svc = service_port(l4["sport"], l4["dport"], l4["flags"], ip["proto"])
        ports[f"{pname.lower()}/{svc}"] += 1
        port_peers[svc].add(ip["dst"] if svc == l4["dport"] else ip["src"])
        if ip["proto"] == 6 and l4["flags"] & 0x02 and not l4["flags"] & 0x10:
            syn_targets[(ip["src"], ip["dst"])].add(l4["dport"])
        payload = l4["payload"]
        app = None
        if 53 in (l4["sport"], l4["dport"]) and payload:
            msg = payload[2:] if ip["proto"] == 6 and len(payload) > 2 else payload
            d = parse_dns(msg)
            if d:
                app = "DNS"
                for qname, qtype in d["questions"]:
                    if not d["qr"]:
                        dns[(qname, qtype)] += 1
                    elif d["rcode"] == 3:
                        dns_nx[qname] += 1
                    elif (qname, qtype) not in dns:
                        dns[(qname, qtype)] += 0  # response-only capture: still list the name
        elif ip["proto"] == 6 and payload:
            req = parse_http_request(payload)
            if req:
                app = "HTTP"
                http[(req["host"], req["user_agent"], req["method"], ip["dst"], svc)] += 1
            else:
                hello = parse_client_hello(payload)
                if hello:
                    app = "TLS"
                    name = hello["sni"]
                    if name:
                        sni[(name, ip["dst"], svc)] += 1
                    else:
                        no_sni[(ip["dst"], svc)] += 1
                    fp = ja4(hello)
                    e = ja4s.setdefault(fp, {"ja4": fp, "count": 0, "alpn": [], "server_names": [], "clients": []})
                    e["count"] += 1
                    for key, val in (("server_names", name), ("clients", ip["src"]),
                                     ("alpn", hello["alpn"][0].decode("ascii", "replace") if hello["alpn"] else None)):
                        if val and val not in e[key] and len(e[key]) < 10:
                            e[key].append(val)
        protos[f"{pname}/{app}" if app else pname] += 1

    if n == 0:
        raise CaptureError("capture contains no packets")
    dns_list = [{"name": k[0], "type": k[1], "count": max(v, 1)} for k, v in dns.most_common()]
    http_list = [{"host": k[0], "user_agent": k[1], "method": k[2], "dst": k[3], "port": k[4], "count": v}
                 for k, v in http.most_common()]
    sni_list = [{"server_name": k[0], "dst": k[1], "port": k[2], "count": v} for k, v in sni.most_common()]
    result = {
        "format": fmt, "linktypes": dict(linktypes), "packets": n, "bytes": total_bytes, "undecoded": undecoded,
        "first_ts": _iso(first), "last_ts": _iso(last),
        "duration_s": round(last - first, 3) if first is not None and last is not None else None,
        "protocols": dict(protos.most_common()),
        "top_talkers": [{"ip": ip, "bytes": b} for ip, b in talkers.most_common(top)],
        "top_conversations": [{"a": a, "b": b, "bytes": v} for (a, b), v in convs.most_common(top)],
        "ports": dict(ports.most_common(top)),
        "dns_queries": dns_list, "dns_nxdomain": dict(dns_nx.most_common(top)),
        "dns_nxdomain_total": sum(dns_nx.values()),
        "http_requests": http_list, "tls_sni": sni_list,
        "tls_ja4": sorted(ja4s.values(), key=lambda e: -e["count"]),
        "tls_no_sni": [{"dst": k[0], "port": k[1], "count": v} for k, v in no_sni.most_common()],
    }
    result["findings"] = analyze(result, port_peers, syn_targets)
    return result


def _iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def analyze(r: Dict, port_peers: Dict[int, set], syn_targets: Dict[Tuple[str, str], set]) -> List[Dict]:
    out = []
    odd = []
    for q in r["dns_queries"]:
        why = odd_dns(q["name"])
        if why:
            odd.append(f"{q['name'][:80]} ({why})")
    if odd:
        out.append(finding("NET-001", "medium" if len(odd) < 5 else "high", "Odd DNS names (possible tunneling or DGA)",
                           f"{len(odd)} name(s): " + "; ".join(odd[:5]),
                           "Check which host asked and whether the base domain is known; DNS tunneling tools put data in "
                           "long random subdomains.", "DNS"))
    per_base = defaultdict(set)
    for q in r["dns_queries"]:
        per_base[base_domain(q["name"])].add(q["name"])
    for base, names in per_base.items():
        if len(names) >= 30:
            out.append(finding("NET-002", "medium", f"Many unique subdomains under {base}",
                               f"{len(names)} different names queried; data exfiltration over DNS looks like this "
                               "(CDNs and anti-virus lookups can too).", "Check the base domain's reputation and owner.", "DNS"))
    txt = [q for q in r["dns_queries"] if q["type"] in ("TXT", "NULL")]
    if len(txt) >= 10:
        out.append(finding("NET-003", "low", "Many TXT/NULL DNS queries",
                           f"{len(txt)} TXT or NULL queries; these record types carry data in most DNS tunneling tools.",
                           "Look at which names they target.", "DNS"))
    if r["dns_nxdomain_total"] >= 20:
        out.append(finding("NET-004", "medium", "Lots of NXDOMAIN answers",
                           f"{r['dns_nxdomain_total']} failed lookups; DGA malware tries many generated domains until one resolves.",
                           "Group the failed names by querying host.", "DNS"))
    for port, peers in sorted(port_peers.items()):
        if port in SUSPICIOUS_PORTS:
            out.append(finding("NET-010", "medium", f"Traffic on port {port} ({SUSPICIOUS_PORTS[port]})",
                               f"Peers: {', '.join(sorted(peers)[:5])}.",
                               "Identify the process using it on the internal host.", f"port {port}"))
    rare = sorted(p for p in port_peers if p not in COMMON_PORTS and p not in SUSPICIOUS_PORTS and p < 49152)
    if rare:
        out.append(finding("NET-011", "info", "Connections to uncommon ports",
                           "Ports: " + ", ".join(str(p) for p in rare[:15]) + (" ..." if len(rare) > 15 else "") + ".",
                           "Most are legitimate apps; confirm the ones talking to public addresses.", "ports"))
    for h in r["http_requests"]:
        if h["host"] and re.fullmatch(r"[\d.]+(:\d+)?|\[[0-9a-fA-F:]+\](:\d+)?", h["host"]) and is_public(h["dst"]):
            out.append(finding("NET-020", "medium", "Cleartext HTTP straight to an IP address",
                               f"{h['method']} to Host {h['host']} ({h['count']}x). Malware often skips DNS and talks to a raw IP.",
                               "Check what was downloaded and from which internal host.", f"{h['dst']}:{h['port']}"))
        if TOOL_UA.search(h["user_agent"] or ""):
            out.append(finding("NET-021", "low", "Scripted HTTP client",
                               f"User-Agent '{h['user_agent'] or '(empty)'}' to {h['host'] or h['dst']}; "
                               "scripts and malware use these, so do admins and CI.",
                               "Confirm the request was expected.", f"{h['dst']}:{h['port']}"))
        elif h["port"] not in (80, 8080, 8000, 8008, 8888):
            out.append(finding("NET-022", "low", f"HTTP on non-standard port {h['port']}",
                               f"{h['method']} to {h['host'] or h['dst']}.", "Confirm the service is known.",
                               f"{h['dst']}:{h['port']}"))
    for (src, dst), dports in syn_targets.items():
        if len(dports) >= 20:
            out.append(finding("NET-030", "high", "Port scan pattern",
                               f"{src} sent SYNs to {len(dports)} ports on {dst}.",
                               "Find out if this is an authorized scanner; if not, treat the source as compromised.", src))
    for s in r["tls_sni"]:
        why = odd_dns(s["server_name"])
        if why:
            out.append(finding("NET-040", "low", "Odd TLS server name",
                               f"SNI {s['server_name'][:80]} ({why}).", "Check the domain's reputation.", f"{s['dst']}:{s['port']}"))
    doh = sorted({s["server_name"] for s in r["tls_sni"] if s["server_name"] in DOH_SNI})
    dot = sorted(ip for ip in port_peers.get(853, ()) if is_public(ip))
    if doh or dot:
        parts = ([f"DoH resolver names in SNI: {', '.join(doh[:5])}"] if doh else []) + \
                ([f"TCP/853 (DNS over TLS) to {', '.join(dot[:5])}"] if dot else [])
        out.append(finding("NET-041", "low", "Encrypted DNS to a public resolver (DoH/DoT)",
                           "; ".join(parts) + ". These lookups skip the local resolver and its logs.",
                           "Check it matches policy (browsers can turn DoH on by themselves). If DNS must stay "
                           "visible, point clients at an internal resolver, use the browser canary domain or "
                           "enterprise policy, and block known DoH/DoT endpoints at the egress.",
                           (doh + dot)[0]))
    public_no_sni = [t for t in r.get("tls_no_sni", []) if is_public(t["dst"])]
    if public_no_sni:
        out.append(finding("NET-042", "low", "TLS to a public IP without a server name",
                           f"{sum(t['count'] for t in public_no_sni)} ClientHello(s) without SNI to "
                           f"{', '.join(t['dst'] + ':' + str(t['port']) for t in public_no_sni[:5])}. "
                           "Browsers always send SNI; scripted clients and some implants connect to a bare IP.",
                           "Match the JA4 in tls_ja4 to the client process (EDR or Zeek ssl.log) and look up the IP.",
                           f"{public_no_sni[0]['dst']}:{public_no_sni[0]['port']}"))
    out.sort(key=lambda f: -SEVERITY_ORDER.index(f["severity"]))
    return out


def render_text(r: Dict, top: int) -> str:
    lines = [f"Capture: {r['format']}, {r['packets']} packets, {r['bytes']} bytes, link {', '.join(r['linktypes'])}",
             f"Time: {r['first_ts']} to {r['last_ts']} ({r['duration_s']} s)", ""]
    lines.append("Protocols: " + ", ".join(f"{k} {v}" for k, v in r["protocols"].items()))
    lines.append("Ports: " + ", ".join(f"{k} {v}" for k, v in r["ports"].items()))
    lines.append("")
    lines.append("Top talkers (bytes):")
    lines += [f"  {t['ip']:<40} {t['bytes']}" for t in r["top_talkers"]]
    lines.append("Top conversations (bytes):")
    lines += [f"  {c['a']} <-> {c['b']}  {c['bytes']}" for c in r["top_conversations"]]
    if r["dns_queries"]:
        lines.append(f"DNS queries ({len(r['dns_queries'])} unique):")
        lines += [f"  {q['count']:>4}  {q['type']:<5} {q['name']}" for q in r["dns_queries"][:top * 2]]
    if r["http_requests"]:
        lines.append("HTTP requests:")
        lines += [f"  {h['count']:>4}  {h['method']} {h['host'] or '-'} -> {h['dst']}:{h['port']}  UA: {h['user_agent'] or '-'}"
                  for h in r["http_requests"][:top * 2]]
    if r["tls_sni"]:
        lines.append("TLS server names (SNI):")
        lines += [f"  {s['count']:>4}  {s['server_name']} -> {s['dst']}:{s['port']}" for s in r["tls_sni"][:top * 2]]
    if r.get("tls_ja4"):
        lines.append("TLS client fingerprints (JA4):")
        lines += [f"  {e['count']:>4}  {e['ja4']}  {', '.join(e['server_names'][:3]) or '(no SNI)'}"
                  for e in r["tls_ja4"][:top]]
    lines.append("")
    if not r["findings"]:
        lines.append("No findings.")
    for f in r["findings"]:
        lines.append(f"[{f['severity'].upper():8}] {f['id']}  {f['title']}")
        lines.append(f"           {f['detail']}")
        lines.append(f"           next: {f['fix']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Summarize a pcap/pcapng file: talkers, ports, DNS, HTTP, TLS SNI, odd traffic.")
    ap.add_argument("capture", help="pcap or pcapng file; '-' reads from stdin")
    ap.add_argument("--top", type=int, default=10, help="rows per top-N table (default 10)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)
    try:
        data = sys.stdin.buffer.read() if args.capture == "-" else Path(args.capture).read_bytes()
        r = summarize(data, max(1, args.top))
    except (OSError, CaptureError, AttributeError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(r, indent=2))
    else:
        print(render_text(r, args.top))
    if args.fail_on != "never":
        t = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= t for f in r["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
