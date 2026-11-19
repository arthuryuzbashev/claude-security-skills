#!/usr/bin/env python3
"""Check a TLS endpoint or a certificate file: protocol, cipher, certificate health.

Live mode makes a few TLS handshakes to one host:port (no HTTP request, nothing else).
One of them is a plain TLS 1.3 ClientHello that offers the X25519MLKEM768 hybrid group,
read only up to the ServerHello, to see which key exchange group the server picks.
File mode parses a PEM or DER certificate with a small built-in ASN.1 reader, fully offline.

Usage:
  tls_check.py app.example.test
  tls_check.py app.example.test:8443 --timeout 5 --no-pq
  tls_check.py --cert server.pem --hostname www.example.test
  tls_check.py --cert server.pem --now 2027-06-01 --json --fail-on medium
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import ipaddress
import os
import json
import re
import socket
import ssl
import sys
from typing import Any, Dict, Iterator, List, Optional, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

OID_NAMES = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O",
    "2.5.4.11": "OU", "2.5.4.5": "serialNumber", "1.2.840.113549.1.9.1": "emailAddress",
}
SIG_ALGS = {
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.10040.4.3": "dsa-with-SHA1",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}
KEY_ALGS = {
    "1.2.840.113549.1.1.1": "RSA", "1.2.840.10045.2.1": "EC", "1.2.840.10040.4.1": "DSA",
    "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448", "1.2.840.113549.1.1.10": "RSA-PSS",
}
EC_CURVES = {
    "1.2.840.10045.3.1.7": ("P-256", 256), "1.3.132.0.34": ("P-384", 384),
    "1.3.132.0.35": ("P-521", 521), "1.3.132.0.10": ("secp256k1", 256),
    "1.2.840.10045.3.1.1": ("P-192", 192), "1.3.132.0.33": ("P-224", 224),
}
OID_SAN = "2.5.29.17"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
# Max validity of publicly trusted TLS leaf certs by issue date (CA/Browser Forum,
# 398 days since 2020-09-01, then ballot SC-081 steps it down).
LIFETIME_CAPS = [
    (dt.datetime(2029, 3, 15, tzinfo=dt.timezone.utc), 47),
    (dt.datetime(2027, 3, 15, tzinfo=dt.timezone.utc), 100),
    (dt.datetime(2026, 3, 15, tzinfo=dt.timezone.utc), 200),
    (dt.datetime(2020, 9, 1, tzinfo=dt.timezone.utc), 398),
]


def lifetime_cap(not_before: dt.datetime) -> Optional[Tuple[str, int]]:
    for start, days in LIFETIME_CAPS:
        if not_before >= start:
            return f"{start:%Y-%m-%d}", days
    return None


def finding(fid: str, severity: str, title: str, detail: str, fix: str) -> Dict[str, str]:
    return {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}


# ---------------------------------------------------------------- minimal DER reader

def read_tlv(data: bytes, pos: int) -> Tuple[int, bytes, int]:
    """Read one DER TLV at pos. Returns (tag, value, next_pos)."""
    if pos + 2 > len(data):
        raise ValueError("truncated DER")
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise ValueError("bad DER length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    if pos + length > len(data):
        raise ValueError("DER value runs past the end")
    return tag, data[pos:pos + length], pos + length


def children(data: bytes) -> Iterator[Tuple[int, bytes]]:
    pos = 0
    while pos < len(data):
        tag, value, pos = read_tlv(data, pos)
        yield tag, value


def decode_oid(raw: bytes) -> str:
    if not raw:
        raise ValueError("empty OID")
    first = raw[0]
    parts = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def decode_string(tag: int, raw: bytes) -> str:
    if tag == 0x1E:
        return raw.decode("utf-16-be", errors="replace")
    if tag == 0x1C:
        return raw.decode("utf-32-be", errors="replace")
    if tag == 0x14:
        return raw.decode("latin-1")
    return raw.decode("utf-8", errors="replace")


def decode_time(tag: int, raw: bytes) -> dt.datetime:
    text = raw.decode("ascii")
    if tag == 0x17:  # UTCTime YYMMDDHHMMSSZ, years 50-99 are 19xx (RFC 5280)
        year = int(text[:2])
        year += 1900 if year >= 50 else 2000
        return dt.datetime(year, int(text[2:4]), int(text[4:6]), int(text[6:8]), int(text[8:10]),
                           int(text[10:12]), tzinfo=dt.timezone.utc)
    if tag == 0x18:  # GeneralizedTime YYYYMMDDHHMMSSZ
        return dt.datetime(int(text[:4]), int(text[4:6]), int(text[6:8]), int(text[8:10]),
                           int(text[10:12]), int(text[12:14]), tzinfo=dt.timezone.utc)
    raise ValueError(f"unexpected time tag 0x{tag:02x}")


def decode_name(raw: bytes) -> List[Tuple[str, str]]:
    out = []
    for _, rdn in children(raw):
        for _, atv in children(rdn):
            parts = list(children(atv))
            if len(parts) >= 2 and parts[0][0] == 0x06:
                oid = decode_oid(parts[0][1])
                out.append((OID_NAMES.get(oid, oid), decode_string(parts[1][0], parts[1][1])))
    return out


def name_str(name: List[Tuple[str, str]]) -> str:
    return ", ".join(f"{k}={v}" for k, v in name)


def parse_public_key(spki: bytes) -> Tuple[str, Optional[int], Optional[str]]:
    parts = list(children(spki))
    alg_parts = list(children(parts[0][1]))
    oid = decode_oid(alg_parts[0][1])
    alg = KEY_ALGS.get(oid, oid)
    bitstring = parts[1][1][1:]  # first byte = unused bits
    if alg in ("RSA", "RSA-PSS"):
        rsa = list(children(read_tlv(bitstring, 0)[1]))
        modulus = rsa[0][1].lstrip(b"\x00")
        return "RSA", len(modulus) * 8 - (8 - modulus[0].bit_length()) if modulus else 0, None
    if alg == "EC":
        curve_oid = decode_oid(alg_parts[1][1]) if len(alg_parts) > 1 and alg_parts[1][0] == 0x06 else ""
        curve, bits = EC_CURVES.get(curve_oid, (curve_oid or "unknown", None))
        return "EC", bits, curve
    if alg == "Ed25519":
        return alg, 256, None
    if alg == "Ed448":
        return alg, 456, None
    if alg == "DSA":
        params = list(children(alg_parts[1][1])) if len(alg_parts) > 1 else []
        p = params[0][1].lstrip(b"\x00") if params else b""
        return "DSA", (len(p) * 8 - (8 - p[0].bit_length())) if p else None, None
    return alg, None, None


def parse_certificate(der: bytes) -> Dict[str, Any]:
    """Parse an X.509 certificate (DER) into a plain dict. Raises ValueError on junk."""
    try:
        tag, cert, _ = read_tlv(der, 0)
        if tag != 0x30:
            raise ValueError("not a DER SEQUENCE")
        top = list(children(cert))
        tbs = list(children(top[0][1]))
        sig_oid = decode_oid(list(children(top[1][1]))[0][1])
        i = 1 if tbs[0][0] == 0xA0 else 0
        version = (int.from_bytes(list(children(tbs[0][1]))[0][1], "big") + 1) if i else 1
        serial = tbs[i][1].hex()
        issuer_raw, validity, subject_raw, spki = tbs[i + 2][1], tbs[i + 3][1], tbs[i + 4][1], tbs[i + 5][1]
        times = list(children(validity))
        not_before = decode_time(*times[0])
        not_after = decode_time(*times[1])
        key_alg, key_size, curve = parse_public_key(spki)
        san_dns: List[str] = []
        san_ip: List[str] = []
        is_ca = False
        has_san = False
        for tag, value in tbs[i + 6:]:
            if tag != 0xA3:
                continue
            for _, ext in children(read_tlv(value, 0)[1]):
                ext_parts = list(children(ext))
                oid = decode_oid(ext_parts[0][1])
                octets = ext_parts[-1][1]
                if oid == OID_SAN:
                    has_san = True
                    for gtag, gval in children(read_tlv(octets, 0)[1]):
                        if gtag == 0x82:
                            san_dns.append(gval.decode("ascii", errors="replace"))
                        elif gtag == 0x87 and len(gval) in (4, 16):
                            san_ip.append(str(ipaddress.ip_address(gval)))
                elif oid == OID_BASIC_CONSTRAINTS:
                    bc = list(children(read_tlv(octets, 0)[1]))
                    is_ca = bool(bc and bc[0][0] == 0x01 and bc[0][1] not in (b"", b"\x00"))
    except (IndexError, UnicodeDecodeError) as err:
        raise ValueError(f"could not parse certificate: {err}")
    subject = decode_name(subject_raw)
    return {
        "version": version,
        "serial": serial,
        "subject": name_str(subject),
        "common_name": next((v for k, v in subject if k == "CN"), None),
        "issuer": name_str(decode_name(issuer_raw)),
        "self_signed": subject_raw == issuer_raw,
        "not_before": not_before,
        "not_after": not_after,
        "signature_oid": sig_oid,
        "signature_algorithm": SIG_ALGS.get(sig_oid, sig_oid),
        "key_type": key_alg,
        "key_size": key_size,
        "curve": curve,
        "has_san": has_san,
        "san_dns": san_dns,
        "san_ip": san_ip,
        "is_ca": is_ca,
    }


def load_certificates(raw: bytes) -> List[bytes]:
    """PEM (one or more blocks) or a single DER blob -> list of DER certs."""
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", raw, re.S)
    if blocks:
        return [base64.b64decode(b"".join(b.split())) for b in blocks]
    if raw[:1] == b"\x30":
        return [raw]
    raise ValueError("no PEM certificate block and not DER")


# ---------------------------------------------------------------- grading

def hostname_matches(hostname: str, cert: Dict[str, Any]) -> bool:
    """RFC 6125 style: SAN only when present, wildcard covers exactly one leftmost label."""
    host = hostname.lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
        return str(ip) in cert["san_ip"]
    except ValueError:
        pass
    names = cert["san_dns"] if cert["has_san"] else ([cert["common_name"]] if cert["common_name"] else [])
    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and "." in host:
            if host.split(".", 1)[1] == name[2:] and host.split(".", 1)[0]:
                return True
    return False


def grade_certificate(cert: Dict[str, Any], hostname: Optional[str] = None,
                      now: Optional[dt.datetime] = None) -> List[Dict[str, str]]:
    now = now or dt.datetime.now(dt.timezone.utc)
    out = []
    days_left = (cert["not_after"] - now).total_seconds() / 86400
    root = cert["self_signed"] and cert["is_ca"]
    if days_left < 0:
        out.append(finding("TLS-001", "critical", "Certificate has expired",
                           f"Expired {abs(int(days_left))} day(s) ago ({cert['not_after']:%Y-%m-%d}). Clients refuse it or users click through warnings.",
                           "Renew now and automate renewal (ACME/certbot, cloud cert manager)."))
    elif days_left <= 14:
        out.append(finding("TLS-002", "high", "Certificate expires within 14 days",
                           f"{int(days_left)} day(s) left (until {cert['not_after']:%Y-%m-%d}).",
                           "Renew now and check why automated renewal did not run."))
    elif days_left <= 30:
        out.append(finding("TLS-003", "medium", "Certificate expires within 30 days",
                           f"{int(days_left)} day(s) left (until {cert['not_after']:%Y-%m-%d}).",
                           "Schedule renewal, ideally automated at about 2/3 of the lifetime."))
    if cert["not_before"] > now:
        out.append(finding("TLS-004", "high", "Certificate is not valid yet",
                           f"notBefore is {cert['not_before']:%Y-%m-%d %H:%M} UTC. Clients will reject it until then.",
                           "Check the issuing clock, or wait before deploying it."))
    sig = cert["signature_algorithm"].lower()
    if not root and ("md5" in sig or "md2" in sig):
        out.append(finding("TLS-011", "critical", f"Certificate signed with {cert['signature_algorithm']}",
                           "MD5/MD2 signatures can be forged with practical collision attacks.",
                           "Reissue with SHA-256 or better."))
    elif not root and "sha1" in sig:
        out.append(finding("TLS-010", "high", f"Certificate signed with {cert['signature_algorithm']}",
                           "SHA-1 has practical chosen-prefix collisions; browsers reject SHA-1 signed leaf certs.",
                           "Reissue with sha256WithRSAEncryption or ecdsa-with-SHA256."))
    if cert["key_type"] == "RSA" and cert["key_size"]:
        if cert["key_size"] < 2048:
            out.append(finding("TLS-020", "critical" if cert["key_size"] < 1024 else "high",
                               f"RSA key is {cert['key_size']} bits",
                               "RSA under 2048 bits is below every current baseline (NIST, CA/B Forum).",
                               "Generate a new RSA-2048+ or ECDSA P-256 key and reissue."))
    elif cert["key_type"] == "DSA":
        out.append(finding("TLS-021", "medium", "DSA public key",
                           "DSA is deprecated for TLS certificates and unsupported by many clients.",
                           "Move to ECDSA P-256 or RSA-2048+."))
    elif cert["key_type"] == "EC" and cert["key_size"] and cert["key_size"] < 256:
        out.append(finding("TLS-022", "high", f"Weak EC curve {cert['curve']}",
                           f"{cert['key_size']}-bit curves are below the 128-bit security level.",
                           "Use P-256 or P-384."))
    if cert["self_signed"] and not cert["is_ca"]:
        out.append(finding("TLS-030", "high", "Self-signed certificate",
                           "No CA vouches for it, so clients cannot tell it from an attacker's cert without pinning.",
                           "Use a publicly trusted cert (ACME) or an internal CA whose root is deployed to clients."))
    elif root:
        out.append(finding("TLS-031", "info", "Self-signed CA certificate (a root)",
                           "Normal for a root CA. It should never be served as a server's leaf certificate.",
                           "No action if this is a trust anchor."))
    if not cert["has_san"] and not cert["is_ca"]:
        out.append(finding("TLS-061", "medium", "No Subject Alternative Name",
                           "Browsers ignore the CN and only match names in the SAN extension.",
                           "Reissue with every hostname listed in subjectAltName."))
    if any(n.startswith("*.") for n in cert["san_dns"]) or (cert["common_name"] or "").startswith("*."):
        out.append(finding("TLS-050", "low", "Wildcard certificate",
                           "One key covers every subdomain, so a leak on any host exposes them all.",
                           "Prefer per-host certs where automation allows; keep wildcard keys on few machines."))
    lifetime = (cert["not_after"] - cert["not_before"]).days
    cap = lifetime_cap(cert["not_before"])
    if not cert["is_ca"] and cap and lifetime > cap[1]:
        out.append(finding("TLS-060", "medium", f"Validity period is {lifetime} days",
                           f"Under CA/Browser Forum rules, publicly trusted TLS certs issued on or after {cap[0]} may last "
                           f"at most {cap[1]} days. Private CAs are not bound, but long lives slow key rotation.",
                           "Issue for 90 days or less and automate renewal."))
    if hostname and not hostname_matches(hostname, cert):
        names = ", ".join(cert["san_dns"] + cert["san_ip"]) or (cert["common_name"] or "none")
        out.append(finding("TLS-040", "high", f"Certificate does not cover {hostname}",
                           f"Names on the cert: {names}.",
                           f"Reissue with {hostname} in subjectAltName, or fix DNS/SNI routing."))
    return out


WEAK_CIPHER = re.compile(r"(RC4|DES|NULL|EXP|MD5|ADH|AECDH|anon|IDEA|SEED)", re.I)


def grade_connection(conn: Dict[str, Any]) -> List[Dict[str, str]]:
    """conn: {protocol, cipher, cipher_bits, legacy: {"TLSv1": status, "TLSv1.1": status}, verify_error}."""
    out = []
    proto = conn.get("protocol") or ""
    cipher = conn.get("cipher") or ""
    legacy = conn.get("legacy") or {}
    if legacy.get("TLSv1") == "supported":
        out.append(finding("TLS-070", "high", "Server accepts TLS 1.0",
                           "TLS 1.0 is deprecated (RFC 8996) and fails PCI DSS.",
                           "Set the minimum protocol to TLS 1.2 (nginx: ssl_protocols TLSv1.2 TLSv1.3;)."))
    if legacy.get("TLSv1.1") == "supported":
        out.append(finding("TLS-071", "medium", "Server accepts TLS 1.1",
                           "TLS 1.1 is deprecated (RFC 8996) and no current browser uses it.",
                           "Set the minimum protocol to TLS 1.2."))
    untested = [v for v, s in legacy.items() if s in ("could not test", "error")]
    if untested:
        out.append(finding("TLS-074", "info", f"Could not test {' / '.join(untested)}",
                           "The local OpenSSL cannot speak these versions, so support is unknown, not absent.",
                           "Re-test from a host with legacy TLS enabled (openssl s_client -tls1 / -tls1_1) or with an external scanner."))
    if proto in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
        out.append(finding("TLS-072", "high", f"Negotiated {proto}",
                           "A modern client still ended up on a deprecated protocol, so the server tops out there.",
                           "Enable TLS 1.2 and TLS 1.3 on the server."))
    elif proto == "TLSv1.2" and conn.get("client_tls13", True):
        out.append(finding("TLS-073", "low", "TLS 1.3 not offered",
                           "The client offered TLS 1.3 and the server picked 1.2. 1.3 is faster and drops legacy options.",
                           "Enable TLS 1.3 (OpenSSL 1.1.1+, nginx 1.13+)."))
    if cipher and WEAK_CIPHER.search(cipher):
        out.append(finding("TLS-080", "high", f"Weak cipher negotiated: {cipher}",
                           "RC4, DES/3DES, NULL, export and anonymous suites are broken or unauthenticated.",
                           "Restrict to AEAD suites (AES-GCM, ChaCha20-Poly1305) with ECDHE."))
    elif cipher and not cipher.startswith("TLS_"):  # TLS 1.3 suite names start with TLS_
        if not re.match(r"^(ECDHE|DHE)-", cipher):
            out.append(finding("TLS-082", "medium", f"No forward secrecy: {cipher}",
                               "Static RSA key exchange: anyone who later gets the server key can decrypt recorded traffic.",
                               "Prefer ECDHE suites and drop plain RSA key exchange."))
        if not re.search(r"(GCM|CHACHA20|CCM)", cipher):
            out.append(finding("TLS-081", "low", f"CBC-mode cipher negotiated: {cipher}",
                               "CBC suites in TLS 1.2 have a long history of padding-oracle bugs.",
                               "Order AEAD suites first on the server."))
    if conn.get("pq_hybrid") is False:
        group = conn.get("key_exchange_group") or "a classical group"
        out.append(finding("TLS-090", "info", "No post-quantum hybrid key exchange",
                           f"Offered X25519MLKEM768 with a key share and the server picked {group}. Recorded traffic "
                           "could be decrypted later by a large quantum computer (harvest now, decrypt later).",
                           "Enable X25519MLKEM768 first in the group list (OpenSSL 3.5+, BoringSSL, Go 1.24+, "
                           "nginx ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1:secp384r1)."))
    err = conn.get("verify_error")
    if err and "hostname" not in err.lower():
        out.append(finding("TLS-032", "high", "Certificate chain does not verify",
                           f"Verification against the system trust store failed: {err}.",
                           "Serve the full chain (leaf + intermediates) from a trusted CA."))
    return out


# ---------------------------------------------------------------- live mode

PROTO_CONST = {"TLSv1": getattr(ssl.TLSVersion, "TLSv1", None), "TLSv1.1": getattr(ssl.TLSVersion, "TLSv1_1", None)}
LOCAL_REFUSAL = ("no protocols available", "no_protocols_available", "no ciphers available", "no_ciphers_available",
                 "unsupported protocol", "unsupported_protocol")


def probe_protocol(host: str, port: int, version: str, timeout: float, sni: Optional[str]) -> Tuple[str, str]:
    """Try a handshake pinned to one legacy version. Returns (status, note)."""
    has = ssl.HAS_TLSv1 if version == "TLSv1" else ssl.HAS_TLSv1_1
    if not has or PROTO_CONST[version] is None:
        return "could not test", f"local OpenSSL ({ssl.OPENSSL_VERSION}) was built without {version}"
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = PROTO_CONST[version]
        ctx.maximum_version = PROTO_CONST[version]
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError) as err:
        return "could not test", f"local OpenSSL refuses {version}: {err}"
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                return ("supported", tls.version() or version)
    except ssl.SSLError as err:
        text = str(err).lower()
        # the server's alert reads differently from our own library refusing to send the hello
        if any(s in text for s in LOCAL_REFUSAL) and "alert" not in text:
            return "could not test", f"local OpenSSL refused: {err}"
        return "not supported", str(err)
    except OSError as err:
        return "error", str(err)


def connect(host: str, port: int, timeout: float, sni: Optional[str]) -> Tuple[Dict[str, Any], bytes]:
    """One verified handshake; if verification fails, one more unverified to read the cert."""
    verify_error = None
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                info = (tls.version(), tls.cipher(), tls.getpeercert(binary_form=True))
    except ssl.SSLCertVerificationError as err:
        verify_error = getattr(err, "verify_message", None) or str(err)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                info = (tls.version(), tls.cipher(), tls.getpeercert(binary_form=True))
    version, cipher, der = info
    conn = {
        "protocol": version,
        "cipher": cipher[0] if cipher else None,
        "cipher_bits": cipher[2] if cipher else None,
        "verify_error": verify_error,
        "client_tls13": ssl.HAS_TLSv1_3,
    }
    return conn, der or b""


# ---------------------------------------------------------------- post-quantum group probe

# IANA TLS Supported Groups; hybrids from RFC 10024 / draft-ietf-tls-ecdhe-mlkem.
GROUP_NAMES = {
    0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1", 0x001D: "x25519", 0x001E: "x448",
    0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096",
    0x0200: "MLKEM512", 0x0201: "MLKEM768", 0x0202: "MLKEM1024",
    0x11EB: "SecP256r1MLKEM768", 0x11EC: "X25519MLKEM768", 0x11ED: "SecP384r1MLKEM1024",
}
PQ_GROUPS = {0x0200, 0x0201, 0x0202, 0x11EB, 0x11EC, 0x11ED}
OFFERED_GROUPS = [0x11EC, 0x001D, 0x11EB, 0x0017, 0x0018]   # key shares sent for the first two only
SIG_SCHEMES = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0807]
HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
MLKEM768_EK_LEN = 1184


def _u16(n: int) -> bytes:
    return n.to_bytes(2, "big")


def _ext(ext_type: int, body: bytes) -> bytes:
    return _u16(ext_type) + _u16(len(body)) + body


def build_pq_client_hello(sni: Optional[str], rand=os.urandom) -> bytes:
    """A TLS 1.3-only ClientHello record offering X25519MLKEM768 (with a share) and X25519.

    The ML-KEM-768 encapsulation key is all-zero coefficients plus a random seed: well formed
    (it passes the FIPS 203 modulus check) and we never finish the handshake, so it has no secret.
    """
    exts = b""
    if sni:
        name = sni.encode("idna")
        entry = b"\x00" + _u16(len(name)) + name
        exts += _ext(0x0000, _u16(len(entry)) + entry)
    groups = b"".join(_u16(g) for g in OFFERED_GROUPS)
    exts += _ext(0x000A, _u16(len(groups)) + groups)
    sigs = b"".join(_u16(x) for x in SIG_SCHEMES)
    exts += _ext(0x000D, _u16(len(sigs)) + sigs)
    exts += _ext(0x002B, b"\x02\x03\x04")          # supported_versions: TLS 1.3 only
    exts += _ext(0x002D, b"\x01\x01")               # psk_key_exchange_modes: psk_dhe_ke
    hybrid = bytes(MLKEM768_EK_LEN - 32) + rand(32) + rand(32)   # ML-KEM-768 ek || X25519 share
    shares = _u16(0x11EC) + _u16(len(hybrid)) + hybrid + _u16(0x001D) + _u16(32) + rand(32)
    exts += _ext(0x0033, _u16(len(shares)) + shares)
    suites = b"\x13\x01\x13\x02\x13\x03"
    body = (b"\x03\x03" + rand(32) + b"\x20" + rand(32) + _u16(len(suites)) + suites
            + b"\x01\x00" + _u16(len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + _u16(len(hs)) + hs


def parse_server_hello(data: bytes) -> Dict[str, Any]:
    """Read the first handshake message from raw records. Returns {status, group, hrr, version}."""
    hs = b""
    pos = 0
    while pos + 5 <= len(data):
        ctype, length = data[pos], int.from_bytes(data[pos + 3:pos + 5], "big")
        frag = data[pos + 5:pos + 5 + length]
        if len(frag) < length:
            break
        pos += 5 + length
        if ctype == 21:
            desc = frag[1] if len(frag) > 1 else -1
            return {"status": "alert", "alert": desc}
        if ctype == 22:
            hs += frag
            if len(hs) >= 4 and len(hs) >= 4 + int.from_bytes(hs[1:4], "big"):
                break
    if len(hs) < 4 or hs[0] != 2 or len(hs) < 4 + int.from_bytes(hs[1:4], "big"):
        return {"status": "incomplete"}
    body = hs[4:4 + int.from_bytes(hs[1:4], "big")]
    try:
        random = body[2:34]
        sid_len = body[34]
        p = 35 + sid_len + 3            # session id, cipher suite, compression
        ext_end = p + 2 + int.from_bytes(body[p:p + 2], "big")
        p += 2
        version, group = None, None
        while p + 4 <= ext_end:
            etype, elen = int.from_bytes(body[p:p + 2], "big"), int.from_bytes(body[p + 2:p + 4], "big")
            edata = body[p + 4:p + 4 + elen]
            if etype == 0x002B and elen >= 2:
                version = int.from_bytes(edata[:2], "big")
            elif etype == 0x0033 and elen >= 2:
                group = int.from_bytes(edata[:2], "big")
            p += 4 + elen
    except IndexError:
        return {"status": "incomplete"}
    return {"status": "ok", "hrr": random == HRR_RANDOM, "version": version, "group": group}


def probe_pq(host: str, port: int, timeout: float, sni: Optional[str]) -> Dict[str, Any]:
    """Send one TLS 1.3 ClientHello, read up to the ServerHello, close. No keys are derived."""
    try:
        ipaddress.ip_address(sni or "")
        sni = None                      # no SNI for IP literals
    except ValueError:
        pass
    data = b""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(build_pq_client_hello(sni))
            while len(data) < 65536:
                chunk = sock.recv(16384)
                if not chunk:
                    break
                data += chunk
                res = parse_server_hello(data)
                if res["status"] != "incomplete":
                    break
    except OSError as err:
        if not data:
            return {"key_exchange_group": None, "pq_hybrid": None, "pq_note": f"probe failed: {err}"}
    res = parse_server_hello(data)
    if res["status"] == "alert":
        return {"key_exchange_group": None, "pq_hybrid": None,
                "pq_note": f"server sent alert {res['alert']} to a TLS 1.3-only hello"}
    if res["status"] != "ok" or res.get("version") != 0x0304 or res.get("group") is None:
        return {"key_exchange_group": None, "pq_hybrid": None, "pq_note": "no TLS 1.3 key share in the reply"}
    gid = res["group"]
    name = GROUP_NAMES.get(gid, f"0x{gid:04x}")
    return {"key_exchange_group": name, "pq_hybrid": gid in PQ_GROUPS,
            "pq_note": "picked after HelloRetryRequest" if res["hrr"] else "picked from our key share"}


def split_target(target: str, default_port: int) -> Tuple[str, int]:
    target = re.sub(r"^[a-z]+://", "", target.strip(), flags=re.I).split("/", 1)[0]
    if target.startswith("["):  # [IPv6]:port
        host, _, rest = target[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else default_port
    if target.count(":") == 1:
        host, port = target.split(":")
        return host, int(port)
    return target, default_port


# ---------------------------------------------------------------- output

def cert_for_json(cert: Dict[str, Any], now: dt.datetime) -> Dict[str, Any]:
    out = dict(cert)
    out["not_before"] = cert["not_before"].isoformat()
    out["not_after"] = cert["not_after"].isoformat()
    out["days_left"] = int((cert["not_after"] - now).total_seconds() // 86400)
    return out


def render_text(target, conn, cert, findings, now) -> str:
    lines = [f"TLS check: {target}"]
    if conn:
        lines.append(f"Protocol {conn['protocol']}, cipher {conn['cipher']} ({conn['cipher_bits']} bits)")
        if "pq_hybrid" in conn:
            lines.append(f"  key exchange: {conn['key_exchange_group'] or 'unknown'} ({conn['pq_note']})")
        for ver, (status, note) in conn.get("legacy_notes", {}).items():
            lines.append(f"  {ver}: {status}" + (f" ({note})" if status in ("could not test", "error") else ""))
    if cert:
        key = f"{cert['key_type']} {cert['key_size'] or '?'}" + (f" {cert['curve']}" if cert["curve"] else "")
        lines += [f"Subject  {cert['subject']}", f"Issuer   {cert['issuer']}",
                  f"Valid    {cert['not_before']:%Y-%m-%d} to {cert['not_after']:%Y-%m-%d} "
                  f"({int((cert['not_after'] - now).total_seconds() // 86400)} days left)",
                  f"SAN      {', '.join(cert['san_dns'] + cert['san_ip']) or '(none)'}",
                  f"Key      {key}, signature {cert['signature_algorithm']}"]
    lines += [f"{len(findings)} finding(s)", ""]
    if not findings:
        lines.append("No issues found.")
    for f in findings:
        lines.append(f"[{f['severity'].upper():8}] {f['id']}  {f['title']}")
        lines.append(f"           {f['detail']}")
        lines.append(f"           fix: {f['fix']}")
    return "\n".join(lines)


def parse_now(value: Optional[str]) -> dt.datetime:
    if not value:
        return dt.datetime.now(dt.timezone.utc)
    return dt.datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=dt.timezone.utc)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Check a TLS endpoint or a certificate file.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("target", nargs="?", help="host, host:port or https URL to connect to")
    src.add_argument("--cert", help="PEM or DER certificate file ('-' for stdin); the first cert is graded")
    ap.add_argument("--port", type=int, default=443, help="port when the target has none (default 443)")
    ap.add_argument("--hostname", help="name to match against the cert (live default: the target host)")
    ap.add_argument("--no-legacy", action="store_true", help="live: skip the TLS 1.0/1.1 probes")
    ap.add_argument("--no-pq", action="store_true", help="live: skip the post-quantum key exchange probe")
    ap.add_argument("--now", help="grade expiry as of YYYY-MM-DD (default: today)")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)

    try:
        now = parse_now(args.now)
        conn = None
        if args.cert:
            raw = sys.stdin.buffer.read() if args.cert == "-" else open(args.cert, "rb").read()
            ders = load_certificates(raw)
            target, hostname = args.cert, args.hostname
        else:
            host, port = split_target(args.target, args.port)
            target = f"{host}:{port}"
            sni = host  # Python skips SNI for IP literals but still checks IP SANs
            conn, der = connect(host, port, args.timeout, sni)
            notes = {}
            if not args.no_legacy:
                for ver in ("TLSv1", "TLSv1.1"):
                    notes[ver] = probe_protocol(host, port, ver, args.timeout, sni)
            # the probe speaks raw TLS 1.3 itself, so it also runs when the local ssl module cannot
            if not args.no_pq and (conn.get("protocol") == "TLSv1.3" or not conn.get("client_tls13")):
                conn.update(probe_pq(host, port, args.timeout, sni))
            conn["legacy"] = {k: v[0] for k, v in notes.items()}
            conn["legacy_notes"] = notes
            ders = [der] if der else []
            hostname = args.hostname or host
        if not ders:
            raise ValueError("no certificate received")
        cert = parse_certificate(ders[0])
    except (OSError, ValueError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    findings = grade_certificate(cert, hostname, now)
    if conn:
        findings += grade_connection(conn)
    findings.sort(key=lambda f: -SEVERITY_ORDER.index(f["severity"]))

    if args.json:
        conn_out = None
        if conn:
            conn_out = {k: v for k, v in conn.items() if k != "legacy_notes"}
            conn_out["legacy_notes"] = {k: v[1] for k, v in conn.get("legacy_notes", {}).items()}
        print(json.dumps({"target": target, "mode": "file" if args.cert else "live",
                          "chain_length": len(ders), "connection": conn_out,
                          "certificate": cert_for_json(cert, now), "findings": findings}, indent=2))
    else:
        print(render_text(target, conn, cert, findings, now))

    if args.fail_on != "never":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
