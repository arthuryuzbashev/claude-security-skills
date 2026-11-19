#!/usr/bin/env python3
"""Decode a JWT and flag risky header and claim choices. Never verifies or forges anything.

Usage:
  jwt_inspect.py eyJhbGciOi...
  echo "$TOKEN" | jwt_inspect.py -
  jwt_inspect.py --file token.txt --json
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SENSITIVE_CLAIM_HINTS = ("password", "passwd", "secret", "ssn", "credit", "card", "cvv", "apikey", "api_key", "private")


def finding(fid, severity, title, detail, fix):
    return {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}


def b64url_decode(part: str) -> bytes:
    pad = "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(part + pad)


def decode(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], str]:
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) == 5:
        raise ValueError("this is a JWE (encrypted token, 5 parts); only the header can be read")
    if len(parts) != 3:
        raise ValueError(f"expected 3 dot-separated parts, got {len(parts)}")
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError) as err:
        raise ValueError(f"not valid base64url JSON: {err}")
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("header and payload must be JSON objects")
    return header, payload, parts[2]


# Five minutes is the usual clock skew allowance verifiers apply to time claims
CLOCK_SKEW = 300


def analyze(header: Dict[str, Any], payload: Dict[str, Any], signature: str, now: Optional[float] = None) -> List[Dict[str, str]]:
    now = time.time() if now is None else now
    out = []
    alg = str(header.get("alg", ""))
    if alg.lower() == "none" or not signature:
        out.append(finding("JWT-001", "critical", "Token is unsigned (alg none or empty signature)",
                           f"alg={alg!r}, signature length {len(signature)}. If a server accepts this, anyone can mint tokens.",
                           "Reject alg none server-side and pin the expected algorithm when verifying."))
    elif alg.upper().startswith("HS"):
        out.append(finding("JWT-002", "info", f"Symmetric algorithm {alg}",
                           "Every service that verifies the token also holds the key that can sign it.",
                           "Fine for one service. Across services prefer RS256/ES256/EdDSA, and use a random key of 256+ bits."))
    for key in ("jku", "x5u"):
        if key in header:
            out.append(finding("JWT-003", "high", f"Header carries {key} (remote key URL)",
                               f"{key}={header[key]!r}. Verifiers that follow it can be pointed at an attacker's key.",
                               f"Ignore {key} or allow-list exact URLs; load keys from local config."))
    if "jwk" in header:
        out.append(finding("JWT-004", "high", "Header embeds its own jwk",
                           "A verifier that trusts the embedded key accepts self-signed tokens.",
                           "Never verify with a key taken from the token itself."))
    if "x5c" in header:
        out.append(finding("JWT-006", "medium", "Header embeds an x5c certificate chain",
                           "Safe only if the verifier validates the chain against pinned roots and checks the leaf identity; otherwise any self-made certificate signs valid tokens.",
                           "Validate x5c against a fixed trust anchor and expected subject, or ignore it and use locally configured keys."))
    kid = header.get("kid")
    if isinstance(kid, str) and any(ch in kid for ch in ("/", "\\", "..", "'", '"', ";", "|")):
        out.append(finding("JWT-005", "medium", "kid contains path or query characters",
                           f"kid={kid!r}. If it is used in a file path or SQL lookup it can be injected.",
                           "Treat kid as an opaque id and look it up in a fixed map."))
    exp = payload.get("exp")
    iat = payload.get("iat")
    if exp is None:
        out.append(finding("JWT-010", "medium", "No exp claim",
                           "The token never expires, so a leaked copy works forever.",
                           "Set exp, e.g. 15 minutes for access tokens, and use refresh tokens."))
    elif isinstance(exp, (int, float)):
        if exp < now:
            out.append(finding("JWT-011", "info", "Token is expired",
                               f"exp was {_fmt(exp)}.", "No action, unless a server still accepts it."))
        start = iat if isinstance(iat, (int, float)) else now
        life = exp - start
        if life > 7 * 86400:
            out.append(finding("JWT-012", "low", "Very long lifetime",
                               f"Valid for about {int(life // 86400)} days.",
                               "Keep access tokens short-lived (minutes to hours)."))
    future = [c for c in ("iat", "nbf") if isinstance(payload.get(c), (int, float)) and payload[c] > now + CLOCK_SKEW]
    if future:
        out.append(finding("JWT-014", "low", f"{'/'.join(future)} lies in the future",
                           f"{', '.join(c + '=' + _fmt(payload[c]) for c in future)}. Either the issuer clock is wrong or tokens are minted ahead of use.",
                           "Sync issuer clocks (NTP) and reject tokens whose nbf/iat is beyond a small skew."))
    for claim in ("iss", "aud"):
        if claim not in payload:
            out.append(finding("JWT-013", "low", f"No {claim} claim",
                               f"Without {claim} a token minted for one service can be replayed at another that shares the key.",
                               f"Set {claim} and check it when verifying."))
    leaked = [k for k in payload if any(h in k.lower() for h in SENSITIVE_CLAIM_HINTS)]
    if leaked:
        out.append(finding("JWT-020", "high", "Sensitive-looking claims in payload",
                           f"Claims {', '.join(leaked)} are readable by anyone holding the token (JWTs are encoded, not encrypted).",
                           "Keep secrets out of tokens; store a reference id instead."))
    out.sort(key=lambda f: -SEVERITY_ORDER.index(f["severity"]))
    return out


def _fmt(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))


def mask_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    masked = {}
    for k, v in payload.items():
        if any(h in k.lower() for h in SENSITIVE_CLAIM_HINTS) and isinstance(v, str):
            masked[k] = v[:4] + "..." if len(v) > 4 else "***"
        else:
            masked[k] = v
    return masked


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Decode a JWT and flag risky choices (read-only, no verification).")
    ap.add_argument("token", nargs="?", help="the token, or '-' to read stdin")
    ap.add_argument("--file", help="read the token from a file")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"])
    args = ap.parse_args(argv)

    if args.file:
        token = open(args.file, encoding="utf-8").read()
    elif args.token == "-" or (args.token is None and not sys.stdin.isatty()):
        token = sys.stdin.read()
    elif args.token:
        token = args.token
    else:
        ap.print_usage(sys.stderr)
        return 2
    try:
        header, payload, sig = decode(token)
    except ValueError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    findings = analyze(header, payload, sig)
    safe_payload = mask_payload(payload)
    if args.json:
        print(json.dumps({"header": header, "payload": safe_payload, "signature_present": bool(sig),
                          "findings": findings}, indent=2, default=str))
    else:
        print("Header:  " + json.dumps(header))
        print("Payload: " + json.dumps(safe_payload, default=str))
        for claim in ("iat", "nbf", "exp"):
            if isinstance(payload.get(claim), (int, float)):
                print(f"  {claim}: {_fmt(payload[claim])}")
        print(f"\n{len(findings)} finding(s)")
        for f in findings:
            print(f"[{f['severity'].upper():8}] {f['id']}  {f['title']}\n           {f['detail']}\n           fix: {f['fix']}")
    if args.fail_on != "never":
        t = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= t for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
