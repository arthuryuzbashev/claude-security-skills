#!/usr/bin/env python3
"""Scan source code for weak cryptography, or identify the format of a hash string.

Scan mode greps files for weak hashes on passwords, ECB, static IVs, hard-coded keys,
non-crypto randomness for secrets, DES/3DES/RC4, small RSA keys, RSA PKCS#1 v1.5 or raw
encryption, low PBKDF2 iterations, low bcrypt cost, disabled certificate checks, pinned
old TLS versions and JWT "none". Hash-id mode names a hash format (md5, bcrypt, argon2id ...);
it never tries to crack anything.

Usage:
  crypto_review.py src/
  crypto_review.py app.py lib/ --json --fail-on medium
  crypto_review.py --hash-id '$2b$12$...'
  cat hashes.txt | crypto_review.py --hash-id -
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Dict, Iterable, List, Optional

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SOURCE_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".kts", ".scala", ".groovy",
    ".go", ".rb", ".php", ".cs", ".vb", ".c", ".h", ".cc", ".cpp", ".hpp", ".m", ".mm", ".swift",
    ".rs", ".dart", ".ex", ".exs", ".erl", ".lua", ".pl", ".sh", ".bash", ".zsh", ".ps1", ".vue",
    ".svelte", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".env", ".properties",
    ".xml", ".gradle", ".tf", ".pem", ".key",
}
SOURCE_NAMES = {"Dockerfile", "Makefile", ".env", "Jenkinsfile", "Procfile"}
SKIP_DIRS = {".git", "node_modules", "vendor", "venv", ".venv", "dist", "build", "__pycache__", ".tox",
             "target", "Pods", ".gradle", ".idea", ".next", "coverage"}
MAX_FILE_BYTES = 2_000_000
SUPPRESS = "secskills-ignore"


def finding(fid, severity, title, detail, fix, location=None, evidence=None):
    f = {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}
    if location:
        f["location"] = location
    if evidence is not None:
        f["evidence"] = evidence
    return f


def mask(value: str) -> str:
    return value[:4] + "..." if len(value) > 4 else "***"


I = re.I
PASSWORD_CTX = re.compile(r"pass(word|wd|phrase)?\b|\bpwd\b|passwd|\bpw\b", I)
STRONG_KDF = re.compile(r"bcrypt|argon2|scrypt|pbkdf2|hmac|crypt_blowfish|password_hash", I)
FAST_HASH = re.compile(r"\b(md5|sha-?1|sha_?1|sha-?256|sha_?256|sha-?512|sha_?512)\b", I)
MD5 = re.compile(r"\bmd5\b|md5\(|md5Hex|MD5\.|createHash\(\s*['\"]md5", I)
SHA1 = re.compile(r"\bsha-?1\b|\bsha1\(|sha1Hex|SHA1\.|createHash\(\s*['\"]sha1|['\"]sha1['\"]", I)
ECB = re.compile(r"\bECB\b|MODE_ECB|-ecb['\"]|_ecb\b|/ECB/|CipherMode\.ECB", I)
STATIC_IV = re.compile(
    r"\b(iv|nonce|init_?vector|initVector)\s*[:=]\s*(b?['\"][^'\"]{8,}['\"]|bytes\(\s*\d+\s*\)|b['\"](\\x00)+['\"]"
    r"|new\s+byte\s*\[\s*\d+\s*\]|Buffer\.alloc\(\s*\d+\s*\)|\[\s*0\s*(,\s*0\s*)+\])"
    r"|IvParameterSpec\(\s*(['\"]|new\s+byte\s*\[)|IvParameterSpec\(\s*\"[^\"]+\"\.getBytes", I)
HARDCODED_KEY = re.compile(
    r"\b(?P<name>[A-Za-z_]*(secret|encryption_?key|aes_?key|private_?key|signing_?key|hmac_?key|crypto_?key|"
    r"cipher_?key|master_?key|jwt_?secret|api_?secret|secret_?key)[A-Za-z_]*)\s*[:=]\s*b?['\"](?P<val>[^'\"\s]{16,})['\"]", I)
SECRET_KEY_SPEC = re.compile(r"SecretKeySpec\(\s*['\"](?P<val>[^'\"]+)['\"]", I)
PLACEHOLDER = re.compile(r"change[_-]?me|your[_-]|xxxx|example|placeholder|dummy|<.*>|\$\{|process\.env|os\.environ|getenv", I)
PRIVATE_KEY = re.compile(r"-----BEGIN (?P<kind>RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
WEAK_RANDOM = re.compile(
    r"Math\.random\(|\brandom\.(random|randint|randrange|choice|choices|getrandbits|sample)\(|\bmt_rand\(|\brand\(\)"
    r"|\bnew\s+Random\(|\brand\.(Int|Intn|Int63|Read)\(|\bsrand\(|\blrand48\(")
SECRET_CTX = re.compile(r"token|secret|passw|salt|nonce|\botp\b|session|api_?key|reset|csrf|\biv\b|\bkey\b|uuid|invite|verification", I)
WEAK_CIPHER_STRONG = re.compile(
    r"\b(RC4|ARC4|RC2|DES)\b(?![-_]?(ede|3|EDE))|['\"]des-cbc['\"]|['\"]rc4['\"]|\bARC4\.new|\bDES\.new|\bdes-ecb\b")
WEAK_CIPHER_MEDIUM = re.compile(r"\b(DESede|TripleDES|3DES|DES3|Blowfish)\b|des-ede3|['\"]des3['\"]|DES3\.new", I)
SMALL_RSA = re.compile(
    r"(RSA\.generate|GenerateKey|genrsa|RSACryptoServiceProvider|\.initialize|key_?size|modulusLength|KeySize|"
    r"generate_private_key|rsa_keygen_bits|-newkey\s+rsa:)\D{0,40}?\b(512|768|1024|1536)\b", I)
TLS_OFF = re.compile(
    r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED['\"]?\s*[:=]\s*['\"]?0"
    r"|InsecureSkipVerify\s*:\s*true|_create_unverified_context|\bCERT_NONE\b|check_hostname\s*=\s*False"
    r"|CURLOPT_SSL_VERIFY(PEER|HOST)\s*,\s*(0|false)\b|\bcurl\b[^\n]*\s(-k|--insecure)\b|--no-check-certificate"
    r"|NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|VERIFY_NONE|ServerCertificate(Custom)?ValidationCallback\s*=[^;]*\btrue\b"
    r"|strict_?ssl\s*[:=]\s*false|ssl_?verify\s*[:=]\s*false|sslVerify\s*=\s*false|setHostnameVerifier\([^)]*->\s*true", I)
JWT_NONE = re.compile(r"algorithms?['\"]?\s*[:=]\s*(\[[^\]]*)?['\"]none['\"]|['\"]alg['\"]\s*:\s*['\"]none['\"]|Algorithm\.none\(\)", I)
JWT_NOVERIFY = re.compile(r"verify_signature['\"]?\s*:\s*False|jwt\.decode\([^)]*verify\s*=\s*False|ignoreExpiration\s*:\s*true", I)
# Java names RSA transforms "RSA/ECB/...": the ECB there is a no-op label, not a block mode.
RSA_ECB_LABEL = re.compile(r"RSA/ECB/", I)
RSA_NO_PADDING = re.compile(r"RSA/(ECB|NONE)/NoPadding|RSA_NO_PADDING|\bNoPadding\(\)", I)
RSA_PKCS1_ENC = re.compile(
    r"RSA/(ECB|NONE)/PKCS1Padding|RSA_PKCS1_PADDING|rsa\.(Encrypt|Decrypt)PKCS1v15(SessionKey)?\("
    r"|RSAEncryptionPadding\.Pkcs1\b|Cipher\s+import\s+PKCS1_v1_5|Cipher\.PKCS1_v1_5"
    r"|\.(encrypt|decrypt)\([^)]*padding\.PKCS1v15\(\)|OPENSSL_PKCS1_PADDING", I)
# PBKDF2 iteration counts (OWASP Password Storage Cheat Sheet, checked 2026-11-19).
PBKDF2_MIN = {"sha1": 1_400_000, "sha256": 600_000, "sha512": 220_000}
PBKDF2_CALLS = [
    re.compile(r"iterations\s*[:=]\s*(?P<n>\d[\d_]*)", I),                           # PBKDF2HMAC(iterations=...), {iterations: n}
    re.compile(r"pbkdf2_hmac\(\s*[^,]+,[^,]+,[^,]+,\s*(?P<n>\d[\d_]*)", I),            # Python hashlib
    re.compile(r"pbkdf2(Sync)?\(\s*[^,]+,[^,]+,\s*(?P<n>\d[\d_]*)", I),                # Node crypto
    re.compile(r"pbkdf2\.Key\(\s*[^,]+,[^,]+,\s*(?P<n>\d[\d_]*)", I),                 # Go x/crypto
    re.compile(r"PBEKeySpec\(\s*[^,]+,[^,]+,\s*(?P<n>\d[\d_]*)", I),                   # Java
    re.compile(r"Rfc2898DeriveBytes(\.Pbkdf2)?\(\s*[^,]+,[^,]+,\s*(?P<n>\d[\d_]*)", I),  # .NET
    re.compile(r"openssl_pbkdf2\(\s*[^,]+,[^,]+,[^,]+,\s*(?P<n>\d[\d_]*)", I),         # PHP
    re.compile(r"hash_pbkdf2\(\s*[^,]+,[^,]+,[^,]+,\s*(?P<n>\d[\d_]*)", I),            # PHP
]
PBKDF2_CTX = re.compile(r"pbkdf2|PBEKeySpec|Rfc2898DeriveBytes", I)
BCRYPT_COST = [
    re.compile(r"gensalt\(\s*(rounds\s*=\s*)?(?P<n>\d{1,2})\s*[,)]", I),               # Python bcrypt, Java jBCrypt
    re.compile(r"genSalt(Sync)?\(\s*(?P<n>\d{1,2})\s*[,)]", I),                       # Node bcrypt(js)
    re.compile(r"bcrypt\w*\.hash(Sync)?\(\s*[^,]+,\s*(?P<n>\d{1,2})\s*[,)]", I),       # Node bcrypt.hash(pw, 8)
    re.compile(r"GenerateFromPassword\(\s*[^,]+,\s*(?P<n>\d{1,2})\s*\)"),              # Go
    re.compile(r"BCryptPasswordEncoder\(\s*(?P<n>\d{1,2})\s*[,)]"),                     # Spring
    re.compile(r"PASSWORD_BCRYPT[^)]*['\"]cost['\"]\s*=>\s*(?P<n>\d{1,2})"),             # PHP
    re.compile(r"BCRYPT_ROUNDS\s*[:=]\s*['\"]?(?P<n>\d{1,2})\b"),                         # Laravel .env / config
]
BCRYPT_MIN_COST = 10
GO_BCRYPT_MIN = re.compile(r"GenerateFromPassword\([^)]*bcrypt\.MinCost")
OLD_TLS_PIN = re.compile(
    r"PROTOCOL_(SSLv2|SSLv3|TLSv1|TLSv1_1)\b|TLSVersion\.(SSLv3|TLSv1|TLSv1_1)\b|\b(SSLv3|TLSv1|TLSv1_1)_(client_|server_)?method\b"
    r"|minVersion['\"]?\s*:\s*['\"]TLSv1(\.1)?['\"]|secureProtocol['\"]?\s*:\s*['\"](SSLv3|TLSv1|TLSv1_1)_method"
    r"|MinVersion\s*:\s*tls\.Version(SSL30|TLS10|TLS11)\b|getInstance\(\s*\"(SSLv3|TLSv1|TLSv1\.1)\"\s*\)"
    r"|SecurityProtocolType\.(Ssl3|Tls|Tls11)\b(?!\d)"
    r"|^\s*ssl_protocols\b[^;#]*\b(SSLv3|TLSv1|TLSv1\.1)(?![.\d])")


def scan_line(line: str) -> List[Dict[str, str]]:
    """Return raw hits for one line: dicts with id, severity, title, detail, fix and optional secret."""
    hits = []

    def add(fid, sev, title, detail, fix, secret=None):
        hits.append({"id": fid, "severity": sev, "title": title, "detail": detail, "fix": fix, "secret": secret})

    pw_hash = False
    if FAST_HASH.search(line) and PASSWORD_CTX.search(line) and not STRONG_KDF.search(line):
        pw_hash = True
        add("CRY-001", "high", "Fast hash used on a password",
            "MD5/SHA-1/plain SHA-2 are built to be fast; leaked hashes fall to GPU guessing in hours.",
            "Hash passwords with argon2id, scrypt or bcrypt (or PBKDF2-HMAC-SHA256 at 600,000+ iterations).")
    if not pw_hash and MD5.search(line):
        add("CRY-002", "low", "MD5 in use",
            "Fine for non-security checksums and cache keys, broken for signatures, integrity against attackers or passwords.",
            "Use SHA-256 for integrity, HMAC-SHA256 for authenticity, argon2id for passwords.")
    elif not pw_hash and SHA1.search(line) and "hmac" not in line.lower():
        add("CRY-003", "low", "SHA-1 in use",
            "SHA-1 has practical collisions. Acceptable only where collisions do not matter (git object ids, legacy HMAC).",
            "Use SHA-256 or better.")
    if ECB.search(RSA_ECB_LABEL.sub("RSA/", line)):
        add("CRY-010", "high", "ECB cipher mode",
            "ECB encrypts equal blocks to equal ciphertext, so patterns in the data stay visible.",
            "Use an AEAD mode: AES-GCM or ChaCha20-Poly1305 with a fresh random nonce per message.")
    if STATIC_IV.search(line):
        add("CRY-011", "high", "Static or zero IV/nonce",
            "Reusing an IV leaks plaintext relations (CBC) and breaks GCM/CTR outright.",
            "Generate a random IV/nonce per encryption (os.urandom(12), crypto.randomBytes(12)) and store it with the ciphertext.")
    m = HARDCODED_KEY.search(line) or SECRET_KEY_SPEC.search(line)
    if m and not PLACEHOLDER.search(m.group("val")):
        add("CRY-020", "high", "Hard-coded key or secret",
            "Anyone with the source, a build artifact or the git history has the key.",
            "Load keys from a secret manager or environment, rotate this one, and purge it from history.",
            secret=m.group("val"))
    pk = PRIVATE_KEY.search(line)
    if pk:
        encrypted = (pk.group("kind") or "").strip() == "ENCRYPTED"
        add("CRY-021", "medium" if encrypted else "critical", "Private key in source",
            "A private key block is committed" + (" (passphrase-protected)." if encrypted else ", unencrypted."),
            "Remove it, revoke/rotate the key, purge history, and keep keys in a vault or KMS.")
    if WEAK_RANDOM.search(line) and SECRET_CTX.search(line):
        add("CRY-030", "high", "Non-cryptographic random used for a secret",
            "Math.random / random / rand are predictable; tokens built from them can be guessed.",
            "Use secrets.token_urlsafe (Python), crypto.randomBytes / crypto.randomUUID (Node), SecureRandom (Java), crypto/rand (Go).")
    if WEAK_CIPHER_STRONG.search(line):
        add("CRY-040", "high", "Broken cipher (DES/RC4/RC2)",
            "DES has a 56-bit key and RC4 has exploitable keystream biases.",
            "Use AES-256-GCM or ChaCha20-Poly1305.")
    elif WEAK_CIPHER_MEDIUM.search(line):
        add("CRY-041", "medium", "Legacy 64-bit block cipher (3DES/Blowfish)",
            "64-bit blocks allow birthday attacks on long sessions (Sweet32); NIST disallowed 3DES for encryption after 2023.",
            "Use AES-GCM.")
    if RSA_NO_PADDING.search(line):
        add("CRY-012", "high", "RSA encryption without padding",
            "Textbook RSA is deterministic and malleable: equal messages give equal ciphertext and an attacker "
            "can change the plaintext in predictable ways.",
            "Use RSA-OAEP with SHA-256 (RSA/ECB/OAEPWithSHA-256AndMGF1Padding, padding.OAEP, RSA_PKCS1_OAEP_PADDING), "
            "or better, ECIES / HPKE or a hybrid scheme with AES-GCM.")
    elif RSA_PKCS1_ENC.search(line):
        add("CRY-012", "medium", "RSA PKCS#1 v1.5 encryption padding",
            "PKCS#1 v1.5 decryption leaks through error messages and timing (Bleichenbacher, ROBOT, Marvin), letting "
            "an attacker decrypt or forge with enough queries. Signing with PKCS#1 v1.5 is a different scheme and is fine.",
            "Switch encryption to RSA-OAEP with SHA-256, or to a hybrid scheme (HPKE, AES-GCM with an ECDH key).")
    if PBKDF2_CTX.search(line) or (re.search(r"iterations", line, I) and re.search(r"pbkdf|kdf|derive", line, I)):
        for rx in PBKDF2_CALLS:
            pm = rx.search(line)
            if not pm:
                continue
            n = int(pm.group("n").replace("_", ""))
            low = line.lower()
            algo = "sha512" if re.search(r"sha-?512", low) else "sha1" if re.search(r"sha-?1\b|hmacsha1|sha1\.new", low) else "sha256"
            need = PBKDF2_MIN[algo]
            if n < need:
                add("CRY-051", "high" if n < 10_000 else "medium",
                    f"PBKDF2 with {n:,} iterations (HMAC-{algo.upper()})",
                    f"OWASP's minimum for PBKDF2-HMAC-{algo.upper()} is {need:,} iterations. Fewer makes each leaked "
                    "password hash cheap to guess on GPUs.",
                    f"Raise to {need:,}+ iterations (rehash on next login), or move to argon2id / scrypt / bcrypt.")
            break
    for rx in BCRYPT_COST:
        bm = rx.search(line)
        if bm and 4 <= int(bm.group("n")) < BCRYPT_MIN_COST:
            add("CRY-052", "medium", f"bcrypt cost {bm.group('n')} is below 10",
                "Each step down halves the work an attacker needs per guess. OWASP sets 10 as the minimum.",
                "Use cost 12 (or the highest your login latency allows, 10 at the least); old hashes upgrade on next login.")
            break
    else:
        if GO_BCRYPT_MIN.search(line):
            add("CRY-052", "medium", "bcrypt cost set to bcrypt.MinCost (4)",
                "MinCost is meant for tests. Each step down halves the work an attacker needs per guess.",
                "Use bcrypt.DefaultCost (10) or higher, 12 is common.")
    if OLD_TLS_PIN.search(line):
        add("CRY-061", "medium", "Code pins SSL 3.0, TLS 1.0 or TLS 1.1",
            "These protocol versions are deprecated (RFC 8996) and fail PCI DSS. A client or server pinned to "
            "them, or allowing them as the minimum, can be downgraded or refuse modern peers.",
            "Use the library default context and set the minimum to TLS 1.2 (ssl.TLSVersion.TLSv1_2, "
            "tls.VersionTLS12, minVersion: 'TLSv1.2', SSLContext.getInstance(\"TLSv1.3\")).")
    rsa = SMALL_RSA.search(line)
    if rsa:
        add("CRY-050", "high", f"Small key size ({rsa.group(2)} bits)",
            "RSA/DSA/DH keys under 2048 bits are below current baselines; 512 and 768 have been factored publicly.",
            "Use RSA-3072 (or 2048 minimum), or switch to ECDSA P-256 / Ed25519.")
    if TLS_OFF.search(line) and "jwt" not in line.lower():
        add("CRY-060", "high", "TLS certificate verification disabled",
            "Any machine on the network path can impersonate the server and read or change the traffic.",
            "Remove the override; for private CAs pass the CA bundle (verify='/path/ca.pem', ca: [...]) instead.")
    if JWT_NONE.search(line):
        add("CRY-070", "critical", "JWT 'none' algorithm allowed",
            "Unsigned tokens let anyone set any claim, including the user id and role.",
            "Pin the expected algorithm list (e.g. ['RS256']) and never include 'none'.")
    if JWT_NOVERIFY.search(line):
        add("CRY-071", "high", "JWT verification switched off",
            "Signature or expiry checks are disabled, so forged or old tokens pass.",
            "Verify signature and exp on every request; decode-without-verify only for logging.")
    return hits


def mask_evidence(line: str, secret: Optional[str]) -> str:
    text = line.strip()
    if secret:
        text = text.replace(secret, mask(secret))
    return text[:160] + ("..." if len(text) > 160 else "")


def scan_text(text: str, path: str = "<input>") -> List[Dict[str, str]]:
    out = []
    in_key = False
    for no, line in enumerate(text.splitlines(), 1):
        if SUPPRESS in line:
            continue
        if in_key:  # do not report base64 lines inside a key block
            in_key = "-----END" not in line
            continue
        for hit in scan_line(line):
            out.append(finding(hit["id"], hit["severity"], hit["title"], hit["detail"], hit["fix"],
                               location=f"{path}:{no}", evidence=mask_evidence(line, hit["secret"])))
            if hit["id"] == "CRY-021":
                in_key = True
    return out


def iter_files(paths: Iterable[str], all_files: bool = False) -> Iterable[str]:
    for p in paths:
        if os.path.isfile(p):
            yield p
            continue
        if not os.path.isdir(p):
            raise FileNotFoundError(p)
        for root, dirs, files in os.walk(p):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            for name in sorted(files):
                ext = os.path.splitext(name)[1].lower()
                if all_files or ext in SOURCE_EXTS or name in SOURCE_NAMES or name.startswith(".env"):
                    yield os.path.join(root, name)


def _loc_key(location: str):
    path, _, line = location.rpartition(":")
    return path, int(line) if line.isdigit() else 0


def scan_paths(paths: Iterable[str], all_files: bool = False) -> Dict[str, object]:
    findings, scanned = [], 0
    for path in iter_files(paths, all_files):
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                continue
            data = open(path, "rb").read()
        except OSError:
            continue
        if b"\x00" in data[:4096]:
            continue
        scanned += 1
        findings += scan_text(data.decode("utf-8", errors="replace"), path)
    findings.sort(key=lambda f: (-SEVERITY_ORDER.index(f["severity"]), _loc_key(f["location"])))
    return {"files_scanned": scanned, "findings": findings}


# ---------------------------------------------------------------- hash identification

HASH_PATTERNS = [
    (re.compile(r"^\$argon2(id|i|d)\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$"), "argon2"),
    (re.compile(r"^\$2[abxy]?\$(\d{2})\$[./A-Za-z0-9]{53}$"), "bcrypt"),
    (re.compile(r"^\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)\$"), "scrypt (passlib)"),
    (re.compile(r"^\$7\$[./A-Za-z0-9]{11,}\$"), "scrypt (crypt $7$)"),
    (re.compile(r"^\$y\$[./A-Za-z0-9]+\$"), "yescrypt"),
    (re.compile(r"^\$6\$(rounds=\d+\$)?[^$]{1,16}\$[./A-Za-z0-9]{86}$"), "sha512crypt"),
    (re.compile(r"^\$5\$(rounds=\d+\$)?[^$]{1,16}\$[./A-Za-z0-9]{43}$"), "sha256crypt"),
    (re.compile(r"^\$1\$[^$]{1,8}\$[./A-Za-z0-9]{22}$"), "md5crypt"),
    (re.compile(r"^\$apr1\$[^$]{1,8}\$[./A-Za-z0-9]{22}$"), "apr1 (Apache md5crypt)"),
    (re.compile(r"^pbkdf2_sha(256|1)\$(\d+)\$[^$]+\$[A-Za-z0-9+/=]+$"), "pbkdf2 (Django)"),
    (re.compile(r"^\$pbkdf2(-sha(256|512))?\$(\d+)\$"), "pbkdf2 (passlib)"),
    (re.compile(r"^\*[0-9A-F]{40}$", I), "MySQL 4.1+ (double SHA-1)"),
    (re.compile(r"^\$wp\$2[aby]\$(\d{2})\$[./A-Za-z0-9]{53}$"), "bcrypt (WordPress 6.8+)"),
    (re.compile(r"^\$[PH]\$[./0-9A-Za-z]{31}$"), "phpass (portable, iterated MD5)"),
    (re.compile(r"^\$S\$[./0-9A-Za-z]{52}$"), "Drupal 7 (iterated SHA-512)"),
    (re.compile(r"^\{(SHA|SSHA|SHA256|SSHA256|SHA512|SSHA512|MD5|SMD5)\}[A-Za-z0-9+/=]+$", I), "LDAP"),
]
# Wrappers around a standard hash: strip the prefix and identify the rest.
HASH_WRAPPERS = [
    (re.compile(r"^\{CRYPT\}", I), "LDAP {CRYPT}"),
    (re.compile(r"^argon2(?=\$argon2)"), "Django argon2"),
    (re.compile(r"^bcrypt_sha256\$(?=\$2)"), "Django bcrypt_sha256"),
    (re.compile(r"^bcrypt\$(?=\$2)"), "Django bcrypt"),
]
HEX_LENGTHS = {
    32: (["MD5", "NTLM", "MD4", "LM"], "weak"),
    40: (["SHA-1", "RIPEMD-160"], "weak"),
    56: (["SHA-224", "SHA3-224"], "weak"),
    64: (["SHA-256", "SHA3-256", "BLAKE2s-256"], "weak"),
    96: (["SHA-384", "SHA3-384"], "weak"),
    128: (["SHA-512", "SHA3-512", "BLAKE2b-512", "Whirlpool"], "weak"),
}


def identify_hash(value: str) -> Dict[str, object]:
    """Name the likely format(s) of a hash string. Read-only: no cracking, no lookups."""
    s = value.strip()
    for wrx, wname in HASH_WRAPPERS:
        wm = wrx.match(s)
        if wm and len(s) > wm.end():
            inner = identify_hash(s[wm.end():])
            if inner["candidates"]:
                inner["input"] = mask(s)
                inner["length"] = len(s)
                inner["candidates"] = [f"{wname}: {c}" for c in inner["candidates"]]
                if "sha256" in wname:
                    inner["note"] = inner["note"].replace(" bcrypt only uses the first 72 bytes of a password.",
                                                          " Pre-hashed with SHA-256, so the 72-byte limit does not apply.")
                return inner
    result = {"input": mask(s) if len(s) > 8 else "***", "length": len(s), "candidates": [],
              "password_storage": "unknown", "params": {}, "note": ""}
    for rx, name in HASH_PATTERNS:
        m = rx.match(s)
        if not m:
            continue
        result["candidates"] = [name]
        if name == "argon2":
            variant, mem, t, p = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4))
            result["candidates"] = [f"argon2{variant}"]
            result["params"] = {"memory_kib": mem, "iterations": t, "parallelism": p}
            ok = variant == "id" and mem >= 19456 and t >= 2
            result["password_storage"] = "strong" if ok else "ok"
            result["note"] = "Meets the OWASP minimum (m=19 MiB, t=2)." if ok else \
                "Below OWASP's argon2id minimum (m=19456 KiB, t=2, p=1) or not the id variant."
        elif name.startswith("bcrypt"):
            cost = int(m.group(1))
            result["params"] = {"cost": cost}
            result["password_storage"] = "strong" if cost >= 10 else "ok"
            result["note"] = f"Cost {cost}." + ("" if cost >= 10 else " Raise to 10+ (12 is common today).") + \
                (" WordPress pre-hashes with HMAC-SHA384, so the 72-byte limit does not apply."
                 if "WordPress" in name else " bcrypt only uses the first 72 bytes of a password.")
        elif name.startswith("scrypt"):
            result["password_storage"] = "strong"
            if m.groups():
                result["params"] = {"log2_N": int(m.group(1)), "r": int(m.group(2)), "p": int(m.group(3))}
        elif name == "yescrypt":
            result["password_storage"] = "strong"
            result["note"] = "Default on recent Debian, Ubuntu and Fedora /etc/shadow."
        elif name == "sha512crypt" or name == "sha256crypt":
            rounds = re.search(r"rounds=(\d+)", s)
            result["params"] = {"rounds": int(rounds.group(1)) if rounds else 5000}
            result["password_storage"] = "ok"
            result["note"] = "Salted and iterated but GPU-friendly; prefer yescrypt/argon2id for new hashes."
        elif name in ("md5crypt", "apr1 (Apache md5crypt)", "MySQL 4.1+ (double SHA-1)"):
            result["password_storage"] = "weak"
            result["note"] = "Legacy scheme, fast to brute-force on GPUs. Rehash on next login."
        elif name.startswith("phpass"):
            result["params"] = {"log2_rounds": "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".index(s[3])}
            result["password_storage"] = "weak"
            result["note"] = ("Old WordPress / phpBB format: iterated MD5, fast on GPUs. "
                              "WordPress 6.8+ rehashes these to $wp$2y$ (bcrypt) at the next login.")
        elif name.startswith("Drupal"):
            result["password_storage"] = "ok"
            result["note"] = "Salted and iterated but GPU-friendly; Drupal 10.1+ uses PHP password_hash (bcrypt) for new hashes."
        elif name == "LDAP":
            scheme = s[1:s.index("}")].upper()
            result["candidates"] = [f"LDAP {{{scheme}}}"]
            result["password_storage"] = "weak"
            salted = scheme in ("SSHA", "SSHA256", "SSHA512", "SMD5")
            digest = {"SHA": "SHA-1", "SSHA": "SHA-1", "MD5": "MD5", "SMD5": "MD5"}.get(scheme, "SHA-" + scheme[-3:])
            result["params"] = {"digest": digest, "salted": salted}
            result["note"] = (f"One round of {'salted' if salted else 'unsalted'} {digest}, fast on GPUs. "
                              "Use {ARGON2} or {CRYPT} with yescrypt/bcrypt if the directory server supports it.")
        elif name.startswith("pbkdf2"):
            iters = re.search(r"\$(\d+)\$", s)
            n = int(iters.group(1)) if iters else 0
            algo = "sha512" if "sha512" in s[:16] else "sha1" if (s.startswith("pbkdf2_sha1$") or s.startswith("$pbkdf2$")) else "sha256"
            need = PBKDF2_MIN[algo]
            result["params"] = {"iterations": n, "prf": "HMAC-" + algo.upper()}
            result["password_storage"] = "strong" if n >= need else "ok"
            result["note"] = (f"OWASP suggests {need:,} iterations for PBKDF2-HMAC-{algo.upper()}." if n < need else "")
        return result
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) in HEX_LENGTHS:
        names, storage = HEX_LENGTHS[len(s)]
        result["candidates"] = names
        result["password_storage"] = storage
        result["note"] = ("Bare hex digest: no salt or work factor is visible. "
                          "If this stores passwords it is crackable at GPU speed.")
        if len(s) == 32:
            result["note"] += " MD5 and NTLM have the same length; context decides (Windows dumps = NTLM)."
        return result
    result["note"] = "Unknown format."
    return result


# ---------------------------------------------------------------- CLI

def render_findings(res: Dict[str, object]) -> str:
    findings = res["findings"]
    lines = [f"Crypto review: {res['files_scanned']} file(s) scanned, {len(findings)} finding(s)", ""]
    if not findings:
        lines.append("No weak crypto patterns found.")
    for f in findings:
        lines.append(f"[{f['severity'].upper():8}] {f['id']}  {f['title']}  ({f['location']})")
        lines.append(f"           {f['evidence']}")
        lines.append(f"           fix: {f['fix']}")
    return "\n".join(lines)


def render_hashes(results: List[Dict[str, object]]) -> str:
    lines = []
    for r in results:
        cands = ", ".join(r["candidates"]) or "unknown"
        lines.append(f"{r['input']} (len {r['length']}): {cands}  [password storage: {r['password_storage']}]")
        if r["params"]:
            lines.append("    params: " + ", ".join(f"{k}={v}" for k, v in r["params"].items()))
        if r["note"]:
            lines.append("    " + r["note"])
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Scan code for weak crypto, or identify a hash format.")
    ap.add_argument("paths", nargs="*", help="files or directories to scan")
    ap.add_argument("--hash-id", metavar="VALUE", help="identify a hash string ('-' = one per line on stdin)")
    ap.add_argument("--all-files", action="store_true", help="scan every non-binary file, not just source/config")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="scan mode: exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)

    if args.hash_id is not None:
        values = sys.stdin.read().splitlines() if args.hash_id == "-" else [args.hash_id]
        values = [v for v in (x.strip() for x in values) if v]
        if not values:
            print("error: no hash given", file=sys.stderr)
            return 2
        results = [identify_hash(v) for v in values]
        print(json.dumps({"mode": "hash_id", "results": results}, indent=2) if args.json else render_hashes(results))
        return 0

    if not args.paths:
        print("error: give paths to scan or --hash-id VALUE", file=sys.stderr)
        return 2
    try:
        res = scan_paths(args.paths, args.all_files)
    except FileNotFoundError as err:
        print(f"error: no such file or directory: {err}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"mode": "scan", **res}, indent=2))
    else:
        print(render_findings(res))
    if args.fail_on != "never":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= threshold for f in res["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
