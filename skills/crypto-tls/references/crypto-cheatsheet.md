# Crypto cheat sheet: what to use instead

Use it to turn `crypto_review.py` findings into code fixes. Default rule: use a well-known library's high-level API, never assemble primitives by hand.

## Replace this with that

| Weak | Use instead | Rule id |
|---|---|---|
| `md5(password)`, `sha1(password)`, `sha256(password + salt)` | argon2id, scrypt or bcrypt (PBKDF2 only where FIPS forces it) | CRY-001 |
| MD5 / SHA-1 for integrity or signatures | SHA-256 / SHA-512; HMAC-SHA256 when a key is involved | CRY-002/003 |
| AES-ECB | AES-GCM or ChaCha20-Poly1305 (authenticated encryption) | CRY-010 |
| Fixed / zero IV, reused nonce | Fresh random nonce per message, stored next to the ciphertext | CRY-011 |
| Key in source | Secret manager, KMS, or env injected at deploy; rotate the leaked one | CRY-020/021 |
| `Math.random`, `random`, `rand()`, `java.util.Random` for tokens | OS CSPRNG (table below) | CRY-030 |
| DES, RC4, RC2 | AES-256-GCM | CRY-040 |
| 3DES, Blowfish | AES-GCM | CRY-041 |
| RSA/DSA/DH < 2048 bits | RSA-3072, or ECDSA P-256 / Ed25519 / X25519 | CRY-050 |
| `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify` | Keep verification; pass the private CA bundle | CRY-060 |
| JWT `alg: none`, verification off | Pin algorithms on verify, check `exp`, `iss`, `aud` | CRY-070/071 |

## Password hashing parameters

Minimums from the OWASP Password Storage Cheat Sheet. Tune upward until a login takes about 100-500 ms on your hardware.

| Algorithm | Minimum |
|---|---|
| argon2id | m = 19 MiB (19456 KiB), t = 2, p = 1 |
| scrypt | N = 2^17, r = 8, p = 1 |
| bcrypt | cost 10 or more; input is truncated at 72 bytes |
| PBKDF2-HMAC-SHA256 | 600,000 iterations |
| PBKDF2-HMAC-SHA512 | 210,000 iterations |

Migrating from a weak hash: on the next successful login, verify against the old hash, then store the new one. For accounts that never log in, wrap the old hash (`argon2id(md5_hash)`) and flag it, so nothing stays as bare MD5.

## Secure randomness per language

| Language | Use | Not |
|---|---|---|
| Python | `secrets.token_urlsafe(32)`, `secrets.token_bytes`, `os.urandom` | `random.*` |
| Node.js | `crypto.randomBytes(32)`, `crypto.randomUUID()`, `crypto.randomInt` | `Math.random()` |
| Browser JS | `crypto.getRandomValues(new Uint8Array(32))`, `crypto.randomUUID()` | `Math.random()` |
| Java / Kotlin | `java.security.SecureRandom` | `java.util.Random`, `ThreadLocalRandom` for secrets |
| Go | `crypto/rand` | `math/rand` |
| PHP | `random_bytes`, `random_int` | `rand`, `mt_rand`, `uniqid` |
| Ruby | `SecureRandom.hex(32)` | `rand`, `Random.new` |
| C# | `RandomNumberGenerator.GetBytes` | `System.Random` |
| Swift | `SecRandomCopyBytes`, `SystemRandomNumberGenerator` | `srand`/`rand` |

Tokens: at least 128 bits of entropy (16 random bytes), single-use where they grant access, compared in constant time.

## Symmetric encryption done right

- AES-256-GCM or ChaCha20-Poly1305 via a high-level API (Python `cryptography` AESGCM / Fernet, libsodium `secretbox`, Go `crypto/cipher` GCM, Java `AES/GCM/NoPadding`, Node `createCipheriv('aes-256-gcm')`)
- 96-bit (12-byte) random nonce per message for GCM. Never reuse a nonce with the same key: GCM nonce reuse reveals the XOR of plaintexts and lets attackers forge tags
- Rotate the key before about 2^32 messages when nonces are random
- Store `nonce || ciphertext || tag`. Nonces are not secret
- Encrypt-then-MAC if you are stuck with CBC; better, move to GCM

## Keys

- Generate with the CSPRNG, never derive from a password without a KDF (argon2id, scrypt, HKDF for key material that is already random)
- Keep them in a KMS or secret manager; inject at runtime; never commit, log or put them in client bundles or mobile apps
- One key per purpose (encryption, signing, HMAC), with a version id so you can rotate

## TLS in client code (keep verification on)

```python
requests.get(url, verify="/etc/ssl/certs/internal-ca.pem", timeout=10)
```

```js
new https.Agent({ ca: fs.readFileSync("internal-ca.pem") })
```

```go
pool := x509.NewCertPool(); pool.AppendCertsFromPEM(caPEM)
tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
```

## JWT

- Verify with an explicit list: `jwt.decode(token, key, algorithms=["RS256"], audience="api", issuer="https://idp.example.test")`
- Never let the token header choose the key or algorithm (`alg`, `jku`, `x5u`, `kid` paths)
- Short `exp` (minutes for access tokens), refresh tokens stored server-side and revocable

## Hash format table (`--hash-id`)

| Looks like | Format | Fit for passwords? |
|---|---|---|
| 32 hex chars | MD5, NTLM, MD4, LM (same length, context decides) | No |
| 40 hex | SHA-1 (or RIPEMD-160) | No |
| 64 hex | SHA-256 (or SHA3-256, BLAKE2s) | No, unsalted and fast |
| 128 hex | SHA-512 (or SHA3-512, BLAKE2b, Whirlpool) | No |
| `*` + 40 hex | MySQL 4.1+ password hash | No |
| `$1$salt$...` | md5crypt | No (legacy) |
| `$apr1$...` | Apache md5crypt (htpasswd) | No (legacy) |
| `$5$` / `$6$` | sha256crypt / sha512crypt (default 5000 rounds) | Acceptable, prefer yescrypt/argon2id |
| `$y$` | yescrypt (current Linux default) | Yes |
| `$2a$`/`$2b$`/`$2y$` + cost | bcrypt | Yes, cost 10+ |
| `$argon2id$v=19$m=..,t=..,p=..` | argon2id | Yes, check params |
| `$scrypt$` or `$7$` | scrypt | Yes |
| `pbkdf2_sha256$iterations$...` | Django PBKDF2 | Yes at 600k+ iterations |
