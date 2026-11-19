# sast_lite rules, CWE ids and safe patterns

Each finding is a candidate. Confirm it by tracing whether data an attacker controls (request params, headers, files, queue messages) reaches the flagged call.

## CWE ids used

| CWE | Name |
|---|---|
| CWE-78 | OS Command Injection |
| CWE-79 | Cross-site Scripting |
| CWE-89 | SQL Injection |
| CWE-95 | Eval Injection |
| CWE-98 | PHP Remote File Inclusion (improper control of filename for include/require) |
| CWE-295 | Improper Certificate Validation |
| CWE-328 | Use of Weak Hash |
| CWE-338 | Use of Cryptographically Weak PRNG |
| CWE-347 | Improper Verification of Cryptographic Signature |
| CWE-377 | Insecure Temporary File |
| CWE-489 | Active Debug Code |
| CWE-502 | Deserialization of Untrusted Data |
| CWE-798 | Use of Hard-coded Credentials (secret_scan findings) |
| CWE-916 | Password Hash With Insufficient Computational Effort (MD5/SHA-1 used for passwords) |

## Python

| Rule | Flags | Safe pattern |
|---|---|---|
| PY-001 CWE-95 | `eval(`, `exec(` with a non-literal argument | `ast.literal_eval`, `json.loads`, dispatch dict |
| PY-002 CWE-78 | `shell=True`, `os.system`, `os.popen` | `subprocess.run(["prog", arg], check=True)` |
| PY-003 CWE-502 | `pickle.loads/load`, `marshal`, `dill` | JSON; HMAC-verify before loading if pickle is unavoidable |
| PY-004 CWE-502 | `yaml.load` without SafeLoader | `yaml.safe_load` |
| PY-005 CWE-89 | SQL in an f-string, `%` or `.format`, or `+` | `cur.execute("... = %s", (v,))` |
| PY-006 CWE-295 | `verify=False`, `CERT_NONE`, unverified context | `verify="/path/ca.pem"` |
| PY-007 CWE-489 | `debug=True`, `DEBUG = True` | `DEBUG = os.environ.get("DEBUG") == "1"` |
| PY-008 CWE-328 | `hashlib.md5/sha1` | `hashlib.sha256`; passwords: argon2, bcrypt, scrypt; checksums: `usedforsecurity=False` |
| PY-009 CWE-377 | `tempfile.mktemp` | `tempfile.mkstemp`, `NamedTemporaryFile` |
| PY-010 CWE-347 | `options={"verify_signature": False}`, `algorithms=[... "none"]` in PyJWT | `jwt.decode(t, key, algorithms=["RS256"], audience=..., issuer=...)` |
| PY-011 CWE-338 | `random.choice`/`randint`/... assigned to a token, OTP, salt, session or reset name | `secrets.token_urlsafe(32)`, `secrets.choice` |

## JavaScript and TypeScript

| Rule | Flags | Safe pattern |
|---|---|---|
| JS-001 CWE-95 | `eval(`, `new Function(`, string timers | `JSON.parse`, pass functions to timers |
| JS-002 CWE-78 | `exec`/`execSync` with a template or concatenation, `shell: true` | `execFile("prog", [arg])`, `spawn` without a shell |
| JS-003 CWE-79 | `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write` | `textContent`, DOMPurify for required HTML |
| JS-004 CWE-79 | `dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`, Angular `bypassSecurityTrust*` | Normal rendering, sanitize before the prop |
| JS-005 CWE-89 | SQL in a template literal or concatenation | `db.query("... = $1", [id])` |
| JS-006 CWE-328 | `createHash("md5"/"sha1")` | `createHash("sha256")`; passwords: bcrypt, argon2 |
| JS-007 CWE-295 | `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0` | `ca: fs.readFileSync("ca.pem")` |
| JS-008 CWE-347 | `algorithms: [... 'none']`, `ignoreExpiration: true` in jsonwebtoken or jose options | `jwt.verify(t, key, { algorithms: ["RS256"], audience, issuer })` |
| JS-009 CWE-338 | `Math.random()` assigned to a token, secret, OTP, salt or session name | `crypto.randomBytes(32)`, `crypto.randomUUID()`, `crypto.getRandomValues` |

## PHP

| Rule | Flags | Safe pattern |
|---|---|---|
| PHP-001 CWE-95 | `eval`, `assert` on strings, `create_function` | Lookup tables, real parsers |
| PHP-002 CWE-78 | `system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open`, backticks with variables | Avoid the shell; `escapeshellarg` per argument plus an allowlist |
| PHP-003 CWE-502 | `unserialize(` | `json_decode`; `['allowed_classes' => false]` |
| PHP-004 CWE-89 | SQL with `$_GET`/`$_POST` or concatenated variables | PDO prepared statements, `bindValue` |
| PHP-005 CWE-79 | `echo`/`print` of request data | `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` |
| PHP-006 CWE-328 | `md5(`, `sha1(` (CWE-916 when the input is a password) | `hash('sha256', ...)`, `password_hash()` |
| PHP-007 CWE-98 | `include`/`require` with request data | Fixed allowlist map from key to file |

## Go

| Rule | Flags | Safe pattern |
|---|---|---|
| GO-001 CWE-78 | `exec.Command("sh", "-c", ...)` | `exec.Command("prog", arg)` |
| GO-002 CWE-89 | `fmt.Sprintf` or `+` building SQL | `db.Query("... = ?", id)` |
| GO-003 CWE-295 | `InsecureSkipVerify: true` | Add the CA to `RootCAs` |
| GO-004 CWE-328 | `md5.New/Sum`, `sha1.New/Sum` | `crypto/sha256`; passwords: `x/crypto/bcrypt`, argon2 |
| GO-005 CWE-79 | `template.HTML/JS/URL(` with dynamic data | Plain strings in `html/template` |

## Known blind spots

- No data flow: a sink fed by a constant is still flagged, and a query built over several lines is missed
- Multi-line calls are seen one line at a time (a `Loader=SafeLoader` on the next line is not seen)
- Frameworks with their own escaping or ORMs are not modeled
- Weak-hash hits are often non-security checksums (cache keys, ETags); downgrade those after review
- For deeper coverage run a dataflow SAST tool (Semgrep, CodeQL, Bandit, gosec) and use this as the quick first pass
