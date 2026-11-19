#!/usr/bin/env python3
"""Check dependency names for typosquats, risky install scripts and dependency confusion.

Reads requirements*.txt, pyproject.toml ([project] dependencies), package.json
and package-lock.json. Compares names against an embedded list of popular PyPI
and npm packages, flags exact versions known to be malicious and install hooks
that match the Shai-Hulud worm. Offline: it never queries a registry.

Usage:
  typosquat_check.py requirements.txt package.json
  typosquat_check.py .                                  # finds the files in a dir
  typosquat_check.py package.json --internal-prefix acme --json
  typosquat_check.py requirements.txt --allow reqests-mock
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Optional, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

POPULAR_PYPI = """
requests urllib3 numpy pandas boto3 botocore setuptools six python-dateutil certifi idna charset-normalizer
pyyaml typing-extensions cryptography packaging pip wheel s3transfer jmespath attrs pydantic click jinja2
markupsafe pytest flask django fastapi uvicorn sqlalchemy psycopg2 psycopg2-binary pillow scipy matplotlib
scikit-learn tensorflow torch keras beautifulsoup4 lxml selenium aiohttp httpx redis celery gunicorn
werkzeug colorama tqdm rich openai anthropic transformers protobuf grpcio pyjwt paramiko pycryptodome
docutils toml tomli virtualenv black isort flake8 mypy coverage pymongo python-dotenv websockets pyopenssl
rsa pyasn1 cffi pycparser wrapt decorator filelock platformdirs zipp importlib-metadata jsonschema
tabulate xmltodict networkx sympy nltk opencv-python requests-oauthlib oauthlib azure-core
google-cloud-storage playwright langchain huggingface-hub
""".split()

POPULAR_NPM = """
react react-dom lodash express axios chalk commander debug moment request typescript webpack vue next
jquery underscore async uuid dotenv yargs minimist glob rimraf mkdirp semver fs-extra body-parser cors
jsonwebtoken bcrypt bcryptjs mongoose mysql mysql2 pg redis socket.io ws eslint prettier jest mocha chai
sinon nodemon cross-env dayjs date-fns classnames prop-types styled-components tailwindcss postcss
autoprefixer vite rollup esbuild inquirer ora node-fetch got colors bluebird rxjs zod graphql puppeteer
cheerio sharp multer helmet morgan passport nodemailer electron react-router react-router-dom redux
react-redux ethers web3 svelte nuxt event-stream ua-parser-js sass core-js tslib qs path-to-regexp js-yaml
""".split()

# Real, widely used packages that sit close to a popular name.
KNOWN_OK = {"pypi": {"boto", "pytest-cov", "requests-mock"},
            "npm": {"preact", "react-dnd", "color", "nest", "chalk-template"}}

AFFIX_PREFIXES = ("python-", "python3-", "py-", "node-", "js-", "npm-")
AFFIX_SUFFIXES = ("-python", "-py", "-js", ".js", "js", "-node", "-npm")

RISKY_SCRIPT = re.compile(r"(curl|wget|https?://|node\s+-e|base64|eval\(|\|\s*(ba)?sh\b|powershell|child_process)", re.I)
INSTALL_HOOKS = ("preinstall", "install", "postinstall")
# Shai-Hulud 2.0 (November 2025): preinstall ran `node setup_bun.js`, which installed Bun and ran bun_environment.js.
WORM_HOOK = re.compile(r"setup_bun\.js|bun_environment\.js", re.I)

# Versions published by attackers and pulled from the registry. Exact matches only; a range that could
# have resolved to one during the exposure window shows up in the lockfile, so scan package-lock.json too.
KNOWN_MALICIOUS = {
    "npm": {
        # 2025-09-08 maintainer phishing (chalk/debug), StepSecurity and Wiz lists
        "ansi-styles": {"6.2.2"}, "strip-ansi": {"7.1.1"}, "ansi-regex": {"6.2.1"}, "debug": {"4.4.2"},
        "color-convert": {"3.1.1"}, "color-name": {"2.0.1"}, "supports-color": {"10.2.1"}, "chalk": {"5.6.1"},
        "wrap-ansi": {"9.0.1"}, "slice-ansi": {"7.1.1"}, "color": {"5.0.1"}, "color-string": {"2.1.1"},
        "is-arrayish": {"0.3.3"}, "simple-swizzle": {"0.2.3"}, "supports-hyperlinks": {"4.1.1"}, "has-ansi": {"6.0.1"},
        "chalk-template": {"1.1.1"}, "backslash": {"0.2.1"},
        # 2025-09-15 Shai-Hulud worm start (OSV MAL-2025-47141)
        "@ctrl/tinycolor": {"4.1.1", "4.1.2"},
    },
    "pypi": {
        # 2024-12 release pipeline compromise (PyPI blog 2024-12-11)
        "ultralytics": {"8.3.41", "8.3.42", "8.3.45", "8.3.46"},
    },
}
EXACT_NPM = re.compile(r"^\s*=?v?(\d+\.\d+\.\d+\S*)\s*$")
PIN_PY = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([0-9][^\s;#,\]\"']*)")


def finding(fid: str, severity: str, title: str, detail: str, fix: str, location: str = "") -> Dict[str, str]:
    f = {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}
    if location:
        f["location"] = location
    return f


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def osa_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein distance (optimal string alignment: adjacent swaps count as 1)."""
    if a == b:
        return 0
    prev2: List[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


# --------------------------------------------------------------------------- parsing

Dep = Tuple[str, str, int]  # (name, ecosystem, line)


def parse_requirements(text: str) -> Tuple[List[Dep], List[Tuple[str, int]]]:
    deps: List[Dep] = []
    options: List[Tuple[str, int]] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            options.append((line, n))
            continue
        if re.match(r"^(git\+|https?://|file:|\.|/)", line) or "@ " in line and "://" in line:
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*@", line)
            if m:
                deps.append((m.group(1), "pypi", n))
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if m:
            deps.append((m.group(1), "pypi", n))
    return deps, options


def parse_pyproject(text: str) -> List[Dep]:
    deps: List[Dep] = []
    lines = text.splitlines()
    section, in_list = "", False
    for n, raw in enumerate(lines, 1):
        line = raw.strip()
        if line.startswith("[") and not in_list:
            section = line.strip("[]").strip()
            continue
        if section == "project" and re.match(r"^dependencies\s*=\s*\[", line):
            in_list = True
            line = line.split("[", 1)[1]
        elif section == "project.optional-dependencies" and re.match(r"^[\w-]+\s*=\s*\[", line):
            in_list = True
            line = line.split("[", 1)[1]
        if in_list:
            for spec in re.findall(r"[\"']([^\"']+)[\"']", line):
                m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", spec)
                if m:
                    deps.append((m.group(1), "pypi", n))
            if "]" in line:
                in_list = False
    return deps


def _json_line(text: str, needle: str) -> int:
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 0


def parse_package_json(text: str) -> Tuple[List[Dep], Dict[str, Tuple[str, int]]]:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("package.json is not a JSON object")
    deps: List[Dep] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        block = data.get(section)
        if isinstance(block, dict):
            for name in block:
                deps.append((name, "npm", _json_line(text, f'"{name}"')))
    scripts = {}
    if isinstance(data.get("scripts"), dict):
        for hook, cmd in data["scripts"].items():
            scripts[hook] = (str(cmd), _json_line(text, f'"{hook}"'))
    return deps, scripts


# --------------------------------------------------------------------------- checks

def check_name(name: str, eco: str, allow: set) -> Optional[Dict[str, str]]:
    popular = POPULAR_PYPI if eco == "pypi" else POPULAR_NPM
    if name.startswith("@"):
        return None  # scoped npm package: different risk, see dependency confusion
    norm = pep503(name) if eco == "pypi" else name.lower()
    pop_norm = {pep503(p) if eco == "pypi" else p: p for p in popular}
    if norm in pop_norm or norm in KNOWN_OK[eco] or name in allow or norm in allow:
        return None
    if any(ord(ch) > 127 for ch in name):
        return finding("TYPO-003", "high", f"Non-ASCII package name: {name}",
                       "Look-alike Unicode characters are a classic way to imitate a real package.",
                       "Replace it with the intended ASCII name and check the lockfile.")
    if eco == "npm":
        squashed = re.sub(r"[-_.]", "", norm)
        for p in popular:
            if re.sub(r"[-_.]", "", p) == squashed:
                return finding("TYPO-001", "high", f"{name} looks like {p} (separator swap)",
                               f"On npm '{name}' and '{p}' are different packages; swapping -, _ or . is a common typosquat trick.",
                               f"Use '{p}' if that was intended, and check what '{name}' is before installing it.")
    best, best_d = None, 99
    for p_norm, p in pop_norm.items():
        if abs(len(p_norm) - len(norm)) > 2:
            continue
        d = osa_distance(norm, p_norm)
        if d < best_d:
            best, best_d = p, d
    if best_d == 1 and len(norm) >= 4:
        return finding("TYPO-001", "high", f"{name} is one edit away from {best}",
                       f"A single added, missing, swapped or repeated character separates '{name}' from the popular '{best}'.",
                       f"If you meant '{best}', fix the name. If '{name}' is intended, confirm the publisher and add it with --allow.")
    if best_d == 2 and len(norm) >= 7:
        return finding("TYPO-001", "medium", f"{name} is two edits away from {best}",
                       f"'{name}' is close to the popular '{best}'.",
                       f"Check that '{name}' is the package you meant; otherwise switch to '{best}'.")
    for pre in AFFIX_PREFIXES:
        if norm.startswith(pre) and norm[len(pre):] in pop_norm:
            base = pop_norm[norm[len(pre):]]
            return finding("TYPO-002", "medium", f"{name} wraps the popular name {base}",
                           f"'{name}' is '{base}' with a '{pre}' prefix, a common pattern for impostor packages.",
                           f"Check the publisher and repository of '{name}', or use '{base}' directly.")
    for suf in AFFIX_SUFFIXES:
        if norm.endswith(suf) and norm[:-len(suf)] in pop_norm:
            base = pop_norm[norm[:-len(suf)]]
            return finding("TYPO-002", "medium", f"{name} wraps the popular name {base}",
                           f"'{name}' is '{base}' with a '{suf}' suffix, a common pattern for impostor packages.",
                           f"Check the publisher and repository of '{name}', or use '{base}' directly.")
    return None


def _internal(name: str, prefixes: List[str]) -> bool:
    n = name.lower()
    return any(n == p or n.startswith((p + "-", p + "_", p + ".")) for p in prefixes)


def _malicious(name: str, version: str, eco: str, location: str) -> Optional[Dict[str, str]]:
    key = name.lower() if eco == "npm" else pep503(name)
    bad = KNOWN_MALICIOUS[eco].get(key)
    if not bad or version not in bad:
        return None
    return finding("TYPO-012", "critical", f"Known malicious release: {name}@{version}",
                   "This exact version was published by an attacker and later removed from the registry. Anything that installed it ran the payload.",
                   "Pin a clean version, delete node_modules or the virtualenv and the package cache, and rotate every token and key the machine or CI runner could read.",
                   location)


def pinned_versions(base: str, text: str) -> List[Tuple[str, str, str, int]]:
    """(name, version, eco, line) for exact pins in manifests and every entry of an npm lockfile."""
    out: List[Tuple[str, str, str, int]] = []
    if base in ("package-lock.json", "npm-shrinkwrap.json"):
        data = json.loads(text)
        pkgs = data.get("packages") if isinstance(data, dict) else None
        if isinstance(pkgs, dict):
            for key, meta in pkgs.items():
                if key and isinstance(meta, dict) and isinstance(meta.get("version"), str):
                    name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
                    out.append((name, meta["version"], "npm", _json_line(text, f'"{key}"')))
        return out
    if base.endswith(".json"):
        data = json.loads(text)
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "overrides"):
            block = data.get(section) if isinstance(data, dict) else None
            if isinstance(block, dict):
                for name, spec in block.items():
                    m = EXACT_NPM.match(str(spec))
                    if m:
                        out.append((name, m.group(1), "npm", _json_line(text, f'"{name}"')))
        return out
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip().strip(",").strip("\"'")
        m = PIN_PY.match(line)
        if m:
            out.append((m.group(1), m.group(2), "pypi", n))
    return out


def check_lockfile(path: str, text: str) -> Tuple[List[Dict[str, str]], int]:
    pins = pinned_versions(os.path.basename(path).lower(), text)
    out = [f for f in (_malicious(n, v, e, f"{path}:{l}") for n, v, e, l in pins) if f]
    return out, len(pins)


def check_file(path: str, text: str, allow: set, prefixes: List[str]) -> Tuple[List[Dict[str, str]], int]:
    base = os.path.basename(path).lower()
    if base in ("package-lock.json", "npm-shrinkwrap.json"):
        return check_lockfile(path, text)
    out: List[Dict[str, str]] = []
    scripts: Dict[str, Tuple[str, int]] = {}
    options: List[Tuple[str, int]] = []
    if base.endswith(".json"):
        deps, scripts = parse_package_json(text)
    elif base == "pyproject.toml":
        deps = parse_pyproject(text)
    else:
        deps, options = parse_requirements(text)

    extra_index = [(o, n) for o, n in options if o.startswith("--extra-index-url")]
    for opt, n in extra_index:
        out.append(finding("TYPO-021", "medium", "--extra-index-url mixes package indexes",
                           "pip treats every index as equal and installs the highest version it finds, so a public package with an internal name wins.",
                           "Use a single index (a proxy such as Artifactory, Nexus or devpi that serves internal names first), and pin with --require-hashes.",
                           f"{path}:{n}"))
    for name, eco, line in deps:
        f = check_name(name, eco, allow)
        if f:
            f["location"] = f"{path}:{line}"
            out.append(f)
        if prefixes:
            pkg = name.split("/", 1)[1] if name.startswith("@") else name
            if eco == "npm" and not name.startswith("@") and _internal(pkg, prefixes):
                out.append(finding("TYPO-020", "high", f"Internal-looking npm package is not scoped: {name}",
                                   "If this name is not registered on the public registry, anyone can publish it there and builds may pull theirs (dependency confusion).",
                                   f"Move it under your org scope (@{prefixes[0]}/{re.sub('^' + re.escape(prefixes[0]) + '[-_.]?', '', pkg) or pkg}) with the scope bound to your registry in .npmrc, or register the public name as a placeholder.",
                                   f"{path}:{line}"))
            elif eco == "pypi" and _internal(name, prefixes):
                sev = "high" if extra_index else "medium"
                out.append(finding("TYPO-020", sev, f"Internal-looking PyPI package: {name}",
                                   "PyPI has no namespaces. If the same name appears on pypi.org, a mixed-index install can take it" +
                                   (", and this file uses --extra-index-url." if extra_index else "."),
                                   "Install from a single trusted index, pin versions with hashes, and register the name on PyPI as a placeholder.",
                                   f"{path}:{line}"))
    for name, version, eco, line in pinned_versions(base, text):
        f = _malicious(name, version, eco, f"{path}:{line}")
        if f:
            out.append(f)
    for hook in INSTALL_HOOKS:
        if hook in scripts:
            cmd, line = scripts[hook]
            if WORM_HOOK.search(cmd):
                out.append(finding("TYPO-011", "critical", f"npm {hook} matches the Shai-Hulud 2.0 worm",
                                   f"'{cmd[:120]}' runs setup_bun.js or bun_environment.js, the loader the November 2025 worm added to infected packages. It steals npm, GitHub and cloud credentials and republishes itself.",
                                   "Do not install. If it already ran: remove the package, look for a self-hosted runner named SHA1HULUD and a .github/workflows/discussion.yaml, rotate all credentials on that machine.",
                                   f"{path}:{line}"))
            risky = bool(RISKY_SCRIPT.search(cmd))
            out.append(finding("TYPO-010", "high" if risky else "medium", f"npm {hook} script",
                               f"'{cmd[:120]}' runs automatically on npm install" +
                               (", and it downloads or evaluates code." if risky else ". Install hooks are the most common way malicious packages run code."),
                               "Move setup into an explicit script (npm run setup). In CI install with npm ci --ignore-scripts and allow-list the packages that need build steps.",
                               f"{path}:{line}"))
    return out, len(deps)


def collect(paths: List[str]) -> List[str]:
    files = []
    for p in paths:
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                low = name.lower()
                if low in ("package.json", "package-lock.json", "npm-shrinkwrap.json", "pyproject.toml") or \
                        re.match(r"^requirements.*\.(txt|in)$", low):
                    files.append(os.path.join(p, name))
        else:
            files.append(p)
    return files


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Check dependency names for typosquats, install scripts and dependency confusion (offline).")
    ap.add_argument("paths", nargs="+", help="requirements*.txt, pyproject.toml, package.json, package-lock.json, or a directory")
    ap.add_argument("--internal-prefix", action="append", default=[], metavar="PREFIX",
                    help="name prefix of your private packages (repeatable), e.g. acme")
    ap.add_argument("--allow", action="append", default=[], metavar="NAME", help="package name you have verified (repeatable)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)

    allow = {a.lower() for a in args.allow} | {pep503(a) for a in args.allow}
    prefixes = [p.lower().lstrip("@").rstrip("-_./") for p in args.internal_prefix]
    findings: List[Dict[str, str]] = []
    total, files = 0, collect(args.paths)
    if not files:
        print("error: no requirements*.txt, pyproject.toml, package.json or package-lock.json found", file=sys.stderr)
        return 2
    try:
        for path in files:
            with open(path, encoding="utf-8") as fh:
                got, count = check_file(path, fh.read(), allow, prefixes)
            findings += got
            total += count
    except (OSError, ValueError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    findings.sort(key=lambda f: (-SEVERITY_ORDER.index(f["severity"]), f.get("location", "")))

    if args.json:
        print(json.dumps({"files": files, "dependencies": total, "count": len(findings), "findings": findings}, indent=2))
    else:
        print(f"Dependency check: {len(files)} file(s), {total} dependencies, {len(findings)} finding(s)\n")
        if not findings:
            print("No issues found.")
        for f in findings:
            print(f"[{f['severity'].upper():8}] {f['id']}  {f['title']}\n           at {f.get('location', '?')}\n"
                  f"           {f['detail']}\n           fix: {f['fix']}")
    if args.fail_on != "never":
        t = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= t for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
