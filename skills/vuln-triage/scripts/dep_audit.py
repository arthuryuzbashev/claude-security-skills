#!/usr/bin/env python3
"""Audit Python and npm dependencies for known vulnerabilities and loose pins, then rank what to fix.

Reads requirements.txt, Pipfile.lock, poetry.lock, package.json and
package-lock.json (v1, v2, v3). Offline it flags unpinned and non-registry
dependencies and matches against OSV records you already have (--osv-results).
With --online it asks the OSV.dev batch API (one POST, then one GET per vuln id).

Usage:
  dep_audit.py requirements.txt package-lock.json
  dep_audit.py requirements.txt --osv-results osv.json --prioritize
  dep_audit.py . --online --kev known_exploited_vulnerabilities.json --epss epss_scores-current.csv
  dep_audit.py package-lock.json --online --json --fail-on critical
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Dict, Iterable, List, Optional, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cvss_calc import score_vector  # noqa: E402  (sibling script in the same skill)
from ssvc_decide import load_epss, load_kev_catalog  # noqa: E402

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
KNOWN_FILES = ("requirements.txt", "Pipfile.lock", "poetry.lock", "package-lock.json", "package.json")
GHSA_SEVERITY = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium", "low": "low"}


def finding(fid: str, severity: str, title: str, detail: str, fix: str, location: Optional[str] = None, **extra) -> Dict[str, object]:
    f: Dict[str, object] = {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}
    if location:
        f["location"] = location
    f.update(extra)
    return f


def dep(name: str, version: Optional[str], ecosystem: str, source: str, spec: str = "", dev: bool = False) -> Dict[str, object]:
    return {"name": name, "version": version, "ecosystem": ecosystem, "source": source, "spec": spec, "dev": dev}


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------- parsers

def parse_requirements(text: str, source: str = "requirements.txt") -> Tuple[List[Dict[str, object]], List[Dict[str, object]]]:
    deps, findings = [], []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #")[0].strip()
        if not line or line.startswith("#"):
            continue
        loc = f"{source}:{n}"
        if line.startswith(("-r", "-c", "--requirement", "--constraint", "--index-url", "-i", "--extra-index-url",
                            "--find-links", "-f", "--hash", "--trusted-host", "--pre", "--no-binary", "--only-binary")):
            continue
        line = line.split(" --hash")[0].strip().rstrip("\\").strip()
        url_like = re.search(r"(git\+|hg\+|svn\+|bzr\+|https?://|file:)", line)
        if line.startswith(("-e", "--editable")) or url_like:
            egg = re.search(r"#egg=([A-Za-z0-9_.-]+)", line)
            named = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*@", line)
            name = egg.group(1) if egg else named.group(1) if named else re.sub(r"^(-e|--editable)\s+", "", line)[:60]
            findings.append(finding("DEP-011", "low", f"{name} installed from a URL or VCS",
                                    "No registry version, so no vulnerability data and no integrity pin unless you add a hash.",
                                    "Publish to a registry or pin an exact commit and add --hash.", loc))
            continue
        line = line.split(";")[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$", line)
        if not m:
            continue
        name, spec = m.group(1), m.group(3).replace(" ", "")
        pin = re.match(r"^===?([A-Za-z0-9._+!-]+)$", spec)
        if pin and "*" not in pin.group(1):
            deps.append(dep(pep503(name), pin.group(1), "PyPI", loc, spec))
        else:
            deps.append(dep(pep503(name), None, "PyPI", loc, spec))
            sev, why = ("medium", "no version at all, so every install can pull a different release") if not spec \
                else ("low", f"'{spec}' allows several versions, so builds are not reproducible and a bad release slips in")
            findings.append(finding("DEP-010" if spec else "DEP-012", sev, f"{name} is not pinned",
                                    f"{name}{spec}: {why}.", "Pin with == in a lock or constraints file (pip-compile, uv, poetry).", loc))
    return deps, findings


def parse_pipfile_lock(data: dict, source: str = "Pipfile.lock") -> List[Dict[str, object]]:
    deps = []
    for section, dev in (("default", False), ("develop", True)):
        for name, info in (data.get(section) or {}).items():
            ver = str(info.get("version", "")).lstrip("=") if isinstance(info, dict) else ""
            deps.append(dep(pep503(name), ver or None, "PyPI", f"{source}:{name}", dev=dev))
    return deps


def parse_poetry_lock(text: str, source: str = "poetry.lock") -> List[Dict[str, object]]:
    deps = []
    for block in re.split(r"^\[\[package\]\]\s*$", text, flags=re.M)[1:]:
        name = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
        ver = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
        cat = re.search(r'^category\s*=\s*"([^"]+)"', block, re.M)
        if name and ver:
            deps.append(dep(pep503(name.group(1)), ver.group(1), "PyPI", f"{source}:{name.group(1)}",
                            dev=bool(cat and cat.group(1) == "dev")))
    return deps


def parse_package_lock(data: dict, source: str = "package-lock.json") -> List[Dict[str, object]]:
    deps: List[Dict[str, object]] = []
    seen: Set[Tuple[str, str]] = set()
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2 and 3
        for path, info in packages.items():
            if not path or not isinstance(info, dict) or info.get("link"):
                continue
            name = info.get("name") or path.rsplit("node_modules/", 1)[-1]
            ver = info.get("version")
            if ver and (name, ver) not in seen:
                seen.add((name, ver))
                deps.append(dep(name, ver, "npm", f"{source}:{path}", dev=bool(info.get("dev"))))
        return deps

    def walk(tree: dict, prefix: str) -> None:  # lockfileVersion 1
        for name, info in (tree or {}).items():
            ver = info.get("version") if isinstance(info, dict) else None
            if ver and (name, ver) not in seen and not str(ver).startswith(("file:", "git", "http")):
                seen.add((name, ver))
                deps.append(dep(name, ver, "npm", f"{source}:{prefix}{name}", dev=bool(info.get("dev"))))
            if isinstance(info, dict):
                walk(info.get("dependencies", {}), f"{prefix}{name}>")
    walk(data.get("dependencies", {}), "")
    return deps


def parse_package_json(data: dict, source: str = "package.json") -> Tuple[List[Dict[str, object]], List[Dict[str, object]]]:
    deps, findings = [], []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec).strip()
            loc = f"{source}:{section}.{name}"
            dev = section == "devDependencies"
            if re.match(r"^(git(\+\w+)?:|git@|github:|gitlab:|bitbucket:|https?://|[\w.-]+/[\w.-]+(#.*)?$)", spec):
                findings.append(finding("DEP-011", "low", f"{name} installed from a URL or git",
                                        f"'{spec}' bypasses the registry, so there is no advisory data for it.",
                                        "Use a published version, or pin a full commit hash.", loc))
                continue
            if spec.startswith(("file:", "link:", "workspace:", "npm:")):
                continue
            if re.match(r"^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$", spec):
                deps.append(dep(name, spec.lstrip("v"), "npm", loc, spec, dev))
                continue
            deps.append(dep(name, None, "npm", loc, spec, dev))
            if spec in ("", "*", "latest", "x", "next"):
                findings.append(finding("DEP-012", "medium", f"{name} accepts any version ('{spec or 'empty'}')",
                                        "Any new release, including a hijacked one, installs on the next build.",
                                        "Use a caret range at most, and commit package-lock.json.", loc))
            else:
                findings.append(finding("DEP-010", "info" if source_has_lock(source) else "low", f"{name} uses a range ('{spec}')",
                                        "Normal for package.json; the lockfile is what pins the real version.",
                                        "Commit package-lock.json and install with npm ci.", loc))
    return deps, findings


def source_has_lock(source: str) -> bool:
    """True when a package-lock.json sits next to this package.json (then ranges are expected)."""
    folder = os.path.dirname(os.path.abspath(source.split(":")[0]))
    return os.path.isfile(os.path.join(folder, "package-lock.json"))


def dedupe(deps: List[Dict[str, object]]) -> List[Dict[str, object]]:
    """Keep one entry per (ecosystem, name, version). Lockfiles load first, so their location wins."""
    seen: Set[Tuple[str, str, str]] = set()
    out = []
    for d in deps:
        key = (str(d["ecosystem"]), str(d["name"]), str(d["version"]))
        if d["version"] and key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out


def load_manifest(path: str) -> Tuple[List[Dict[str, object]], List[Dict[str, object]]]:
    base = os.path.basename(path)
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    if base.endswith(".json"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as err:
            raise ValueError(f"{path}: not valid JSON ({err})")
        if base == "Pipfile.lock" or ("_meta" in data and "default" in data):
            return parse_pipfile_lock(data, path), []
        if "lockfileVersion" in data:
            return parse_package_lock(data, path), []
        return parse_package_json(data, path)
    if base == "Pipfile.lock":
        return parse_pipfile_lock(json.loads(text), path), []
    if base.endswith(".lock") and "[[package]]" in text:
        return parse_poetry_lock(text, path), []
    return parse_requirements(text, path)


def expand_paths(paths: Iterable[str]) -> List[str]:
    out = []
    for p in paths:
        if os.path.isdir(p):
            for name in KNOWN_FILES:
                if os.path.isfile(os.path.join(p, name)):
                    out.append(os.path.join(p, name))
        else:
            out.append(p)
    return out


# ---------------------------------------------------------------- versions and OSV matching

def version_key(v: str):
    """Approximate ordering for PEP 440 and semver strings. Good enough to place a version against OSV ranges."""
    v = v.strip().lower().lstrip("v").split("+")[0]
    m = re.match(r"^(\d+(?:\.\d+)*)(.*)$", v)
    if not m:
        return ((0,), 0, [(1, 0, v)])
    nums = [int(x) for x in m.group(1).split(".")]
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    rest = m.group(2).lstrip(".-_")
    if not rest:
        return (tuple(nums), 1, [])
    rest = re.sub(r"^(post|rev|r)(?=\d|$)", "post", rest)
    phase = 2 if rest.startswith("post") else 0
    rest = re.sub(r"^(a)(?=\d|$)", "alpha", rest)
    rest = re.sub(r"^(b)(?=\d|$)", "beta", rest)
    rest = re.sub(r"^(c|pre|preview)(?=\d|$)", "rc", rest)
    rest = re.sub(r"^dev", "0dev", rest)
    parts = []
    for tok in re.findall(r"\d+|[a-z]+", rest):
        parts.append((0, int(tok), "") if tok.isdigit() else (1, 0, tok))
    return (tuple(nums), phase, parts)


def _event_version(ev: dict) -> str:
    return next(iter(ev.values()))


def in_ranges(version: str, ranges: List[dict]) -> bool:
    vk = version_key(version)
    for rng in ranges:
        if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        events = [e for e in rng.get("events", []) if isinstance(e, dict) and e]
        events.sort(key=lambda e: ((), 0, []) if e.get("introduced") == "0" else version_key(str(_event_version(e))))
        affected = False
        for ev in events:
            if "introduced" in ev:
                if ev["introduced"] == "0" or vk >= version_key(ev["introduced"]):
                    affected = True
            elif "fixed" in ev:
                if vk >= version_key(ev["fixed"]):
                    affected = False
            elif "last_affected" in ev:
                if vk > version_key(ev["last_affected"]):
                    affected = False
        if affected:
            return True
    return False


def affected_entries(vuln: dict, d: Dict[str, object]) -> List[dict]:
    out = []
    for aff in vuln.get("affected", []) or []:
        pkg = aff.get("package") or {}
        eco = str(pkg.get("ecosystem", ""))
        name = str(pkg.get("name", ""))
        if eco.split(":")[0] != d["ecosystem"]:
            continue
        if (pep503(name) if eco.startswith("PyPI") else name) == d["name"]:
            out.append(aff)
    return out


def is_affected(vuln: dict, d: Dict[str, object]) -> bool:
    version = d.get("version")
    if not version:
        return False
    for aff in affected_entries(vuln, d):
        if str(version) in [str(x) for x in aff.get("versions", []) or []]:
            return True
        if in_ranges(str(version), aff.get("ranges", []) or []):
            return True
    return False


def fixed_versions(vuln: dict, d: Dict[str, object]) -> List[str]:
    fixes = set()
    for aff in affected_entries(vuln, d):
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if "fixed" in ev:
                    fixes.add(str(ev["fixed"]))
    current = version_key(str(d.get("version") or "0"))
    later = sorted((f for f in fixes if version_key(f) > current), key=version_key)
    return later


def vuln_severity(vuln: dict) -> Tuple[str, Optional[float]]:
    """Severity from a CVSS v3 or v4 vector when present (highest wins), else the advisory's label, else 'medium'."""
    best: Optional[float] = None
    entries = list(vuln.get("severity", []) or [])
    for aff in vuln.get("affected", []) or []:
        entries += aff.get("severity", []) or []
    for s in entries:
        kind = str(s.get("type", ""))
        if kind.startswith(("CVSS_V3", "CVSS_V4")):
            try:
                scored = score_vector(str(s.get("score", "")))
                val = float(scored["base_score" if kind.startswith("CVSS_V3") else "score"])  # type: ignore[arg-type]
            except (ValueError, KeyError):
                continue
            best = val if best is None else max(best, val)
    if best is not None:
        if best == 0:
            return "info", best
        return ("critical" if best >= 9 else "high" if best >= 7 else "medium" if best >= 4 else "low"), best
    label = str((vuln.get("database_specific") or {}).get("severity", "")).lower()
    if label in GHSA_SEVERITY:
        return GHSA_SEVERITY[label], None
    return "medium", None


def is_kev(vuln: dict, kev_ids: Set[str]) -> bool:
    ids = {str(vuln.get("id", "")).upper()} | {str(a).upper() for a in vuln.get("aliases", []) or []}
    if ids & kev_ids:
        return True
    db = vuln.get("database_specific") or {}
    return bool(vuln.get("kev") or db.get("kev") or db.get("cisa_kev") or db.get("known_exploited"))


def collect_vulns(data) -> List[dict]:
    """Find OSV vulnerability objects anywhere in a JSON document (OSV API, osv-scanner output, plain list)."""
    found: Dict[str, dict] = {}

    def walk(node) -> None:
        if isinstance(node, dict):
            if "id" in node and ("affected" in node or "aliases" in node or "summary" in node):
                found.setdefault(str(node["id"]), node)
                return
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    walk(data)
    return list(found.values())


def load_kev(path: str) -> Set[str]:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    try:
        data = json.loads(text)
        items = data.get("vulnerabilities", data) if isinstance(data, dict) else data
        return {str(i.get("cveID") or i.get("cve") or i.get("id")).upper() if isinstance(i, dict) else str(i).upper()
                for i in items}
    except json.JSONDecodeError:
        return {m.upper() for m in re.findall(r"CVE-\d{4}-\d{4,}", text, re.I)}


def osv_online(deps: List[Dict[str, object]], timeout: float, max_vulns: int) -> Dict[int, List[dict]]:
    """Query OSV.dev. Returns {dep index: [full vuln objects]}."""
    queryable = [(i, d) for i, d in enumerate(deps) if d.get("version")]
    by_dep: Dict[int, List[str]] = {}
    for start in range(0, len(queryable), 1000):
        chunk = queryable[start:start + 1000]
        body = json.dumps({"queries": [{"package": {"name": d["name"], "ecosystem": d["ecosystem"]},
                                        "version": d["version"]} for _, d in chunk]}).encode()
        req = urllib.request.Request(OSV_BATCH, data=body, headers={"Content-Type": "application/json",
                                                                    "User-Agent": "claude-security-skills-dep-audit/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            results = json.load(resp).get("results", [])
        for (i, _), res in zip(chunk, results):
            ids = [v["id"] for v in (res or {}).get("vulns", []) or []]
            if ids:
                by_dep[i] = ids
    cache: Dict[str, dict] = {}
    for vid in sorted({v for ids in by_dep.values() for v in ids})[:max_vulns]:
        with urllib.request.urlopen(OSV_VULN + vid, timeout=timeout) as resp:
            cache[vid] = json.load(resp)
    return {i: [cache[v] for v in ids if v in cache] for i, ids in by_dep.items()}


# ---------------------------------------------------------------- findings and priority

def priority(sev: str, kev: bool) -> str:
    if kev or sev == "critical":
        return "P1"
    return {"high": "P2", "medium": "P3"}.get(sev, "P4")


def vuln_findings(deps: List[Dict[str, object]], matches: Dict[int, List[dict]], kev_ids: Set[str],
                  kev_info: Optional[Dict[str, dict]] = None,
                  epss: Optional[Dict[str, Dict[str, float]]] = None) -> List[Dict[str, object]]:
    out = []
    kev_info = kev_info or {}
    epss = epss or {}
    for i, vulns in matches.items():
        d = deps[i]
        seen: Set[str] = set()
        # GHSA, PYSEC and CVE records often describe the same bug; keep the best-rated one per alias group
        for v in sorted(vulns, key=lambda x: (vuln_severity(x)[1] is None, str(x.get("id")))):
            names = {str(v.get("id"))} | {str(a) for a in v.get("aliases", []) or []}
            if names & seen:
                continue
            seen |= names
            sev, cvss = vuln_severity(v)
            kev = is_kev(v, kev_ids)
            fixes = fixed_versions(v, d)
            aliases = [a for a in v.get("aliases", []) or []]
            cves = [a for a in [v.get("id")] + aliases if str(a).startswith("CVE-")]
            summary = (v.get("summary") or v.get("details") or "").strip().splitlines()
            detail = (summary[0][:200] if summary else "No summary in the advisory.")
            extra: Dict[str, object] = {}
            if kev:
                detail += " Listed as known exploited (KEV)."
                entry = next((kev_info[c.upper()] for c in cves if c.upper() in kev_info), {})
                if entry.get("dueDate"):
                    extra["kev_due_date"] = entry["dueDate"]
                if entry.get("knownRansomwareCampaignUse"):
                    extra["kev_ransomware"] = entry["knownRansomwareCampaignUse"]
                    if entry["knownRansomwareCampaignUse"] == "Known":
                        detail += " Used in ransomware campaigns."
            scores = [epss[c.upper()] for c in cves if c.upper() in epss]
            if scores:
                best = max(scores, key=lambda e: e["epss"])
                extra["epss"], extra["epss_percentile"] = best["epss"], best["percentile"]
            fix = f"Upgrade {d['name']} to {fixes[0]} or later." if fixes else \
                "No fixed version listed. Check the advisory for a workaround, or replace the package."
            out.append(finding("DEP-001", sev, f"{d['name']} {d['version']}: {v.get('id')}", detail, fix,
                               str(d["source"]), package=d["name"], version=d["version"], ecosystem=d["ecosystem"],
                               vuln_id=v.get("id"), aliases=aliases, cves=cves, cvss=cvss, fixed=fixes, kev=kev,
                               dev=d.get("dev", False), priority=priority(sev, kev), **extra))
    return out


def offline_matches(deps: List[Dict[str, object]], vulns: List[dict]) -> Dict[int, List[dict]]:
    out: Dict[int, List[dict]] = {}
    for i, d in enumerate(deps):
        hits = [v for v in vulns if is_affected(v, d)]
        if hits:
            out[i] = hits
    return out


def sort_findings(findings: List[Dict[str, object]]) -> List[Dict[str, object]]:
    return sorted(findings, key=lambda f: (str(f.get("priority", "P9")), not f.get("kev", False),
                                           -SEVERITY_ORDER.index(str(f["severity"])), -float(f.get("epss") or 0),
                                           -(f.get("cvss") or 0),
                                           bool(f.get("dev")), str(f.get("location", ""))))


def upgrade_plan(findings: List[Dict[str, object]]) -> List[Dict[str, object]]:
    """One line per vulnerable package: the lowest version that fixes every listed advisory."""
    plan: Dict[Tuple[str, str, str], Dict[str, object]] = {}
    for f in findings:
        if f["id"] != "DEP-001":
            continue
        key = (str(f["ecosystem"]), str(f["package"]), str(f["version"]))
        p = plan.setdefault(key, {"ecosystem": key[0], "package": key[1], "version": key[2], "fixes": 0,
                                  "target": None, "unfixed": [], "top": f["priority"]})
        p["fixes"] = int(p["fixes"]) + 1  # type: ignore[call-overload]
        p["top"] = min(str(p["top"]), str(f["priority"]))
        if f["fixed"]:
            first = f["fixed"][0]  # type: ignore[index]
            if p["target"] is None or version_key(first) > version_key(str(p["target"])):
                p["target"] = first
        else:
            p["unfixed"].append(f["vuln_id"])  # type: ignore[union-attr]
    return sorted(plan.values(), key=lambda p: (str(p["top"]), -int(p["fixes"]), str(p["package"])))  # type: ignore[call-overload]


def render_text(deps, findings, plan, prioritize: bool, mode: str) -> str:
    vulns = [f for f in findings if f["id"] == "DEP-001"]
    lines = [f"Dependency audit ({mode}): {len(deps)} dependencies, {len(vulns)} known vulnerabilities, "
             f"{len(findings) - len(vulns)} pinning issue(s)"]
    if prioritize:
        lines += ["", f"{'PRI':4} {'SEV':8} {'KEV':4} {'CVSS':5} {'PACKAGE':28} {'VULN':22} FIX       EPSS"]
        for f in vulns:
            fix = f"{f['fixed'][0]}" if f["fixed"] else "none"
            ep = f"{float(f['epss']):.3f}" if f.get("epss") is not None else "-"
            lines.append(f"{f['priority']:4} {str(f['severity']):8} {'yes' if f['kev'] else '':4} "
                         f"{(str(f['cvss']) if f['cvss'] is not None else '-'):5} "
                         f"{(str(f['package']) + ' ' + str(f['version']))[:28]:28} {str(f['vuln_id'])[:22]:22} {fix:9} {ep}")
        if plan:
            lines += ["", "Upgrade plan:"]
            for p in plan:
                tgt = p["target"] or "no fix listed"
                extra = f" (still open: {', '.join(p['unfixed'])})" if p["unfixed"] and p["target"] else ""
                lines.append(f"  {p['top']} {p['package']} {p['version']} -> {tgt}  fixes {p['fixes']}{extra}")
        return "\n".join(lines)
    lines.append("")
    if not findings:
        lines.append("No issues found.")
    for f in findings:
        tag = f" [{f['priority']}{' KEV' if f.get('kev') else ''}]" if f["id"] == "DEP-001" else ""
        lines.append(f"[{str(f['severity']).upper():8}] {f['id']}{tag}  {f['title']}")
        lines.append(f"           {f['detail']}")
        lines.append(f"           fix: {f['fix']}  ({f.get('location', '')})")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Audit pip/npm dependencies against OSV and rank fixes.")
    ap.add_argument("paths", nargs="+", help="manifest/lock files or directories (requirements.txt, Pipfile.lock, poetry.lock, package.json, package-lock.json)")
    ap.add_argument("--online", action="store_true", help="query the OSV.dev API (sends package names and versions)")
    ap.add_argument("--osv-results", help="saved OSV vulnerability JSON (API objects, osv-scanner output or a list)")
    ap.add_argument("--kev", help="CISA KEV catalog JSON or a text file of CVE ids; matching vulns become P1")
    ap.add_argument("--epss", help="EPSS scores (daily CSV or saved api.first.org JSON); adds epss keys and ranks by them within a bucket")
    ap.add_argument("--no-dev", action="store_true", help="drop dev dependencies")
    ap.add_argument("--prioritize", action="store_true", help="text output as a ranked table with an upgrade plan")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--max-vulns", type=int, default=300, help="cap on advisories fetched with --online")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)

    deps: List[Dict[str, object]] = []
    findings: List[Dict[str, object]] = []
    try:
        files = expand_paths(args.paths)
        if not files:
            raise ValueError("no supported manifest found")
        for path in files:
            d, f = load_manifest(path)
            deps += d
            findings += f
        deps = dedupe(deps)
        kev_info = load_kev_catalog(args.kev) if args.kev else {}
        kev_ids = set(kev_info)
        epss_map = load_epss(args.epss)[0] if args.epss else {}
        if args.no_dev:
            deps = [d for d in deps if not d.get("dev")]
        if args.online:
            matches, mode = osv_online(deps, args.timeout, args.max_vulns), "OSV.dev online"
        elif args.osv_results:
            with open(args.osv_results, encoding="utf-8") as fh:
                vulns = collect_vulns(json.load(fh))
            matches, mode = offline_matches(deps, vulns), f"offline, {len(vulns)} OSV records"
        else:
            matches, mode = {}, "offline, pinning checks only"
    except (OSError, ValueError, json.JSONDecodeError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    except urllib.error.URLError as err:
        print(f"error: OSV query failed: {err}", file=sys.stderr)
        return 2

    findings = sort_findings(vuln_findings(deps, matches, kev_ids, kev_info, epss_map) + findings)
    plan = upgrade_plan(findings)
    if args.json:
        print(json.dumps({"mode": mode, "dependencies": len(deps), "findings": findings, "upgrades": plan}, indent=2))
    else:
        print(render_text(deps, findings, plan, args.prioritize, mode))

    if args.fail_on != "never":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(str(f["severity"])) >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
