#!/usr/bin/env python3
"""SSVC decision and CISA BOD 26-04 remediation timeline for one or more CVEs.

Uses two published decision tables (CERT/CC SSVC repo, data/csv/cisa):
  - CISA Coordinator SSVC v2.0.3: Exploitation, Automatable, Technical Impact,
    Mission and Well-Being  ->  Track, Track*, Attend, Act
  - CISA BOD 26-04 timelines v1.0.0: In KEV, Publicly Exposed, Automatable,
    Technical Impact  ->  3 days (+ forensic triage), 14 days, 60 days, on upgrade

Inputs come from flags, from CVE JSON 5 records that carry the CISA ADP
(Vulnrichment) SSVC block, from a saved KEV catalog and EPSS file, or, only
with --online, from the public Vulnrichment repository on GitHub.

Usage:
  ssvc_decide.py CVE-2099-0001 --exploitation poc --automatable no --impact total --mission high --exposed yes
  ssvc_decide.py CVE-2021-44228.json --kev known_exploited_vulnerabilities.json --epss epss.csv --json
  ssvc_decide.py CVE-2021-44228 --online --mission medium --exposed no
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
VULNRICHMENT = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop/{year}/{bucket}xxx/{cve}.json"

# CISA Coordinator v2.0.3: key (exploitation, automatable, technical impact) -> decisions for mission low, medium, high
COORDINATOR = {
    ("none", "no", "partial"): ("track", "track", "track"),
    ("none", "no", "total"): ("track", "track", "track*"),
    ("none", "yes", "partial"): ("track", "track", "attend"),
    ("none", "yes", "total"): ("track", "track", "attend"),
    ("poc", "no", "partial"): ("track", "track", "track*"),
    ("poc", "no", "total"): ("track", "track*", "attend"),
    ("poc", "yes", "partial"): ("track", "track", "attend"),
    ("poc", "yes", "total"): ("track", "track*", "attend"),
    ("active", "no", "partial"): ("track", "track", "attend"),
    ("active", "no", "total"): ("track", "attend", "act"),
    ("active", "yes", "partial"): ("attend", "attend", "act"),
    ("active", "yes", "total"): ("attend", "act", "act"),
}
MISSION_INDEX = {"low": 0, "medium": 1, "high": 2}
# BOD 26-04 v1.0.0: key (in KEV, publicly exposed, automatable, technical impact) -> timeline
BOD_26_04 = {
    ("no", "no", "no", "partial"): "fix on system upgrade", ("no", "no", "no", "total"): "fix on system upgrade",
    ("yes", "no", "no", "partial"): "14 days", ("yes", "no", "no", "total"): "14 days",
    ("no", "yes", "no", "partial"): "60 days", ("no", "yes", "no", "total"): "14 days",
    ("no", "no", "yes", "partial"): "60 days", ("no", "no", "yes", "total"): "60 days",
    ("yes", "yes", "no", "partial"): "14 days", ("yes", "yes", "no", "total"): "3 days & forensic investigation",
    ("yes", "no", "yes", "partial"): "14 days", ("yes", "no", "yes", "total"): "3 days & forensic investigation",
    ("no", "yes", "yes", "partial"): "14 days", ("no", "yes", "yes", "total"): "3 days",
    ("yes", "yes", "yes", "partial"): "3 days", ("yes", "yes", "yes", "total"): "3 days & forensic investigation",
}
DECISION_SEVERITY = {"act": "critical", "attend": "high", "track*": "medium", "track": "low"}
TIMELINE_SEVERITY = {"3 days & forensic investigation": "critical", "3 days": "critical", "14 days": "high",
                     "60 days": "medium", "fix on system upgrade": "low"}
DECISION_TEXT = {
    "act": "Act: fix now, at the highest priority, with leadership involved",
    "attend": "Attend: fix sooner than the normal cycle and tell the owners",
    "track*": "Track*: normal cycle, but watch it closely for changes (exploit news, KEV listing)",
    "track": "Track: fix in the normal patch cycle",
}


def norm(field: str, value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    v = str(value).strip().lower()
    aliases = {"public poc": "poc", "proof of concept": "poc", "y": "yes", "n": "no", "true": "yes", "false": "no",
               "med": "medium", "m": "medium", "l": "low", "h": "high"}
    v = aliases.get(v, v)
    allowed = {"exploitation": ("none", "poc", "active"), "automatable": ("yes", "no"), "impact": ("partial", "total"),
               "mission": ("low", "medium", "high"), "exposed": ("yes", "no"), "kev": ("yes", "no")}[field]
    if v not in allowed:
        raise ValueError(f"{field} must be one of {', '.join(allowed)}, got {value!r}")
    return v


def adp_ssvc(record: dict) -> Tuple[Optional[str], Dict[str, str], bool]:
    """Pull CVE id, the CISA-ADP SSVC options and the ADP KEV flag out of a CVE JSON 5 record."""
    cve = (record.get("cveMetadata") or {}).get("cveId")
    opts: Dict[str, str] = {}
    kev = False
    for adp in (record.get("containers") or {}).get("adp", []) or []:
        for metric in adp.get("metrics", []) or []:
            other = metric.get("other") or {}
            content = other.get("content") or {}
            if other.get("type") == "ssvc":
                cve = cve or content.get("id")
                for opt in content.get("options", []) or []:
                    opts.update({str(k): str(v) for k, v in opt.items()})
            elif other.get("type") == "kev":
                kev = True
    return cve, opts, kev


def load_kev_catalog(path: str) -> Dict[str, dict]:
    """CISA KEV catalog JSON -> {CVE id: entry}. A plain text file of CVE ids also works."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {m.upper(): {} for m in re.findall(r"CVE-\d{4}-\d{4,}", text, re.I)}
    items = data.get("vulnerabilities", data) if isinstance(data, dict) else data
    out: Dict[str, dict] = {}
    for i in items or []:
        if isinstance(i, dict) and (i.get("cveID") or i.get("cve")):
            out[str(i.get("cveID") or i.get("cve")).upper()] = i
        elif isinstance(i, str):
            out[i.upper()] = {}
    return out


def load_epss(path: str) -> Tuple[Dict[str, Dict[str, float]], str]:
    """EPSS scores from the daily CSV (epss_scores-YYYY-MM-DD.csv) or a saved api.first.org JSON response."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    out: Dict[str, Dict[str, float]] = {}
    model = ""
    if text.lstrip().startswith(("{", "[")):
        data = json.loads(text)
        rows = data.get("data", []) if isinstance(data, dict) else data
        for r in rows:
            out[str(r["cve"]).upper()] = {"epss": float(r["epss"]), "percentile": float(r["percentile"])}
        return out, model
    lines = text.splitlines()
    if lines and lines[0].startswith("#"):
        m = re.search(r"model_version:([^,\s]+)", lines[0])
        model = m.group(1) if m else ""
        lines = lines[1:]
    for r in csv.DictReader(io.StringIO("\n".join(lines))):
        if r.get("cve"):
            out[r["cve"].upper()] = {"epss": float(r["epss"]), "percentile": float(r["percentile"])}
    return out, model


def fetch_vulnrichment(cve: str, timeout: float) -> dict:
    year, num = cve.upper().split("-")[1:3]
    url = VULNRICHMENT.format(year=year, bucket=int(num) // 1000, cve=cve.upper())
    req = urllib.request.Request(url, headers={"User-Agent": "claude-security-skills-ssvc/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def decide(cve: str, given: Dict[str, Optional[str]], kev_entry: Optional[dict],
           epss: Optional[Dict[str, float]]) -> Dict[str, object]:
    """Fill gaps with stated assumptions, then look up both tables."""
    assumed: List[str] = []
    kev = "yes" if kev_entry is not None else (given.get("kev") or "no")
    exploitation = given.get("exploitation")
    if kev == "yes" and exploitation != "active":
        exploitation = "active"
        assumed.append("exploitation=active because the CVE is in KEV")
    if exploitation is None:
        exploitation = "none"
        assumed.append("exploitation=none (no data; check KEV, vendor advisories and threat intel)")
    automatable, impact = given.get("automatable"), given.get("impact")
    if automatable is None:
        automatable = "yes" if kev == "yes" else "no"
        assumed.append(f"automatable={automatable} ({'worst case for a KEV entry' if kev == 'yes' else 'BOD 26-04 default'})")
    if impact is None:
        impact = "total"
        assumed.append("technical impact=total (BOD 26-04 default and worst case)")
    mission = given.get("mission") or "high"
    if not given.get("mission"):
        assumed.append("mission and well-being=high (worst case; pass --mission)")
    exposed = given.get("exposed") or "yes"
    if not given.get("exposed"):
        assumed.append("publicly exposed=yes (worst case; pass --exposed)")

    decision = COORDINATOR[(exploitation, automatable, impact)][MISSION_INDEX[mission]]
    timeline = BOD_26_04[(kev, exposed, automatable, impact)]
    result: Dict[str, object] = {
        "cve": cve, "decision": decision, "bod_26_04": timeline,
        "inputs": {"exploitation": exploitation, "automatable": automatable, "technical_impact": impact,
                   "mission_wellbeing": mission, "exposed": exposed, "kev": kev},
        "assumed": assumed,
    }
    if kev_entry:
        result["kev_details"] = {k: kev_entry[k] for k in ("dateAdded", "dueDate", "knownRansomwareCampaignUse",
                                                           "forensicTriage") if k in kev_entry}
    if epss:
        result["epss"] = epss
    return result


def to_finding(r: Dict[str, object]) -> Dict[str, object]:
    sev = max(DECISION_SEVERITY[str(r["decision"])], TIMELINE_SEVERITY[str(r["bod_26_04"])], key=SEVERITY_ORDER.index)
    inp = r["inputs"]
    detail = (f"SSVC {r['decision']} (exploitation {inp['exploitation']}, automatable {inp['automatable']}, "  # type: ignore[index]
              f"impact {inp['technical_impact']}, mission {inp['mission_wellbeing']}); "  # type: ignore[index]
              f"BOD 26-04 timeline: {r['bod_26_04']}.")
    kd = r.get("kev_details") or {}
    if kd.get("knownRansomwareCampaignUse") == "Known":  # type: ignore[union-attr]
        detail += " KEV says it is used in ransomware campaigns."
    if r.get("epss"):
        e = r["epss"]
        detail += f" EPSS {e['epss']:.3f} (percentile {e['percentile']:.2f})."  # type: ignore[index]
    fix = DECISION_TEXT[str(r["decision"])] + "."
    if str(r["bod_26_04"]).endswith("forensic investigation"):
        fix += " Under BOD 26-04 also run CISA's forensic triage on the affected assets."
    return {"id": "SSVC-001", "severity": sev, "title": f"{r['cve']}: {r['decision']}, {r['bod_26_04']}",
            "detail": detail, "fix": fix, "location": str(r["cve"]), "cve": r["cve"], "decision": r["decision"],
            "bod_26_04": r["bod_26_04"]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="SSVC (CISA Coordinator v2.0.3) decision and BOD 26-04 timeline per CVE.")
    ap.add_argument("targets", nargs="+", help="CVE ids, CVE JSON 5 files, or directories of them ('-' for stdin)")
    ap.add_argument("--exploitation", help="none, poc or active (overrides the record)")
    ap.add_argument("--automatable", help="yes or no (overrides the record)")
    ap.add_argument("--impact", help="technical impact: partial or total (overrides the record)")
    ap.add_argument("--mission", help="mission and well-being impact for your org: low, medium or high")
    ap.add_argument("--exposed", help="is the affected asset reachable from the internet: yes or no")
    ap.add_argument("--kev", help="CISA KEV catalog JSON (or text with CVE ids); listed CVEs count as active and in KEV")
    ap.add_argument("--epss", help="EPSS CSV (epss_scores-*.csv) or saved api.first.org JSON, shown next to the decision")
    ap.add_argument("--online", action="store_true", help="fetch CVE ids from the public cisagov/vulnrichment repo")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if a result is at or above this severity (act/3 days = critical, attend/14 days = high)")
    args = ap.parse_args(argv)

    try:
        flags = {"exploitation": norm("exploitation", args.exploitation), "automatable": norm("automatable", args.automatable),
                 "impact": norm("impact", args.impact), "mission": norm("mission", args.mission),
                 "exposed": norm("exposed", args.exposed)}
        kev_cat = load_kev_catalog(args.kev) if args.kev else {}
        epss_map, model = load_epss(args.epss) if args.epss else ({}, "")
        jobs: List[Tuple[str, Dict[str, str], bool]] = []
        for t in args.targets:
            if CVE_RE.match(t):
                if args.online:
                    _, opts, adp_kev = adp_ssvc(fetch_vulnrichment(t, args.timeout))
                    jobs.append((t.upper(), opts, adp_kev))
                else:
                    jobs.append((t.upper(), {}, False))
                continue
            paths = [os.path.join(t, f) for f in sorted(os.listdir(t)) if f.endswith(".json")] if os.path.isdir(t) else [t]
            for p in paths:
                raw = sys.stdin.read() if p == "-" else open(p, encoding="utf-8").read()
                cve, opts, adp_kev = adp_ssvc(json.loads(raw))
                if not cve:
                    raise ValueError(f"{p}: no CVE id found (expected a CVE JSON 5 record)")
                jobs.append((str(cve).upper(), opts, adp_kev))
    except (OSError, ValueError, KeyError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    except urllib.error.URLError as err:
        print(f"error: Vulnrichment fetch failed: {err}", file=sys.stderr)
        return 2

    results = []
    try:
        for cve, opts, adp_kev in jobs:
            given = {"exploitation": flags["exploitation"] or norm("exploitation", opts.get("Exploitation")),
                     "automatable": flags["automatable"] or norm("automatable", opts.get("Automatable")),
                     "impact": flags["impact"] or norm("impact", opts.get("Technical Impact")),
                     "mission": flags["mission"], "exposed": flags["exposed"], "kev": "yes" if adp_kev else None}
            entry = kev_cat.get(cve)
            if entry is None and adp_kev:
                entry = {}
            results.append(decide(cve, given, entry, epss_map.get(cve)))
    except ValueError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    findings = [to_finding(r) for r in results]
    if args.json:
        out = {"results": results, "findings": findings, "count": len(findings)}
        if model:
            out["epss_model"] = model
        print(json.dumps(out, indent=2))
    else:
        for r, f in zip(results, findings):
            print(f"{r['cve']}: {str(r['decision']).upper()}  |  BOD 26-04: {r['bod_26_04']}  [{f['severity']}]")
            print(f"  {f['detail']}")
            print(f"  next: {f['fix']}")
            for a in r["assumed"]:  # type: ignore[attr-defined]
                print(f"  assumed: {a}")
    if args.fail_on != "never":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(str(f["severity"])) >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
