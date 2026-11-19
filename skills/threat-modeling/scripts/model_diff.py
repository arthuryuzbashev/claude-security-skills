#!/usr/bin/env python3
"""Compare two system descriptions (old vs new design) and list what needs threat-model review.

Reads the same JSON / simple YAML format as stride_model.py. Flows are matched by
their id, or by from->to when they have no id. Reports new and changed boundary
crossings, weakened auth or encryption, new components, zone moves, logging turned
off and removals.

Usage:
  model_diff.py old.yaml new.yaml
  model_diff.py old.yaml new.yaml --json
  model_diff.py old.yaml new.yaml --fail-on medium
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stride_model as sm  # noqa: E402  (same folder, standard library only)

SEVERITY_ORDER = sm.SEVERITY_ORDER
RISKY_TYPES = {"external", "llm", "user"}


def _finding(rule, severity, title, detail, fix, location, change):
    return {"id": rule, "severity": severity, "title": title, "detail": detail, "fix": fix,
            "location": location, "change": change}


def _flow_text(a: Dict[str, Any]) -> str:
    bits = [f"{a['from']} ({a['from_zone']}) -> {a['to']} ({a['to_zone']})"]
    bits.append(f"protocol {a['protocol'] or 'not given'}")
    bits.append(f"auth {a['auth'] or 'not stated'}")
    bits.append(f"data {', '.join(a['data']) or 'unclassified'}")
    return ", ".join(bits)


def diff_models(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    oc, nc = old["components"], new["components"]
    # components
    for cid, c in nc.items():
        loc = f"component {cid}"
        if cid not in oc:
            risky = c["type"] in RISKY_TYPES or new["trust"][c["zone"]] == 0
            findings.append(_finding(
                "DIFF-004", "medium" if risky else "low", "New component",
                f"{c['name']} ({c['type']}) added in zone {c['zone']}.",
                "Run its STRIDE threats (stride_model.py on the new model) and agree owners for the mitigations.",
                loc, "added"))
            continue
        o = oc[cid]
        if o["zone"] != c["zone"]:
            lower = new["trust"][c["zone"]] < old["trust"][o["zone"]]
            findings.append(_finding(
                "DIFF-005", "high" if lower and c["kind"] == "store" else "medium", "Component moved zone",
                f"{c['name']} moved from {o['zone']} (trust {old['trust'][o['zone']]}) to {c['zone']} "
                f"(trust {new['trust'][c['zone']]}).",
                "Re-check every flow into it: network rules, authentication and who can now reach it.", loc, "changed"))
        if o["type"] != c["type"]:
            findings.append(_finding("DIFF-005", "medium", "Component type changed",
                                     f"{c['name']} changed from {o['type']} to {c['type']}.",
                                     "Review the threats for the new type.", loc, "changed"))
        if o["logging"] is not False and c["logging"] is False:
            findings.append(_finding("DIFF-006", "medium", "Logging turned off",
                                     f"{c['name']} had logging {('on' if o['logging'] else 'not stated')}, now logging: no.",
                                     "Keep security logging on, or record who accepted the gap and why.", loc, "changed"))
    for cid, o in oc.items():
        if cid not in nc:
            findings.append(_finding("DIFF-007", "info", "Component removed", f"{o['name']} is gone from the new model.",
                                     "Confirm it is decommissioned: credentials revoked, data deleted or migrated, DNS removed.",
                                     f"component {cid}", "removed"))
    # flows
    old_flows = {a["key"]: a for a in (sm.analyze_flow(f, old) for f in old["flows"])}
    new_flows = {a["key"]: a for a in (sm.analyze_flow(f, new) for f in new["flows"])}
    review = []
    for key, a in new_flows.items():
        loc = f"flow {key}"
        if key not in old_flows:
            if a["crosses_boundary"]:
                bad = a["authenticated"] is False and a["inbound"] or (a["encrypted"] is False and a["sensitive"])
                findings.append(_finding(
                    "DIFF-001", "high" if bad else "medium", "New flow crosses a trust boundary",
                    _flow_text(a) + ".",
                    "Add it to the threat model session: authentication, encryption, input validation and rate limits on the receiver.",
                    loc, "added"))
                review.append(key)
            else:
                plain = a["encrypted"] is False and a["sensitive"]
                findings.append(_finding("DIFF-002", "medium" if plain else "low", "New flow inside one zone",
                                         _flow_text(a) + (" Sensitive data in plaintext." if plain else "."),
                                         "Quick check: least-privilege credentials, the data it carries, and TLS for sensitive data.",
                                         loc, "added"))
            continue
        o = old_flows[key]
        changes, sev = [], "low"

        def bump(level):
            nonlocal sev
            if SEVERITY_ORDER.index(level) > SEVERITY_ORDER.index(sev):
                sev = level

        if (o["from"], o["to"]) != (a["from"], a["to"]):
            changes.append(f"endpoints {o['from']}->{o['to']} became {a['from']}->{a['to']}")
            bump("medium")
        if o["authenticated"] is True and a["authenticated"] is not True:
            changes.append(f"auth {o['auth']} became {a['auth'] or 'not stated'}")
            bump("high" if a["authenticated"] is False else "medium")
        elif o["auth"] != a["auth"]:
            changes.append(f"auth {o['auth'] or 'not stated'} became {a['auth'] or 'not stated'}")
        if o["encrypted"] is True and a["encrypted"] is not True:
            changes.append(f"encryption lost ({o['protocol'] or 'encrypted'} became {a['protocol'] or 'not stated'})")
            bump("high" if a["encrypted"] is False or a["sensitive"] else "medium")
        if a["data_level"] > o["data_level"]:
            changes.append(f"data {', '.join(o['data']) or 'unclassified'} became {', '.join(a['data'])}")
            bump("medium")
        if a["crosses_boundary"] and not o["crosses_boundary"]:
            changes.append(f"now crosses {a['from_zone']} -> {a['to_zone']}")
            bump("medium")
        if changes:
            findings.append(_finding("DIFF-003", sev, "Flow changed", f"{key}: " + "; ".join(changes) + ".",
                                     "Re-review this flow; restore the control or record the accepted risk.", loc, "changed"))
            if a["crosses_boundary"]:
                review.append(key)
    for key, o in old_flows.items():
        if key not in new_flows:
            findings.append(_finding("DIFF-007", "info", "Flow removed", _flow_text(o) + ".",
                                     "Remove the firewall rules and credentials it used.", f"flow {key}", "removed"))
    findings.sort(key=lambda f: -SEVERITY_ORDER.index(f["severity"]))
    by_sev = {s: sum(1 for f in findings if f["severity"] == s) for s in reversed(SEVERITY_ORDER)}
    return {"old": old["name"], "new": new["name"], "findings": findings, "needs_review": review,
            "summary": {"added": sum(1 for f in findings if f["change"] == "added"),
                        "changed": sum(1 for f in findings if f["change"] == "changed"),
                        "removed": sum(1 for f in findings if f["change"] == "removed"),
                        "boundary_flows_to_review": len(review), "by_severity": by_sev}}


def render_text(result: Dict[str, Any]) -> str:
    s = result["summary"]
    lines = [f"Model diff: {result['old']} -> {result['new']}",
             f"{s['added']} added, {s['changed']} changed, {s['removed']} removed; "
             f"{s['boundary_flows_to_review']} boundary-crossing flows need review", ""]
    if not result["findings"]:
        lines.append("No security-relevant changes.")
    for f in result["findings"]:
        lines.append(f"[{f['severity'].upper()}] {f['id']} {f['title']} ({f['location']})")
        lines.append(f"    {f['detail']}")
        lines.append(f"    fix: {f['fix']}")
    if result["needs_review"]:
        lines += ["", "Review these flows in the next session: " + ", ".join(result["needs_review"])]
    return "\n".join(lines) + "\n"


def _load(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return sm.load_model(fh.read())


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="List new flows, boundary crossings and weakened controls between two model versions.")
    ap.add_argument("old", help="previous system description (JSON or simple YAML)")
    ap.add_argument("new", help="new system description")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any change is at or above this severity (default: high)")
    args = ap.parse_args(argv)
    try:
        old, new = _load(args.old), _load(args.new)
    except (OSError, ValueError, json.JSONDecodeError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    result = diff_models(old, new)
    print(json.dumps(result, indent=2) if args.json else render_text(result), end="" if not args.json else "\n")
    if args.fail_on != "never":
        t = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= t for f in result["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
