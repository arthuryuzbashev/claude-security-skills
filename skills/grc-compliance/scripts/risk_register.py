#!/usr/bin/env python3
"""Score and check a CSV risk register: inherent vs residual risk, heat map, overdue reviews, gaps.

Likelihood and impact are 1-5. Inherent = likelihood x impact (1-25). Residual comes from
explicit residual_likelihood/residual_impact columns, or from control effectiveness
(inherent x (1 - effectiveness), never below 1).

Usage:
  risk_register.py register.csv
  risk_register.py register.csv --today 2026-11-19 --top 10
  risk_register.py register.csv --json --fail-on medium
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from datetime import date, timedelta
from typing import Any, Dict, List, Optional, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
RATINGS = ["low", "medium", "high", "critical"]
# Default bands on the 1-25 scale. Change them here if your risk policy says otherwise.
BANDS = [(15, "critical"), (10, "high"), (5, "medium"), (0, "low")]
EFFECTIVENESS = {"none": 0.0, "nil": 0.0, "weak": 0.25, "low": 0.25, "partial": 0.5, "medium": 0.5,
                 "moderate": 0.5, "strong": 0.75, "high": 0.75, "effective": 0.75}
CLOSED = ("closed", "retired", "transferred-closed")
REQUIRED = ["id", "title", "likelihood", "impact"]
ALIASES = {"risk_id": "id", "risk": "title", "name": "title", "l": "likelihood", "i": "impact",
           "risk_owner": "owner", "control_effectiveness": "effectiveness", "controls_effectiveness": "effectiveness",
           "next_review_date": "next_review", "review_due": "next_review", "last_review_date": "last_review",
           "last_reviewed": "last_review", "residual_l": "residual_likelihood", "residual_i": "residual_impact",
           "acceptance_expiry": "accepted_until", "acceptance_expires": "accepted_until",
           "acceptance_until": "accepted_until", "accept_until": "accepted_until",
           "target_date": "treatment_due", "due_date": "treatment_due", "action_due": "treatment_due",
           "treatment_date": "treatment_due"}


def finding(fid, severity, title, detail, fix, location=None) -> Dict[str, Any]:
    f = {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}
    if location:
        f["location"] = location
    return f


def rating(score: float) -> str:
    for floor, name in BANDS:
        if score >= floor:
            return name
    return "low"


def parse_effectiveness(value: str) -> float:
    v = (value or "").strip().lower()
    if not v:
        return 0.0
    if v in EFFECTIVENESS:
        return EFFECTIVENESS[v]
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*%?", v)
    if not m:
        raise ValueError(f"control effectiveness {value!r} (use none/weak/partial/strong, 0-1 or 0-100%)")
    num = float(m.group(1))
    if v.endswith("%") or num > 1:
        num /= 100.0
    if not 0 <= num <= 1:
        raise ValueError(f"control effectiveness {value!r} out of range")
    return num


def _score(value: str, name: str) -> int:
    try:
        n = int(str(value).strip())
    except ValueError:
        raise ValueError(f"{name} {value!r} is not a whole number 1-5")
    if not 1 <= n <= 5:
        raise ValueError(f"{name} {n} is outside 1-5")
    return n


def _date(value: str, name: str) -> Optional[date]:
    v = (value or "").strip()
    if not v:
        return None
    try:
        return date.fromisoformat(v)
    except ValueError:
        raise ValueError(f"{name} {v!r} is not an ISO date (YYYY-MM-DD)")


def load_register(text: str, review_days: int = 180) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Parse and score the register. Returns (risks, errors). Each error names the row."""
    reader = csv.DictReader(io.StringIO(text.lstrip("﻿")))
    if not reader.fieldnames:
        raise ValueError("CSV has no header row")
    risks, errors = [], []
    for line_no, raw in enumerate(reader, 2):
        row = {}
        for k, v in raw.items():
            if k is None:
                continue
            key = k.strip().lower().replace(" ", "_").replace("-", "_")
            row[ALIASES.get(key, key)] = (v or "").strip() if isinstance(v, str) else ""
        if not any(row.values()):
            continue
        label = f"row {line_no}" + (f" ({row.get('id')})" if row.get("id") else "")
        missing = [k for k in REQUIRED if not row.get(k)]
        if missing:
            errors.append(f"{label}: missing {', '.join(missing)}")
            continue
        try:
            lik, imp = _score(row["likelihood"], "likelihood"), _score(row["impact"], "impact")
            eff = parse_effectiveness(row.get("effectiveness", ""))
            if row.get("residual_likelihood") or row.get("residual_impact"):
                r_l = _score(row.get("residual_likelihood") or row["likelihood"], "residual_likelihood")
                r_i = _score(row.get("residual_impact") or row["impact"], "residual_impact")
                residual = float(r_l * r_i)
                residual_basis = "explicit"
                residual_pos = [r_l, r_i]
            else:
                residual_pos = None
                residual = max(1.0, round(lik * imp * (1 - eff), 1))
                residual_basis = "effectiveness"
            last = _date(row.get("last_review", ""), "last_review")
            nxt = _date(row.get("next_review", ""), "next_review")
            accepted_until = _date(row.get("accepted_until", ""), "accepted_until")
            treatment_due = _date(row.get("treatment_due", ""), "treatment_due")
        except ValueError as err:
            errors.append(f"{label}: {err}")
            continue
        due = nxt or (last + timedelta(days=review_days) if last else None)
        inherent = lik * imp
        risks.append({
            "id": row["id"], "title": row["title"], "owner": row.get("owner", ""),
            "category": row.get("category", ""), "status": (row.get("status") or "open").lower(),
            "treatment": (row.get("treatment") or "").lower(), "controls": row.get("controls", ""),
            "has_controls_column": "controls" in row,
            "likelihood": lik, "impact": imp, "inherent": inherent, "inherent_rating": rating(inherent),
            "effectiveness": eff, "residual": residual, "residual_rating": rating(residual),
            "residual_basis": residual_basis, "residual_position": residual_pos,
            "last_review": last.isoformat() if last else None, "review_due": due.isoformat() if due else None,
            "accepted_until": accepted_until.isoformat() if accepted_until else None,
            "treatment_due": treatment_due.isoformat() if treatment_due else None,
        })
    return risks, errors


def check(risks: List[Dict[str, Any]], today: date) -> List[Dict[str, Any]]:
    """Governance checks on open risks: owners, review dates, acceptance of high risk, treatment gaps."""
    out = []
    seen: Dict[str, int] = {}
    for r in risks:
        seen[r["id"]] = seen.get(r["id"], 0) + 1
    for rid, n in seen.items():
        if n > 1:
            out.append(finding("RR-009", "medium", "Duplicate risk id",
                               f"{rid} appears {n} times. Treatment actions, audit evidence and reports that cite "
                               "the id become ambiguous.",
                               "Give every risk a unique id; merge the rows if they are the same risk.", rid))
    for r in risks:
        if r["status"] in CLOSED:
            continue
        loc = f"{r['id']} {r['title']}"
        serious = r["residual_rating"] in ("high", "critical")
        if not r["owner"]:
            out.append(finding("RR-001", "high" if serious else "medium", "Risk has no owner",
                               f"{r['id']} (residual {r['residual']:g}, {r['residual_rating']}) has nobody accountable for it.",
                               "Name one person (a role holder, not a team) who can decide and fund the treatment.", loc))
        if r["review_due"]:
            due = date.fromisoformat(r["review_due"])
            if due < today:
                days = (today - due).days
                out.append(finding("RR-002", "high" if r["residual_rating"] == "critical" else "medium",
                                   "Risk review overdue",
                                   f"{r['id']} was due for review on {r['review_due']} ({days} days ago).",
                                   "Review likelihood, impact and controls with the owner and set the next review date.", loc))
        else:
            out.append(finding("RR-003", "low", "No review date",
                               f"{r['id']} has neither last_review nor next_review, so nobody knows if it is current.",
                               "Add next_review (quarterly for high and critical risks, yearly for the rest).", loc))
        if serious and r["treatment"] in ("accept", "accepted", "tolerate"):
            out.append(finding("RR-004", "high" if r["residual_rating"] == "critical" else "medium",
                               f"{r['residual_rating'].capitalize()} residual risk accepted",
                               f"{r['id']} is accepted at residual {r['residual']:g}. Acceptance above the appetite usually needs senior sign-off.",
                               "Record who accepted it, when, and the expiry of the acceptance; or plan more treatment.", loc))
        if serious and not r["treatment"]:
            out.append(finding("RR-005", "medium", "No treatment decision",
                               f"{r['id']} is {r['residual_rating']} after controls but has no treatment (mitigate, transfer, avoid, accept).",
                               "Decide the treatment and add the actions with dates.", loc))
        accepted = r["treatment"] in ("accept", "accepted", "tolerate")
        if accepted and r.get("accepted_until") and date.fromisoformat(r["accepted_until"]) < today:
            out.append(finding("RR-008", "high" if r["residual_rating"] == "critical" else "medium",
                               "Risk acceptance expired",
                               f"{r['id']} was accepted until {r['accepted_until']}; the acceptance has lapsed, so "
                               "the risk is open without a valid decision.",
                               "Have the risk owner re-approve the acceptance with a new expiry, or plan treatment.", loc))
        if (not accepted and r.get("treatment_due") and date.fromisoformat(r["treatment_due"]) < today):
            days = (today - date.fromisoformat(r["treatment_due"])).days
            out.append(finding("RR-010", "medium" if serious else "low", "Treatment action overdue",
                               f"{r['id']} treatment was due on {r['treatment_due']} ({days} days ago) and the risk "
                               "is still open.",
                               "Confirm the action is done (then lower the scores or close the risk) or agree a new date "
                               "with the owner.", loc))
        if r["residual"] > r["inherent"]:
            out.append(finding("RR-006", "low", "Residual risk above inherent",
                               f"{r['id']}: residual {r['residual']:g} > inherent {r['inherent']}. Controls cannot make a risk worse.",
                               "Recheck the residual scores; the inherent score may be too low.", loc))
        if r["has_controls_column"] and r["effectiveness"] > 0 and not r["controls"]:
            out.append(finding("RR-007", "low", "Effectiveness claimed without listed controls",
                               f"{r['id']} claims {int(r['effectiveness'] * 100)}% control effectiveness but lists no controls.",
                               "Name the controls (and ideally the evidence that they work).", loc))
    out.sort(key=lambda f: -SEVERITY_ORDER.index(f["severity"]))
    return out


def heat_map(risks: List[Dict[str, Any]], which: str = "inherent") -> List[List[int]]:
    """5x5 counts, grid[likelihood-1][impact-1]. Residual uses the explicit or scaled position."""
    grid = [[0] * 5 for _ in range(5)]
    for r in risks:
        if r["status"] in CLOSED:
            continue
        if which == "inherent":
            lik, imp = r["likelihood"], r["impact"]
        elif r["residual_position"]:
            lik, imp = r["residual_position"]
        else:
            # controls mostly cut likelihood: keep impact, scale likelihood so l x i ~= residual score
            imp = r["impact"]
            lik = max(1, min(5, round(r["residual"] / imp)))
        grid[lik - 1][imp - 1] += 1
    return grid


def render_heat_map(grid: List[List[int]], title: str) -> List[str]:
    lines = [f"{title} (rows likelihood 5..1, columns impact 1..5; band letter L/M/H/C, count)", "```"]
    lines.append("        " + "".join(f"   I{i}  " for i in range(1, 6)))
    for lik in range(5, 0, -1):
        cells = []
        for imp in range(1, 6):
            band = rating(lik * imp)[0].upper()
            n = grid[lik - 1][imp - 1]
            cells.append(f"  {band}:{n if n else '.':<3} ")
        lines.append(f"  L{lik}   " + "".join(cells))
    lines.append("```")
    return lines


def summarize(risks, findings, today, top) -> Dict[str, Any]:
    open_risks = [r for r in risks if r["status"] not in CLOSED]
    by = lambda key: {b: sum(1 for r in open_risks if r[key] == b) for b in reversed(RATINGS)}
    ranked = sorted(open_risks, key=lambda r: (-r["residual"], -r["inherent"], r["id"]))
    return {
        "today": today.isoformat(),
        "total": len(risks), "open": len(open_risks),
        "inherent_by_rating": by("inherent_rating"), "residual_by_rating": by("residual_rating"),
        "top_risks": [{k: r[k] for k in ("id", "title", "owner", "inherent", "residual", "residual_rating", "treatment")}
                      for r in ranked[:top]],
        "overdue": [f["location"] for f in findings if f["id"] == "RR-002"],
        "missing_owner": [f["location"] for f in findings if f["id"] == "RR-001"],
    }


def render_markdown(risks, findings, summary) -> str:
    s = summary
    L = [f"# Risk register review ({s['today']})", "",
         f"{s['open']} open risks of {s['total']}. Residual score = inherent x (1 - control effectiveness) unless residual L/I are given.", "",
         "| Rating | Inherent | Residual |", "|---|---|---|"]
    L += [f"| {b.capitalize()} | {s['inherent_by_rating'][b]} | {s['residual_by_rating'][b]} |" for b in reversed(RATINGS)]
    L.append("")
    L += render_heat_map(heat_map(risks, "inherent"), "Inherent heat map")
    L.append("")
    L += render_heat_map(heat_map(risks, "residual"), "Residual heat map")
    L += ["", "## Top risks by residual score", "", "| ID | Risk | Owner | Inherent | Residual | Treatment |", "|---|---|---|---|---|---|"]
    for r in s["top_risks"]:
        L.append(f"| {r['id']} | {r['title']} | {r['owner'] or 'MISSING'} | {r['inherent']} | "
                 f"{r['residual']:g} ({r['residual_rating']}) | {r['treatment'] or '-'} |")
    L += ["", "## Overdue reviews", ""] + ([f"- {x}" for x in s["overdue"]] or ["None."])
    L += ["", "## Risks without an owner", ""] + ([f"- {x}" for x in s["missing_owner"]] or ["None."])
    L += ["", f"## Findings ({len(findings)})", ""]
    if not findings:
        L.append("No issues found.")
    for f in findings:
        L.append(f"- [{f['severity'].upper()}] {f['id']} {f['title']}: {f['detail']} Fix: {f['fix']}")
    return "\n".join(L) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Score and check a CSV risk register.")
    ap.add_argument("file", help="risk register CSV; '-' for stdin")
    ap.add_argument("--today", help="date to measure overdue reviews against (YYYY-MM-DD, default today)")
    ap.add_argument("--review-days", type=int, default=180,
                    help="review cycle used when only last_review is given (default 180)")
    ap.add_argument("--top", type=int, default=5, help="how many top risks to list (default 5)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)
    try:
        text = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8").read()
        today = date.fromisoformat(args.today) if args.today else date.today()
        risks, errors = load_register(text, args.review_days)
    except (OSError, ValueError, csv.Error) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 2
    if not risks:
        print("error: the register has no risks", file=sys.stderr)
        return 2
    findings = check(risks, today)
    summary = summarize(risks, findings, today, args.top)
    if args.json:
        print(json.dumps({"summary": summary, "risks": risks, "findings": findings}, indent=2))
    else:
        sys.stdout.write(render_markdown(risks, findings, summary))
    if args.fail_on != "never":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
