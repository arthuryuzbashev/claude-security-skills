#!/usr/bin/env python3
"""Exact CVSS v3.1 calculator: base, temporal and environmental scores from a vector string.

Follows the FIRST CVSS v3.1 specification, including its Roundup function, so
results match the official calculator. CVSS:3.0 vectors are scored with the 3.1
formulas (the only difference is rounding precision) and flagged in the output.

Usage:
  cvss_calc.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  cvss_calc.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:P/RL:O"
  cvss_calc.py --file vectors.txt --json
  cvss_calc.py --file vectors.txt --fail-on critical
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from typing import Dict, List, Optional

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
TEMPORAL_METRICS = ("E", "RL", "RC")
ENV_METRICS = ("CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA")

ALLOWED = {
    "AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC", "C": "HLN", "I": "HLN", "A": "HLN",
    "E": "XUPFH", "RL": "XOTWU", "RC": "XURC",
    "CR": "XLMH", "IR": "XLMH", "AR": "XLMH",
    "MAV": "XNALP", "MAC": "XLH", "MPR": "XNLH", "MUI": "XNR", "MS": "XUC", "MC": "XNLH", "MI": "XNLH", "MA": "XNLH",
}

W_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
W_AC = {"L": 0.77, "H": 0.44}
W_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
W_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
W_UI = {"N": 0.85, "R": 0.62}
W_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
W_E = {"X": 1.0, "H": 1.0, "F": 0.97, "P": 0.94, "U": 0.91}
W_RL = {"X": 1.0, "U": 1.0, "W": 0.97, "T": 0.96, "O": 0.95}
W_RC = {"X": 1.0, "C": 1.0, "R": 0.96, "U": 0.92}
W_REQ = {"X": 1.0, "H": 1.5, "M": 1.0, "L": 0.5}

NAMES = {"AV": "Attack Vector", "AC": "Attack Complexity", "PR": "Privileges Required", "UI": "User Interaction",
         "S": "Scope", "C": "Confidentiality", "I": "Integrity", "A": "Availability"}


def roundup(value: float) -> float:
    """CVSS v3.1 Roundup: smallest number with one decimal >= value, immune to float noise (spec Appendix A)."""
    as_int = int(round(value * 100000))
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def severity(score: float) -> str:
    """Qualitative rating from the spec. 0.0 is 'none'."""
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def parse_vector(vector: str) -> Dict[str, str]:
    """Validate and split a CVSS v3.x vector. Raises ValueError with a readable reason."""
    vector = vector.strip()
    m = re.match(r"^CVSS:(3\.[01])/(.+)$", vector)
    if not m:
        raise ValueError("vector must start with CVSS:3.1/ (or CVSS:3.0/)")
    metrics: Dict[str, str] = {"_version": m.group(1)}
    for part in m.group(2).split("/"):
        if ":" not in part:
            raise ValueError(f"bad component {part!r}, expected METRIC:VALUE")
        key, val = part.split(":", 1)
        if key not in ALLOWED:
            raise ValueError(f"unknown metric {key!r}")
        if key in metrics:
            raise ValueError(f"metric {key} appears twice")
        if len(val) != 1 or val not in ALLOWED[key]:
            raise ValueError(f"{key}:{val} is not valid; allowed values: {', '.join(ALLOWED[key])}")
        metrics[key] = val
    missing = [k for k in BASE_METRICS if k not in metrics]
    if missing:
        raise ValueError(f"missing base metric(s): {', '.join(missing)}")
    return metrics


def _impact_iss(c: float, i: float, a: float) -> float:
    return 1 - ((1 - c) * (1 - i) * (1 - a))


def base_scores(m: Dict[str, str]) -> Dict[str, float]:
    changed = m["S"] == "C"
    iss = _impact_iss(W_CIA[m["C"]], W_CIA[m["I"]], W_CIA[m["A"]])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    pr = (W_PR_C if changed else W_PR_U)[m["PR"]]
    exploitability = 8.22 * W_AV[m["AV"]] * W_AC[m["AC"]] * pr * W_UI[m["UI"]]
    if impact <= 0:
        base = 0.0
    elif changed:
        base = roundup(min(1.08 * (impact + exploitability), 10))
    else:
        base = roundup(min(impact + exploitability, 10))
    return {"base_score": base, "impact": round(impact, 1) if impact > 0 else 0.0,
            "exploitability": round(exploitability, 1)}


def temporal_score(m: Dict[str, str], base: float) -> float:
    return roundup(base * W_E[m.get("E", "X")] * W_RL[m.get("RL", "X")] * W_RC[m.get("RC", "X")])


def environmental_score(m: Dict[str, str]) -> float:
    def mod(key: str) -> str:
        v = m.get("M" + key, "X")
        return m[key] if v == "X" else v

    changed = mod("S") == "C"
    miss = min(1 - ((1 - W_REQ[m.get("CR", "X")] * W_CIA[mod("C")]) *
                    (1 - W_REQ[m.get("IR", "X")] * W_CIA[mod("I")]) *
                    (1 - W_REQ[m.get("AR", "X")] * W_CIA[mod("A")])), 0.915)
    if changed:
        m_impact = 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13
    else:
        m_impact = 6.42 * miss
    pr = (W_PR_C if changed else W_PR_U)[mod("PR")]
    m_expl = 8.22 * W_AV[mod("AV")] * W_AC[mod("AC")] * pr * W_UI[mod("UI")]
    t = W_E[m.get("E", "X")] * W_RL[m.get("RL", "X")] * W_RC[m.get("RC", "X")]
    if m_impact <= 0:
        return 0.0
    if changed:
        return roundup(roundup(min(1.08 * (m_impact + m_expl), 10)) * t)
    return roundup(roundup(min(m_impact + m_expl, 10)) * t)


def score_vector(vector: str) -> Dict[str, object]:
    """Score one vector. Temporal/environmental scores appear only when those metrics are in the vector."""
    m = parse_vector(vector)
    result: Dict[str, object] = {"vector": vector.strip(), "version": m["_version"]}
    result.update(base_scores(m))
    result["base_severity"] = severity(result["base_score"])  # type: ignore[arg-type]
    final = result["base_score"]
    if any(k in m for k in TEMPORAL_METRICS):
        result["temporal_score"] = temporal_score(m, result["base_score"])  # type: ignore[arg-type]
        result["temporal_severity"] = severity(result["temporal_score"])  # type: ignore[arg-type]
        final = result["temporal_score"]
    if any(k in m for k in ENV_METRICS):
        result["environmental_score"] = environmental_score(m)
        result["environmental_severity"] = severity(result["environmental_score"])  # type: ignore[arg-type]
        final = result["environmental_score"]
    result["score"] = final
    result["severity"] = severity(final)  # type: ignore[arg-type]
    result["metrics"] = {NAMES[k]: m[k] for k in BASE_METRICS}
    if m["_version"] == "3.0":
        result["note"] = "CVSS:3.0 vector scored with v3.1 formulas; 3.0 rounding can differ by 0.1"
    return result


def _sev_rank(sev: str) -> int:
    return SEVERITY_ORDER.index("info" if sev == "none" else sev)


def render_text(results: List[Dict[str, object]], errors: List[str]) -> str:
    lines = []
    for r in results:
        parts = [f"base {r['base_score']} ({r['base_severity']})"]
        if "temporal_score" in r:
            parts.append(f"temporal {r['temporal_score']} ({r['temporal_severity']})")
        if "environmental_score" in r:
            parts.append(f"environmental {r['environmental_score']} ({r['environmental_severity']})")
        lines.append(f"{r['vector']}")
        lines.append(f"  {', '.join(parts)}; impact {r['impact']}, exploitability {r['exploitability']}")
        if "note" in r:
            lines.append(f"  note: {r['note']}")
    for e in errors:
        lines.append(f"invalid: {e}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Score CVSS v3.1 vectors (base, temporal, environmental).")
    ap.add_argument("vectors", nargs="*", help="one or more CVSS:3.1/... vectors")
    ap.add_argument("--file", help="file with one vector per line ('-' for stdin); text after the vector is ignored")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any final score is at or above this severity (default: high)")
    args = ap.parse_args(argv)

    vectors = list(args.vectors)
    if args.file:
        try:
            raw = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8").read()
        except OSError as err:
            print(f"error: {err}", file=sys.stderr)
            return 2
        for line in raw.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                vectors.append(line.split()[0])
    if not vectors:
        print("error: no vectors given", file=sys.stderr)
        return 2

    results, errors = [], []
    for v in vectors:
        try:
            results.append(score_vector(v))
        except ValueError as err:
            errors.append(f"{v}: {err}")
    if args.json:
        print(json.dumps({"results": results, "errors": errors}, indent=2))
    else:
        print(render_text(results, errors))
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 2
    if args.fail_on != "never":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(_sev_rank(str(r["severity"])) >= threshold for r in results):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
