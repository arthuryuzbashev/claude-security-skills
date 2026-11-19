#!/usr/bin/env python3
"""Exact CVSS v3.1 and v4.0 calculator: scores from a vector string.

v3.1 follows the FIRST specification, including its Roundup function, so
results match the official calculator (base, temporal, environmental).
CVSS:3.0 vectors are scored with the 3.1 formulas and flagged in the output.
v4.0 follows the FIRST v4.0 specification (MacroVector lookup plus
interpolation, same steps and data as the FIRST reference calculator) and
reports the CVSS-B / BT / BE / BTE score plus the base-only score.

Usage:
  cvss_calc.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  cvss_calc.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:P/RL:O"
  cvss_calc.py "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
  cvss_calc.py --file vectors.txt --json
  cvss_calc.py --file vectors.txt --fail-on critical
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from typing import Dict, List, Optional, Tuple

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
    """Score one vector. Temporal/environmental scores appear only when those metrics are in the vector.

    CVSS:4.0 vectors go to score_vector_v4 (one score plus the base-only score and the nomenclature)."""
    if vector.strip().startswith("CVSS:4.0/"):
        return score_vector_v4(vector)
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


# ---------------------------------------------------------------- CVSS v4.0
# MacroVector lookup, max vectors and max severity distances come from the FIRST
# reference calculator (github.com/FIRSTdotorg/cvss-v4-calculator,
# Copyright FIRST, Red Hat, and contributors, BSD-2-Clause).

V4_BASE = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
V4_ENV = ("CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA")
V4_ALLOWED = {
    "AV": "NALP", "AC": "LH", "AT": "NP", "PR": "NLH", "UI": "NPA", "VC": "HLN", "VI": "HLN", "VA": "HLN",
    "SC": "HLN", "SI": "HLN", "SA": "HLN", "E": "XAPU", "CR": "XHML", "IR": "XHML", "AR": "XHML",
    "MAV": "XNALP", "MAC": "XLH", "MAT": "XNP", "MPR": "XNLH", "MUI": "XNPA", "MVC": "XHLN", "MVI": "XHLN",
    "MVA": "XHLN", "MSC": "XHLN", "MSI": "XSHLN", "MSA": "XSHLN",
    "S": "XNP", "AU": "XNY", "R": "XAUI", "V": "XDC", "RE": "XLMH",
}
V4_U = ("X", "Clear", "Green", "Amber", "Red")
V4_NAMES = {"AV": "Attack Vector", "AC": "Attack Complexity", "AT": "Attack Requirements",
            "PR": "Privileges Required", "UI": "User Interaction", "VC": "Vulnerable System Confidentiality",
            "VI": "Vulnerable System Integrity", "VA": "Vulnerable System Availability",
            "SC": "Subsequent System Confidentiality", "SI": "Subsequent System Integrity",
            "SA": "Subsequent System Availability"}
V4_LOOKUP = {k: float(v) for k, v in (item.split(":") for item in (
    "000000:10 000001:9.9 000010:9.8 000011:9.5 000020:9.5 000021:9.2 000100:10 000101:9.6 000110:9.3 "
    "000111:8.7 000120:9.1 000121:8.1 000200:9.3 000201:9 000210:8.9 000211:8 000220:8.1 000221:6.8 "
    "001000:9.8 001001:9.5 001010:9.5 001011:9.2 001020:9 001021:8.4 001100:9.3 001101:9.2 001110:8.9 "
    "001111:8.1 001120:8.1 001121:6.5 001200:8.8 001201:8 001210:7.8 001211:7 001220:6.9 001221:4.8 "
    "002001:9.2 002011:8.2 002021:7.2 002101:7.9 002111:6.9 002121:5 002201:6.9 002211:5.5 002221:2.7 "
    "010000:9.9 010001:9.7 010010:9.5 010011:9.2 010020:9.2 010021:8.5 010100:9.5 010101:9.1 010110:9 "
    "010111:8.3 010120:8.4 010121:7.1 010200:9.2 010201:8.1 010210:8.2 010211:7.1 010220:7.2 "
    "010221:5.3 011000:9.5 011001:9.3 011010:9.2 011011:8.5 011020:8.5 011021:7.3 011100:9.2 "
    "011101:8.2 011110:8 011111:7.2 011120:7 011121:5.9 011200:8.4 011201:7 011210:7.1 011211:5.2 "
    "011220:5 011221:3 012001:8.6 012011:7.5 012021:5.2 012101:7.1 012111:5.2 012121:2.9 012201:6.3 "
    "012211:2.9 012221:1.7 100000:9.8 100001:9.5 100010:9.4 100011:8.7 100020:9.1 100021:8.1 "
    "100100:9.4 100101:8.9 100110:8.6 100111:7.4 100120:7.7 100121:6.4 100200:8.7 100201:7.5 "
    "100210:7.4 100211:6.3 100220:6.3 100221:4.9 101000:9.4 101001:8.9 101010:8.8 101011:7.7 "
    "101020:7.6 101021:6.7 101100:8.6 101101:7.6 101110:7.4 101111:5.8 101120:5.9 101121:5 101200:7.2 "
    "101201:5.7 101210:5.7 101211:5.2 101220:5.2 101221:2.5 102001:8.3 102011:7 102021:5.4 102101:6.5 "
    "102111:5.8 102121:2.6 102201:5.3 102211:2.1 102221:1.3 110000:9.5 110001:9 110010:8.8 110011:7.6 "
    "110020:7.6 110021:7 110100:9 110101:7.7 110110:7.5 110111:6.2 110120:6.1 110121:5.3 110200:7.7 "
    "110201:6.6 110210:6.8 110211:5.9 110220:5.2 110221:3 111000:8.9 111001:7.8 111010:7.6 111011:6.7 "
    "111020:6.2 111021:5.8 111100:7.4 111101:5.9 111110:5.7 111111:5.7 111120:4.7 111121:2.3 "
    "111200:6.1 111201:5.2 111210:5.7 111211:2.9 111220:2.4 111221:1.6 112001:7.1 112011:5.9 112021:3 "
    "112101:5.8 112111:2.6 112121:1.5 112201:2.3 112211:1.3 112221:0.6 200000:9.3 200001:8.7 "
    "200010:8.6 200011:7.2 200020:7.5 200021:5.8 200100:8.6 200101:7.4 200110:7.4 200111:6.1 "
    "200120:5.6 200121:3.4 200200:7 200201:5.4 200210:5.2 200211:4 200220:4 200221:2.2 201000:8.5 "
    "201001:7.5 201010:7.4 201011:5.5 201020:6.2 201021:5.1 201100:7.2 201101:5.7 201110:5.5 "
    "201111:4.1 201120:4.6 201121:1.9 201200:5.3 201201:3.6 201210:3.4 201211:1.9 201220:1.9 "
    "201221:0.8 202001:6.4 202011:5.1 202021:2 202101:4.7 202111:2.1 202121:1.1 202201:2.4 202211:0.9 "
    "202221:0.4 210000:8.8 210001:7.5 210010:7.3 210011:5.3 210020:6 210021:5 210100:7.3 210101:5.5 "
    "210110:5.9 210111:4 210120:4.1 210121:2 210200:5.4 210201:4.3 210210:4.5 210211:2.2 210220:2 "
    "210221:1.1 211000:7.5 211001:5.5 211010:5.8 211011:4.5 211020:4 211021:2.1 211100:6.1 211101:5.1 "
    "211110:4.8 211111:1.8 211120:2 211121:0.9 211200:4.6 211201:1.8 211210:1.7 211211:0.7 211220:0.8 "
    "211221:0.2 212001:5.3 212011:2.4 212021:1.4 212101:2.4 212111:1.2 212121:0.5 212201:1 212211:0.3 "
    "212221:0.1 "
).split())}
V4_MAX_COMPOSED = {
    1: {0: ["AV:N/PR:N/UI:N"], 1: ["AV:A/PR:N/UI:N", "AV:N/PR:L/UI:N", "AV:N/PR:N/UI:P"],
        2: ["AV:P/PR:N/UI:N", "AV:A/PR:L/UI:P"]},
    2: {0: ["AC:L/AT:N"], 1: ["AC:H/AT:N", "AC:L/AT:P"]},
    3: {0: {0: ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H"],
            1: ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M"]},
        1: {0: ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H"],
            1: ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M",
                "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M"]},
        2: {1: ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H"]}},
    4: {0: ["SC:H/SI:S/SA:S"], 1: ["SC:H/SI:H/SA:H"], 2: ["SC:L/SI:L/SA:L"]},
}
V4_MAX_SEVERITY = {1: {0: 1, 1: 4, 2: 5}, 2: {0: 1, 1: 2}, 4: {0: 6, 1: 5, 2: 4},
                   36: {(0, 0): 7, (0, 1): 6, (1, 0): 8, (1, 1): 8, (2, 1): 10}}
V4_LEVELS = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}, "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2}, "AC": {"L": 0.0, "H": 0.1}, "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2}, "VI": {"H": 0.0, "L": 0.1, "N": 0.2}, "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3}, "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2}, "IR": {"H": 0.0, "M": 0.1, "L": 0.2}, "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}
V4_DIST_ORDER = ("AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR")


def parse_vector_v4(vector: str) -> Dict[str, str]:
    """Validate and split a CVSS v4.0 vector. Raises ValueError with a readable reason."""
    vector = vector.strip()
    if not vector.startswith("CVSS:4.0/"):
        raise ValueError("vector must start with CVSS:4.0/")
    metrics: Dict[str, str] = {}
    for part in vector[len("CVSS:4.0/"):].split("/"):
        if ":" not in part:
            raise ValueError(f"bad component {part!r}, expected METRIC:VALUE")
        key, val = part.split(":", 1)
        if key not in V4_ALLOWED and key != "U":
            raise ValueError(f"unknown CVSS 4.0 metric {key!r}")
        if key in metrics:
            raise ValueError(f"metric {key} appears twice")
        allowed = V4_U if key == "U" else tuple(V4_ALLOWED[key])
        if val not in allowed:
            raise ValueError(f"{key}:{val} is not valid; allowed values: {', '.join(allowed)}")
        metrics[key] = val
    missing = [k for k in V4_BASE if k not in metrics]
    if missing:
        raise ValueError(f"missing base metric(s): {', '.join(missing)}")
    return metrics


def _v4_metric(m: Dict[str, str], key: str) -> str:
    """Effective value: E:X counts as A, CR/IR/AR:X as H, a modified metric other than X overrides the base."""
    sel = m.get(key, "X")
    if key == "E" and sel == "X":
        return "A"
    if key in ("CR", "IR", "AR") and sel == "X":
        return "H"
    mod = m.get("M" + key, "X")
    return mod if mod != "X" else sel


def v4_macrovector(m: Dict[str, str]) -> str:
    g = lambda k: _v4_metric(m, k)  # noqa: E731
    if g("AV") == "N" and g("PR") == "N" and g("UI") == "N":
        eq1 = 0
    elif (g("AV") == "N" or g("PR") == "N" or g("UI") == "N") and g("AV") != "P":
        eq1 = 1
    else:
        eq1 = 2
    eq2 = 0 if g("AC") == "L" and g("AT") == "N" else 1
    if g("VC") == "H" and g("VI") == "H":
        eq3 = 0
    elif "H" in (g("VC"), g("VI"), g("VA")):
        eq3 = 1
    else:
        eq3 = 2
    if g("MSI") == "S" or g("MSA") == "S":
        eq4 = 0
    elif "H" in (g("SC"), g("SI"), g("SA")):
        eq4 = 1
    else:
        eq4 = 2
    eq5 = {"A": 0, "P": 1, "U": 2}[g("E")]
    high_req = any(g(r) == "H" and g(v) == "H" for r, v in (("CR", "VC"), ("IR", "VI"), ("AR", "VA")))
    eq6 = 0 if high_req else 1
    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def v4_score(m: Dict[str, str]) -> Tuple[float, str]:
    """CVSS v4.0 score (MacroVector lookup plus interpolation), same steps as the FIRST reference calculator."""
    mv = v4_macrovector(m)
    if all(_v4_metric(m, k) == "N" for k in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0, mv
    eq = [int(c) for c in mv]
    value = V4_LOOKUP[mv]

    def macro(*digits: int) -> str:
        return "".join(str(d) for d in digits)

    def look(key: str) -> Optional[float]:
        return V4_LOOKUP.get(key)

    e1, e2, e3, e4, e5, e6 = eq
    lower1 = look(macro(e1 + 1, e2, e3, e4, e5, e6))
    lower2 = look(macro(e1, e2 + 1, e3, e4, e5, e6))
    if e3 == 0 and e6 == 0:
        left, right = look(macro(e1, e2, e3, e4, e5, e6 + 1)), look(macro(e1, e2, e3 + 1, e4, e5, e6))
        lower36 = left if (left is not None and right is not None and left > right) else right
    elif e3 == 1 and e6 == 0:
        lower36 = look(macro(e1, e2, e3, e4, e5, e6 + 1))
    elif e6 == 1 and e3 in (0, 1):
        lower36 = look(macro(e1, e2, e3 + 1, e4, e5, e6))
    else:
        lower36 = look(macro(e1, e2, e3 + 1, e4, e5, e6 + 1))
    lower4 = look(macro(e1, e2, e3, e4 + 1, e5, e6))
    lower5 = look(macro(e1, e2, e3, e4, e5 + 1, e6))

    dist: Dict[str, float] = {}
    for a in V4_MAX_COMPOSED[1][e1]:
        for b in V4_MAX_COMPOSED[2][e2]:
            for c in V4_MAX_COMPOSED[3][e3][e6]:
                for d in V4_MAX_COMPOSED[4][e4]:
                    mx = dict(x.split(":") for x in "/".join((a, b, c, d)).split("/"))
                    dist = {k: V4_LEVELS[k][_v4_metric(m, k)] - V4_LEVELS[k][mx[k]] for k in V4_DIST_ORDER}
                    if all(dist[k] >= 0 for k in V4_DIST_ORDER):
                        break
                else:
                    continue
                break
            else:
                continue
            break
        else:
            continue
        break

    cur = {
        1: dist["AV"] + dist["PR"] + dist["UI"],
        2: dist["AC"] + dist["AT"],
        36: dist["VC"] + dist["VI"] + dist["VA"] + dist["CR"] + dist["IR"] + dist["AR"],
        4: dist["SC"] + dist["SI"] + dist["SA"],
    }
    max_sev = {1: V4_MAX_SEVERITY[1][e1] * 0.1, 2: V4_MAX_SEVERITY[2][e2] * 0.1,
               36: V4_MAX_SEVERITY[36][(e3, e6)] * 0.1, 4: V4_MAX_SEVERITY[4][e4] * 0.1}
    total, n = 0.0, 0
    for key, lower in ((1, lower1), (2, lower2), (36, lower36), (4, lower4)):
        if lower is not None:
            n += 1
            total += (value - lower) * (cur[key] / max_sev[key])
    if lower5 is not None:
        n += 1  # EQ5 (threat) has no in-macro distance, it only counts toward the mean
    if n:
        value -= total / n
    value = min(max(value, 0.0), 10.0)
    return math.floor(value * 10 + 0.5) / 10, mv


def score_vector_v4(vector: str) -> Dict[str, object]:
    m = parse_vector_v4(vector)
    score, mv = v4_score(m)
    has_threat = m.get("E", "X") != "X"
    has_env = any(m.get(k, "X") != "X" for k in V4_ENV)
    base_only = {k: m[k] for k in V4_BASE}
    base, _ = v4_score(base_only) if (has_threat or has_env) else (score, mv)
    result: Dict[str, object] = {"vector": vector.strip(), "version": "4.0",
                                 "nomenclature": "CVSS-B" + ("T" if has_threat else "") + ("E" if has_env else ""),
                                 "macrovector": mv, "base_score": base, "base_severity": severity(base),
                                 "score": score, "severity": severity(score),
                                 "metrics": {V4_NAMES[k]: m[k] for k in V4_BASE}}
    supplemental = {k: m[k] for k in ("S", "AU", "R", "V", "RE", "U") if m.get(k, "X") != "X"}
    if supplemental:
        result["supplemental"] = supplemental
    if not has_threat:
        result["note"] = "No E metric: scored as Attacked (worst case). Add E:P or E:U from threat intel to lower it"
    return result


def _sev_rank(sev: str) -> int:
    return SEVERITY_ORDER.index("info" if sev == "none" else sev)


def render_text(results: List[Dict[str, object]], errors: List[str]) -> str:
    lines = []
    for r in results:
        if r.get("version") == "4.0":
            lines.append(f"{r['vector']}")
            lines.append(f"  {r['nomenclature']} {r['score']} ({r['severity']}); base {r['base_score']} "
                         f"({r['base_severity']}); macrovector {r['macrovector']}")
            if "note" in r:
                lines.append(f"  note: {r['note']}")
            continue
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
    ap = argparse.ArgumentParser(description="Score CVSS v3.1 vectors (base, temporal, environmental) and CVSS v4.0 vectors.")
    ap.add_argument("vectors", nargs="*", help="one or more CVSS:3.1/... or CVSS:4.0/... vectors")
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
