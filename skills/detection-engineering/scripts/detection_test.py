#!/usr/bin/env python3
"""Run Sigma-style detections against JSON-lines events and show what matches.

A small, offline Sigma evaluator for testing rules before deployment. It
supports field modifiers contains, startswith, endswith, re, all, exists,
cased and i/m/s regex flags, `*` and `?` wildcards, null, keyword lists,
dotted field paths (process.command_line), and conditions with and, or,
not, parentheses, `1 of selection*`, `all of filter_*` and `1 of them`.
Matching is case-insensitive like Sigma, except `re` and `cased`.

Pipe aggregations (`| count() > 5`) are not evaluated (exit 2).

Usage:
  detection_test.py rule.yml --events events.jsonl
  detection_test.py rules/ --events events.jsonl --json
  detection_test.py rule.yml --events events.jsonl --expect 2,5
  cat events.jsonl | detection_test.py rule.yml --events -
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from typing import Any, Dict, List

# The YAML reader lives in the sibling sigma_lint.py (same skill), loaded by path.
_spec = importlib.util.spec_from_file_location(
    "_secskills_sigma_lint", os.path.join(os.path.dirname(os.path.abspath(__file__)), "sigma_lint.py"))
_lint = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_lint)
YamlError, collect_files, load_rules = _lint.YamlError, _lint.collect_files, _lint.load_rules

KNOWN_MODS = {"contains", "startswith", "endswith", "all", "re", "i", "m", "s", "exists", "cased"}


class RuleError(ValueError):
    pass


# ---------------------------------------------------------------- field matching

def get_field(event: Dict, name: str):
    """Exact key first, then a dotted path into nested objects. Returns (found, value)."""
    if name in event:
        return True, event[name]
    cur: Any = event
    for part in name.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return False, None
    return True, cur


def _wildcard_re(pattern: str, mode: str) -> "re.Pattern":
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    body = "".join(out)
    if mode == "contains":
        body = ".*" + body + ".*"
    elif mode == "startswith":
        body = body + ".*"
    elif mode == "endswith":
        body = ".*" + body
    return body


def value_matches(actual: Any, expected: Any, mods: List[str]) -> bool:
    if "exists" in mods:
        return actual is not None if bool(expected) else actual is None
    if expected is None:
        return actual is None
    if actual is None:
        return False
    if isinstance(actual, list):
        return any(value_matches(a, expected, mods) for a in actual)
    if isinstance(expected, bool) or isinstance(actual, bool):
        return str(actual).lower() == str(expected).lower()
    if isinstance(expected, (int, float)) and not mods:
        try:
            return float(actual) == float(expected)
        except (TypeError, ValueError):
            return False
    text, pat = str(actual), str(expected)
    if "re" in mods:
        flags = (re.I if "i" in mods else 0) | (re.M if "m" in mods else 0) | (re.S if "s" in mods else 0)
        return re.search(pat, text, flags) is not None
    mode = next((m for m in ("contains", "startswith", "endswith") if m in mods), "equals")
    flags = re.S if "cased" in mods else re.S | re.I
    return re.fullmatch(_wildcard_re(pat, mode), text, flags) is not None


def field_matches(event: Dict, key: str, expected: Any) -> bool:
    name, *mods = str(key).split("|")
    for m in mods:
        if m not in KNOWN_MODS:
            raise RuleError(f"modifier '{m}' is not supported by this tester")
    found, actual = get_field(event, name)
    if "exists" in mods:
        return found == bool(expected) if not isinstance(expected, list) else found
    if not found:
        actual = None
    values = expected if isinstance(expected, list) else [expected]
    if not values:
        return False
    test = all if "all" in mods else any
    return test(value_matches(actual, v, mods) for v in values)


def _keyword_hit(event: Any, word: Any) -> bool:
    if isinstance(event, dict):
        return any(_keyword_hit(v, word) for v in event.values())
    if isinstance(event, list):
        return any(_keyword_hit(v, word) for v in event)
    return event is not None and value_matches(event, word, ["contains"])


def selection_matches(event: Dict, selection: Any) -> bool:
    if isinstance(selection, dict):
        return all(field_matches(event, k, v) for k, v in selection.items())
    if isinstance(selection, list):
        if all(isinstance(x, dict) for x in selection):
            return any(selection_matches(event, x) for x in selection)
        return any(_keyword_hit(event, w) for w in selection)
    if isinstance(selection, (str, int, float)):
        return _keyword_hit(event, selection)
    raise RuleError(f"cannot evaluate selection of type {type(selection).__name__}")


# ---------------------------------------------------------------- condition parser

TOKEN_RE = re.compile(r"\s*(\(|\)|[\w*.-]+)")


def tokenize(cond: str) -> List[str]:
    pos, out = 0, []
    cond = cond.strip()
    while pos < len(cond):
        m = TOKEN_RE.match(cond, pos)
        if not m:
            raise RuleError(f"cannot parse condition near '{cond[pos:pos + 20]}'")
        out.append(m.group(1))
        pos = m.end()
    return out


class Condition:
    """Recursive descent: or < and < not < atom. Evaluates against selection results."""

    def __init__(self, text: str, names: List[str]):
        if "|" in text:
            raise RuleError("aggregation conditions (| count() ...) are not supported; test the base selection or use a SIEM")
        self.text, self.names = text, names
        self.tokens = tokenize(text)
        self.pos = 0
        self.tree = self._or()
        if self.pos != len(self.tokens):
            raise RuleError(f"unexpected '{self.tokens[self.pos]}' in condition")

    def _peek(self):
        return self.tokens[self.pos].lower() if self.pos < len(self.tokens) else None

    def _take(self):
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def _or(self):
        node = self._and()
        while self._peek() == "or":
            self._take()
            node = ("or", node, self._and())
        return node

    def _and(self):
        node = self._not()
        while self._peek() == "and":
            self._take()
            node = ("and", node, self._not())
        return node

    def _not(self):
        if self._peek() == "not":
            self._take()
            return ("not", self._not())
        return self._atom()

    def _expand(self, pattern: str) -> List[str]:
        if pattern.lower() == "them":
            return [n for n in self.names if not n.startswith("_")]
        rx = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
        hits = [n for n in self.names if rx.match(n)]
        if not hits:
            raise RuleError(f"'{pattern}' matches no selection")
        return hits

    def _atom(self):
        tok = self._peek()
        if tok is None:
            raise RuleError("condition ends early")
        if tok == "(":
            self._take()
            node = self._or()
            if self._peek() != ")":
                raise RuleError("missing ')' in condition")
            self._take()
            return node
        if (tok.isdigit() or tok in ("all", "any")) and self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1].lower() == "of":
            quant = self._take().lower()
            self._take()
            if self.pos >= len(self.tokens):
                raise RuleError("'of' needs a pattern")
            names = self._expand(self._take())
            return ("of", "all" if quant == "all" else int(quant) if quant.isdigit() else 1, names)
        name = self._take()
        if name not in self.names:
            raise RuleError(f"condition uses undefined selection '{name}'")
        return ("sel", name)

    def evaluate(self, hits: Dict[str, bool]) -> bool:
        def ev(n):
            kind = n[0]
            if kind == "sel":
                return hits[n[1]]
            if kind == "not":
                return not ev(n[1])
            if kind == "and":
                return ev(n[1]) and ev(n[2])
            if kind == "or":
                return ev(n[1]) or ev(n[2])
            count = sum(1 for s in n[2] if hits[s])
            return count == len(n[2]) if n[1] == "all" else count >= n[1]
        return ev(self.tree)


# ---------------------------------------------------------------- running rules

def compile_rule(rule: Dict) -> Dict:
    if not isinstance(rule, dict) or not isinstance(rule.get("detection"), dict):
        raise RuleError("rule has no detection block")
    det = rule["detection"]
    cond = det.get("condition")
    if cond is None:
        raise RuleError("detection has no condition")
    if isinstance(cond, list):
        cond = " or ".join(f"({c})" for c in cond)
    names = [k for k in det if k not in ("condition", "timeframe")]
    return {"title": rule.get("title"), "id": rule.get("id"), "level": rule.get("level"),
            "selections": {n: det[n] for n in names}, "condition": Condition(str(cond), names)}


def match_event(compiled: Dict, event: Dict) -> Dict:
    hits = {n: selection_matches(event, s) for n, s in compiled["selections"].items()}
    return {"match": compiled["condition"].evaluate(hits), "selections": hits}


def load_events(lines: List[str]):
    events, errors = [], []
    for no, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as err:
            errors.append(f"line {no}: {err.msg}")
            continue
        if isinstance(obj, dict):
            events.append((no, obj))
        else:
            errors.append(f"line {no}: not a JSON object")
    return events, errors


def summarize(event: Dict, limit: int = 140) -> str:
    keys = ("CommandLine", "process.command_line", "Image", "TargetImage", "message", "TaskName")
    for k in keys:
        found, v = get_field(event, k)
        if found and v:
            s = str(v)
            return (s[: limit - 3] + "...") if len(s) > limit else s
    s = json.dumps(event, sort_keys=True)
    return (s[: limit - 3] + "...") if len(s) > limit else s


def run(rules: List[Dict], events) -> List[Dict]:
    results = []
    for r in rules:
        compiled = r["compiled"]
        matches = []
        for no, ev in events:
            res = match_event(compiled, ev)
            if res["match"]:
                matches.append({"line": no, "selections": [k for k, v in res["selections"].items() if v],
                                "summary": summarize(ev)})
        results.append({"file": r["file"], "title": compiled["title"], "id": compiled["id"], "level": compiled["level"],
                        "condition": compiled["condition"].text, "matched": len(matches), "matches": matches})
    return results


def parse_expect(text: str) -> List[int]:
    if text.strip().lower() in ("none", ""):
        return []
    return sorted({int(x) for x in text.split(",") if x.strip()})


def render_text(results: List[Dict], total: int, expect=None) -> str:
    out = []
    for r in results:
        out.append(f"{r['title'] or r['file']}  [{r['level'] or '?'}]")
        out.append(f"  file: {r['file']}")
        out.append(f"  condition: {r['condition']}")
        out.append(f"  matched {r['matched']} of {total} event(s)")
        for m in r["matches"]:
            out.append(f"    line {m['line']:>3}  via {', '.join(m['selections']) or '(negation)'}  {m['summary']}")
        if expect is not None:
            got = [m["line"] for m in r["matches"]]
            out.append(f"  expect {expect or 'none'}: {'PASS' if got == expect else 'FAIL, got ' + str(got or 'none')}")
        out.append("")
    return "\n".join(out).rstrip()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Test Sigma-style rules against JSON-lines events.")
    ap.add_argument("rules", nargs="+", help="rule files or folders (YAML or JSON)")
    ap.add_argument("--events", required=True, help="JSON-lines file of events, or - for stdin")
    ap.add_argument("--expect", help="comma-separated event line numbers every rule must match exactly (or 'none'); exit 1 on mismatch")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    try:
        expect = parse_expect(args.expect) if args.expect is not None else None
    except ValueError:
        print("error: --expect takes line numbers like 2,5 or 'none'", file=sys.stderr)
        return 2
    try:
        if args.events == "-":
            raw = sys.stdin.read().splitlines()
        else:
            with open(args.events, encoding="utf-8") as fh:
                raw = fh.read().splitlines()
    except OSError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    events, errors = load_events(raw)
    if not events:
        print("error: no JSON events found" + (f" ({errors[0]})" if errors else ""), file=sys.stderr)
        return 2

    files = collect_files(args.rules)
    if not files:
        print("error: no rule files found", file=sys.stderr)
        return 2
    rules = []
    for path in files:
        try:
            docs = load_rules(path)
            for doc in docs:
                rules.append({"file": path, "compiled": compile_rule(doc)})
        except (OSError, YamlError, json.JSONDecodeError, RuleError) as err:
            print(f"error: {path}: {err}", file=sys.stderr)
            return 2
    try:
        results = run(rules, events)
    except (RuleError, re.error) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    ok = True
    if expect is not None:
        ok = all([m["line"] for m in r["matches"]] == expect for r in results)
    if args.json:
        payload = {"events": len(events), "bad_lines": errors, "rules": results}
        if expect is not None:
            payload["expect"] = expect
            payload["expect_ok"] = ok
        print(json.dumps(payload, indent=2))
    else:
        print(render_text(results, len(events), expect))
        if errors:
            print(f"\nskipped {len(errors)} bad line(s): " + "; ".join(errors[:5]))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
