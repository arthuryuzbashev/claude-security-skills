#!/usr/bin/env python3
"""Find beacon-like (regular, repeated) connections in connection logs.

Command-and-control implants usually call home on a timer: the same source
talks to the same destination and port over and over, at nearly fixed
intervals, with nearly fixed sizes. This script groups connections by
(source, destination, destination port), then scores each group on interval
regularity, size regularity, connection count and how much of the log window
it covers.

Input (auto-detected): Zeek conn.log (TSV with a #fields line), CSV with a
header, a JSON array, or JSON lines. Recognized column names:
  time:   ts, timestamp, time, start, start_time, first_seen
  source: id.orig_h, src, src_ip, source, source_ip, saddr
  dest:   id.resp_h, dst, dst_ip, dest, destination, dest_ip, daddr
  port:   id.resp_p, dport, dst_port, dest_port, destination_port, port
  bytes:  orig_bytes, bytes_out, bytes_sent, out_bytes, bytes, sent_bytes, length
Times may be epoch seconds (or ms) or ISO 8601.

Reads a saved file or stdin; never touches the network.

Usage:
  beacon_detect.py conn.log
  beacon_detect.py conns.csv --min-conns 10 --allow 192.0.2.53 --allow 10.0.0.0/8
  cat events.jsonl | beacon_detect.py - --json --fail-on medium
"""
from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

FIELDS = {
    "ts": ("ts", "timestamp", "time", "start", "start_time", "first_seen", "@timestamp"),
    "src": ("id.orig_h", "src", "src_ip", "source", "source_ip", "saddr", "client"),
    "dst": ("id.resp_h", "dst", "dst_ip", "dest", "destination", "dest_ip", "daddr", "server"),
    "dport": ("id.resp_p", "dport", "dst_port", "dest_port", "destination_port", "port"),
    "bytes": ("orig_bytes", "bytes_out", "bytes_sent", "out_bytes", "sent_bytes", "bytes", "length"),
}


class InputError(ValueError):
    pass


# ---------------------------------------------------------------- loading

def parse_time(value) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        v = float(value)
    else:
        s = str(value).strip()
        if not s or s == "-":
            return None
        try:
            v = float(s)
        except ValueError:
            try:
                dt = datetime.fromisoformat(s.replace("Z", "+00:00").replace(" ", "T", 1))
            except ValueError:
                return None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
    if v > 1e17:   # nanoseconds
        return v / 1e9
    if v > 1e14:   # microseconds
        return v / 1e6
    if v > 1e11:   # milliseconds
        return v / 1e3
    return v


def _pick(row: Dict, key: str):
    lower = {str(k).lower(): v for k, v in row.items()}
    for name in FIELDS[key]:
        v = lower.get(name)
        if v not in (None, "", "-"):
            return v
    return None


def _to_int(v) -> Optional[int]:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def normalize(rows: Iterable[Dict]) -> Tuple[List[Dict], int]:
    """Map raw rows to {ts, src, dst, dport, bytes}; return (records, skipped)."""
    out, skipped = [], 0
    for row in rows:
        if not isinstance(row, dict):
            skipped += 1
            continue
        ts = parse_time(_pick(row, "ts"))
        src, dst = _pick(row, "src"), _pick(row, "dst")
        if ts is None or src is None or dst is None:
            skipped += 1
            continue
        out.append({"ts": ts, "src": str(src), "dst": str(dst), "dport": _to_int(_pick(row, "dport")),
                    "bytes": _to_int(_pick(row, "bytes"))})
    return out, skipped


def parse_zeek(text: str) -> List[Dict]:
    fields, sep, rows = None, "\t", []
    for line in text.splitlines():
        if line.startswith("#separator"):
            raw = line.split(" ", 1)[1].strip() if " " in line else "\\x09"
            sep = bytes(raw, "ascii").decode("unicode_escape") if raw.startswith("\\x") else raw
        elif line.startswith("#fields"):
            fields = line.split(sep)[1:] if sep in line else line.split()[1:]
        elif line.startswith("#") or not line.strip():
            continue
        elif fields:
            rows.append(dict(zip(fields, line.split(sep))))
    if fields is None:
        raise InputError("Zeek log has no #fields line")
    return rows


def load_records(text: str) -> Tuple[List[Dict], int, str]:
    """Auto-detect the format and return (records, skipped, format)."""
    stripped = text.lstrip()
    if not stripped:
        raise InputError("input is empty")
    if stripped.startswith("#separator") or stripped.startswith("#fields"):
        recs, skipped = normalize(parse_zeek(text))
        return recs, skipped, "zeek"
    if stripped.startswith("["):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as err:
            raise InputError(f"bad JSON: {err}") from None
        recs, skipped = normalize(data if isinstance(data, list) else [])
        return recs, skipped, "json"
    if stripped.startswith("{"):
        rows, bad = [], 0
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                bad += 1
        recs, skipped = normalize(rows)
        return recs, skipped + bad, "jsonl"
    reader = csv.DictReader(io.StringIO(stripped))
    if not reader.fieldnames or not any(f and f.strip().lower() in FIELDS["ts"] for f in reader.fieldnames):
        raise InputError("unrecognized input: need Zeek conn.log, JSON, JSON lines, or CSV with a time column")
    recs, skipped = normalize({(k or "").strip(): v for k, v in r.items()} for r in reader)
    return recs, skipped, "csv"


# ---------------------------------------------------------------- scoring

def _allowed(host: str, allow: List) -> bool:
    for a in allow:
        if isinstance(a, str):
            if host.lower() == a.lower():
                return True
        else:
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                continue
            if ip.version == a.version and ip in a:
                return True
    return False


def parse_allow(values: List[str]) -> List:
    out = []
    for v in values or []:
        for item in v.split(","):
            item = item.strip()
            if not item:
                continue
            try:
                out.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                out.append(item)
    return out


def _cv(values: List[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = statistics.fmean(values)
    return statistics.pstdev(values) / mean if mean > 0 else 0.0


def score_group(times: List[float], sizes: List[Optional[int]], window: float) -> Dict:
    """Stats and a 0-100 beacon score for one (src, dst, port) group. Times must be sorted."""
    deltas = [b - a for a, b in zip(times, times[1:])]
    deltas = [d for d in deltas if d > 0] or [0.0]
    mean = statistics.fmean(deltas)
    median = statistics.median(deltas)
    stdev = statistics.pstdev(deltas) if len(deltas) > 1 else 0.0
    cv = stdev / mean if mean > 0 else 0.0
    mad = statistics.median([abs(d - median) for d in deltas])
    jitter = mad / median if median > 0 else 1.0
    # Interval regularity: robust jitter matters most, CV catches a few long gaps.
    interval_score = max(0.0, 1.0 - jitter / 0.3) * 0.7 + max(0.0, 1.0 - cv / 1.0) * 0.3
    known = [s for s in sizes if s is not None]
    if len(known) >= 2:
        size_cv = _cv([float(s) for s in known])
        size_score = max(0.0, 1.0 - size_cv / 0.5)
    else:
        size_cv = None
        size_score = 0.5  # unknown: neutral
    count_score = min(1.0, (len(times) - 1) / 30.0)
    span = times[-1] - times[0]
    coverage = min(1.0, span / window) if window > 0 else 0.0
    score = round(100 * (0.5 * interval_score + 0.2 * size_score + 0.15 * count_score + 0.15 * coverage))
    return {
        "connections": len(times), "first": _iso(times[0]), "last": _iso(times[-1]), "span_s": round(span, 1),
        "interval_mean_s": round(mean, 2), "interval_median_s": round(median, 2), "interval_stdev_s": round(stdev, 2),
        "interval_cv": round(cv, 3), "jitter": round(jitter, 3),
        "bytes_mean": round(statistics.fmean(known), 1) if known else None,
        "bytes_cv": round(size_cv, 3) if size_cv is not None else None,
        "coverage": round(coverage, 3), "score": score,
    }


def severity_for(score: int) -> Optional[str]:
    if score >= 80:
        return "high"
    if score >= 65:
        return "medium"
    if score >= 50:
        return "low"
    return None


def detect(records: List[Dict], min_conns: int = 6, allow: Optional[List] = None) -> Dict:
    allow = allow or []
    if not records:
        raise InputError("no usable connection records (need time, source and destination)")
    t0 = min(r["ts"] for r in records)
    t1 = max(r["ts"] for r in records)
    window = t1 - t0
    groups: Dict[Tuple[str, str, Optional[int]], List[Dict]] = defaultdict(list)
    ignored = 0
    for r in records:
        if _allowed(r["src"], allow) or _allowed(r["dst"], allow):
            ignored += 1
            continue
        groups[(r["src"], r["dst"], r["dport"])].append(r)
    candidates = []
    for (src, dst, port), recs in groups.items():
        if len(recs) < min_conns:
            continue
        recs.sort(key=lambda r: r["ts"])
        stats = score_group([r["ts"] for r in recs], [r["bytes"] for r in recs], window)
        stats.update({"src": src, "dst": dst, "dport": port})
        candidates.append(stats)
    candidates.sort(key=lambda c: (-c["score"], -c["connections"]))
    findings = []
    for c in candidates:
        sev = severity_for(c["score"])
        if not sev:
            continue
        target = f"{c['dst']}:{c['dport']}" if c["dport"] is not None else c["dst"]
        size = f", ~{c['bytes_mean']:.0f} bytes out (CV {c['bytes_cv']})" if c["bytes_mean"] is not None else ""
        findings.append({
            "id": "BCN-001", "severity": sev,
            "title": f"Beacon-like traffic {c['src']} -> {target}",
            "detail": (f"Score {c['score']}/100: {c['connections']} connections every ~{c['interval_median_s']:g}s "
                       f"(jitter {c['jitter']:.0%}, interval CV {c['interval_cv']}){size}, "
                       f"covering {c['coverage']:.0%} of the log window."),
            "fix": ("Find the process on the source host that opens these connections (EDR, netstat/lsof at the right "
                    "time), check the destination's reputation and owner, and allow-list it here if it is a known "
                    "updater, monitor or telemetry service."),
            "location": f"{c['src']} -> {target}",
        })
    return {"records": len(records), "ignored_by_allow": ignored, "groups": len(groups),
            "window_s": round(window, 1), "candidates": candidates, "findings": findings}


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def render_text(r: Dict, fmt: str, skipped: int) -> str:
    lines = [f"Input: {fmt}, {r['records']} connections, {r['groups']} groups, window {r['window_s']} s"
             + (f", {skipped} rows skipped" if skipped else "")
             + (f", {r['ignored_by_allow']} allow-listed" if r["ignored_by_allow"] else ""), ""]
    if r["candidates"]:
        lines.append(f"{'score':>5}  {'conns':>5}  {'every':>8}  {'jitter':>6}  {'bytes':>8}  flow")
        for c in r["candidates"][:25]:
            b = f"{c['bytes_mean']:.0f}" if c["bytes_mean"] is not None else "-"
            port = f":{c['dport']}" if c["dport"] is not None else ""
            lines.append(f"{c['score']:>5}  {c['connections']:>5}  {c['interval_median_s']:>7g}s  "
                         f"{c['jitter']:>6.0%}  {b:>8}  {c['src']} -> {c['dst']}{port}")
        lines.append("")
    else:
        lines.append("No group reached the minimum connection count.")
    if not r["findings"]:
        lines.append("No beacon-like traffic found.")
    for f in r["findings"]:
        lines.append(f"[{f['severity'].upper():8}] {f['id']}  {f['title']}")
        lines.append(f"           {f['detail']}")
    if r["findings"]:
        lines.append("")
        lines.append("next: " + r["findings"][0]["fix"])
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Score connection logs for beacon-like (C2 check-in) patterns.")
    ap.add_argument("input", help="Zeek conn.log, CSV, JSON or JSON lines file; '-' reads stdin")
    ap.add_argument("--min-conns", type=int, default=6, help="ignore flows with fewer connections (default 6)")
    ap.add_argument("--allow", action="append", default=[],
                    help="host, IP or CIDR to ignore (repeat or comma-separate), e.g. known updaters")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)
    try:
        text = sys.stdin.read() if args.input == "-" else Path(args.input).read_text(encoding="utf-8", errors="replace")
        records, skipped, fmt = load_records(text)
        r = detect(records, max(3, args.min_conns), parse_allow(args.allow))
    except (OSError, InputError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    if args.json:
        out = dict(r)
        out.update({"format": fmt, "skipped": skipped})
        print(json.dumps(out, indent=2))
    else:
        print(render_text(r, fmt, skipped))
    if args.fail_on != "never":
        t = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= t for f in r["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
