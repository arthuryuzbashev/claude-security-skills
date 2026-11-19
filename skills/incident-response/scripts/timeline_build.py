#!/usr/bin/env python3
"""Merge events from CSV, JSON lines and syslog-style logs into one UTC timeline.

Every input is read as text and never modified. Timestamps are normalized to
UTC; naive timestamps are treated as UTC unless --tz-offset says otherwise.

Supported timestamp shapes:
  ISO 8601           2026-03-04T10:15:30Z, 2026-03-04 10:15:30.123+02:00
  epoch              1772619330 (s), 1772619330123 (ms), 1772619330123456 (us)
  Windows FILETIME   133855... (100 ns ticks since 1601, 18 digits)
  syslog (BSD)       Mar  4 10:15:30  (needs a year: --year, default current UTC year)
  Windows / US       3/4/2026 10:15:30 AM  (month first; --dayfirst for 4/3/2026)
  Apache / nginx     [04/Mar/2026:10:15:30 +0000]

Usage:
  timeline_build.py auth.log events.csv cloudtrail.jsonl
  timeline_build.py auth.log --year 2026 --from 2026-03-04T00:00 --to 2026-03-05
  timeline_build.py *.log --keyword sshd --keyword sudo --format csv --output timeline.csv
  timeline_build.py events.csv --time-field TimeCreated --tz-offset +04:00 --format json
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

TIME_FIELDS = ["@timestamp", "timestamp", "time", "ts", "datetime", "date_time", "eventtime",
               "event_time", "timecreated", "time_created", "_time", "date", "created", "created_at",
               "time_generated", "timegenerated", "utc_time", "utctime", "start_time", "starttime"]
HOST_FIELDS = ["host", "hostname", "computer", "computername", "machine", "device", "src", "source_ip",
               "sourceipaddress", "client_ip", "clientip", "ip", "id.orig_h"]
MESSAGE_FIELDS = ["message", "msg", "event", "eventname", "description", "action", "activity", "log"]

MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], start=1)}

ISO_RE = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})[T ](?P<time>\d{2}:\d{2}(?::\d{2})?)(?P<frac>[.,]\d{1,9})?"
    r"\s*(?P<tz>Z|z|UTC|[+-]\d{2}:?\d{2})?")
SYSLOG_RE = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})(?P<frac>\.\d+)?\s*")
CLF_RE = re.compile(r"\[?(?P<day>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):(?P<time>\d{2}:\d{2}:\d{2})\s*(?P<tz>[+-]\d{4})?\]?")
US_RE = re.compile(r"(?P<a>\d{1,2})/(?P<b>\d{1,2})/(?P<year>\d{4})[ ,T]+(?P<time>\d{1,2}:\d{2}(?::\d{2})?)(?P<frac>\.\d+)?"
                   r"\s*(?P<ampm>[AaPp][Mm])?")
EPOCH_RE = re.compile(r"^\d{9,18}(\.\d+)?$")
FILETIME_EPOCH_DIFF = 11644473600  # seconds between 1601-01-01 and 1970-01-01


class ParseError(ValueError):
    pass


def parse_offset(text: Optional[str]) -> timezone:
    """'+04:00', '-0500', 'Z', 'UTC' -> timezone."""
    if not text or text.upper() in ("Z", "UTC"):
        return timezone.utc
    m = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", text.strip())
    if not m:
        raise ParseError(f"bad UTC offset: {text!r}")
    delta = timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))
    return timezone(delta if m.group(1) == "+" else -delta)


def _frac(text: Optional[str]) -> int:
    """Fraction like '.123456789' -> microseconds."""
    if not text:
        return 0
    digits = text[1:][:6].ljust(6, "0")
    return int(digits)


def parse_timestamp(value, year: Optional[int] = None, default_tz: timezone = timezone.utc,
                    dayfirst: bool = False) -> Optional[datetime]:
    """Parse one timestamp in any supported shape. Returns an aware UTC datetime or None."""
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _from_epoch(float(value))
    text = str(value).strip()
    if not text:
        return None
    if EPOCH_RE.match(text):
        return _from_epoch(float(text))
    m = ISO_RE.search(text)
    if m and m.start() <= 2:
        t = m.group("time")
        if len(t) == 5:
            t += ":00"
        dt = datetime.strptime(f"{m.group('date')} {t}", "%Y-%m-%d %H:%M:%S")
        dt = dt.replace(microsecond=_frac(m.group("frac") and "." + m.group("frac")[1:]))
        tz = parse_offset(m.group("tz")) if m.group("tz") else default_tz
        return dt.replace(tzinfo=tz).astimezone(timezone.utc)
    m = CLF_RE.search(text)
    if m:
        mon = MONTHS.get(m.group("mon").lower())
        if mon:
            h, mi, s = (int(x) for x in m.group("time").split(":"))
            dt = datetime(int(m.group("year")), mon, int(m.group("day")), h, mi, s)
            tz = parse_offset(m.group("tz")) if m.group("tz") else default_tz
            return dt.replace(tzinfo=tz).astimezone(timezone.utc)
    m = US_RE.match(text)
    if m:
        a, b = int(m.group("a")), int(m.group("b"))
        month, day = (b, a) if dayfirst else (a, b)
        parts = [int(x) for x in m.group("time").split(":")] + [0]
        h, mi, s = parts[0], parts[1], parts[2]
        ampm = (m.group("ampm") or "").lower()
        if ampm == "pm" and h < 12:
            h += 12
        elif ampm == "am" and h == 12:
            h = 0
        try:
            dt = datetime(int(m.group("year")), month, day, h, mi, s, _frac(m.group("frac")))
        except ValueError:
            return None
        return dt.replace(tzinfo=default_tz).astimezone(timezone.utc)
    m = SYSLOG_RE.match(text)
    if m:
        mon = MONTHS.get(m.group("mon").lower())
        if mon:
            h, mi, s = (int(x) for x in m.group("time").split(":"))
            y = year or datetime.now(timezone.utc).year
            try:
                dt = datetime(y, mon, int(m.group("day")), h, mi, s, _frac(m.group("frac")))
            except ValueError:
                return None
            return dt.replace(tzinfo=default_tz).astimezone(timezone.utc)
    return None


def _from_epoch(num: float) -> Optional[datetime]:
    if num >= 1e17:            # Windows FILETIME, 100 ns ticks since 1601
        num = num / 1e7 - FILETIME_EPOCH_DIFF
    elif num >= 1e14:          # microseconds
        num /= 1e6
    elif num >= 1e11:          # milliseconds
        num /= 1e3
    try:
        return datetime.fromtimestamp(num, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _lookup(record: Dict, wanted: Iterable[str]) -> Tuple[Optional[str], object]:
    """Case-insensitive field lookup, supports dotted paths into nested dicts."""
    lower = {str(k).lower(): k for k in record}
    for name in wanted:
        key = lower.get(name.lower())
        if key is not None and record[key] not in (None, "", "-"):
            return key, record[key]
        if "." in name:
            cur = record
            for part in name.split("."):
                if not isinstance(cur, dict):
                    cur = None
                    break
                low = {str(k).lower(): k for k in cur}
                cur = cur.get(low.get(part.lower()))
            if cur not in (None, "", "-"):
                return name, cur
    return None, None


def _flatten(record: Dict, skip: Iterable[str]) -> str:
    skip = {s for s in skip if s}
    parts = []
    for k, v in record.items():
        if k in skip or v in (None, "", "-"):
            continue
        if isinstance(v, (dict, list)):
            v = json.dumps(v, separators=(",", ":"), sort_keys=True)
        parts.append(f"{k}={v}")
    return " ".join(parts)


SECRET_PATTERNS = [
    re.compile(r"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)[\"']?\s*[=:]\s*[\"']?)([^\s\"'&,;|}]{4,})"),
    re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)(\S{4,})"),
    re.compile(r"()\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
    re.compile(r"()\b(gh[pousr]_[A-Za-z0-9]{20,}|xox[abpr]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{10,})\b"),
]


def mask_secrets(text: str) -> str:
    """Keep the first 4 chars of anything that looks like a credential."""
    for pat in SECRET_PATTERNS:
        text = pat.sub(lambda m: m.group(1) + m.group(2)[:4] + "...", text)
    return text


def _event(dt: datetime, source: str, host: str, message: str, raw_time: str) -> Dict:
    return {"time": dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z", "epoch": round(dt.timestamp(), 6),
            "source": source, "host": host or "", "message": mask_secrets(message.strip()),
            "raw_time": str(raw_time)}


def records_to_events(records: Iterable[Dict], source: str, opts: Dict) -> Tuple[List[Dict], int]:
    events, skipped = [], 0
    fields = [opts["time_field"]] if opts.get("time_field") else TIME_FIELDS
    for rec in records:
        if not isinstance(rec, dict):
            skipped += 1
            continue
        tkey, tval = _lookup(rec, fields)
        dt = parse_timestamp(tval, opts.get("year"), opts["tz"], opts.get("dayfirst", False)) if tkey else None
        if dt is None:
            skipped += 1
            continue
        hkey, hval = _lookup(rec, HOST_FIELDS)
        mkey, mval = _lookup(rec, MESSAGE_FIELDS)
        rest = _flatten(rec, [tkey, hkey, mkey])
        message = (f"{mval} | {rest}" if mval and rest else str(mval or rest))
        events.append(_event(dt, source, str(hval or ""), message, tval))
    return events, skipped


SYSLOG_LINE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?P<host>\S+)\s+(?P<msg>.*)$")
RFC5424_LINE = re.compile(r"^(?:<\d+>\d?\s*)?(?P<ts>\d{4}-\d{2}-\d{2}T\S+)\s+(?P<host>\S+)\s+(?P<msg>.*)$")


def text_to_events(text: str, source: str, opts: Dict) -> Tuple[List[Dict], int]:
    """Syslog (BSD and RFC 5424), web access logs and any line that carries a timestamp."""
    events, skipped = [], 0
    for line in text.splitlines():
        if not line.strip():
            continue
        m = SYSLOG_LINE.match(line) or RFC5424_LINE.match(line)
        if m:
            dt = parse_timestamp(m.group("ts"), opts.get("year"), opts["tz"])
            if dt:
                events.append(_event(dt, source, m.group("host"), m.group("msg"), m.group("ts")))
                continue
        clf = CLF_RE.search(line)
        if clf:
            dt = parse_timestamp(clf.group(0), opts.get("year"), opts["tz"])
            if dt:
                host = line.split(None, 1)[0]
                events.append(_event(dt, source, host, line[clf.end():].strip(), clf.group(0)))
                continue
        dt = parse_timestamp(line, opts.get("year"), opts["tz"], opts.get("dayfirst", False))
        if dt:
            iso = ISO_RE.match(line) or US_RE.match(line)
            rest = line[iso.end():] if iso else line
            events.append(_event(dt, source, "", rest.strip(" \t,;|-"), iso.group(0) if iso else ""))
        else:
            skipped += 1
    return events, skipped


def detect_format(text: str, name: str = "") -> str:
    lower = name.lower()
    stripped = text.lstrip()
    if lower.endswith((".jsonl", ".ndjson", ".json")) or stripped.startswith(("{", "[")):
        return "json"
    if lower.endswith((".csv", ".tsv")):
        return "csv"
    first = stripped.splitlines()[0] if stripped else ""
    for delim in (",", "\t"):
        cells = [c.strip().strip('"').lower() for c in first.split(delim)]
        if len(cells) >= 3 and any(c in TIME_FIELDS for c in cells):
            return "csv"
    return "text"


def load_events(text: str, source: str, opts: Dict, fmt: str = "auto") -> Tuple[List[Dict], int]:
    fmt = detect_format(text, source) if fmt == "auto" else fmt
    if fmt == "json":
        stripped = text.strip()
        if stripped.startswith("["):
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError as err:
                raise ParseError(f"{source}: invalid JSON: {err}")
            if isinstance(data, dict):
                data = data.get("Records") or data.get("records") or data.get("events") or [data]
            return records_to_events(data, source, opts)
        records, bad = [], 0
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            if isinstance(obj, dict) and isinstance(obj.get("Records"), list):  # CloudTrail file
                records.extend(obj["Records"])
            else:
                records.append(obj)
        events, skipped = records_to_events(records, source, opts)
        return events, skipped + bad
    if fmt == "csv":
        delim = "\t" if source.lower().endswith(".tsv") or text.split("\n", 1)[0].count("\t") > 1 else ","
        reader = csv.DictReader(io.StringIO(text), delimiter=delim)
        return records_to_events(list(reader), source, opts)
    return text_to_events(text, source, opts)


def build_timeline(inputs: List[Tuple[str, str]], opts: Dict, start: Optional[datetime] = None,
                   end: Optional[datetime] = None, keywords: Optional[List[str]] = None,
                   fmt: str = "auto") -> Tuple[List[Dict], Dict[str, int]]:
    """inputs: list of (source_name, text). Returns (sorted events, skipped lines per source)."""
    events, skipped = [], {}
    for name, text in inputs:
        evs, sk = load_events(text, name, opts, fmt)
        events.extend(evs)
        skipped[name] = sk
    if start:
        events = [e for e in events if e["epoch"] >= start.timestamp()]
    if end:
        events = [e for e in events if e["epoch"] <= end.timestamp()]
    if keywords:
        kws = [k.lower() for k in keywords]
        events = [e for e in events if any(k in (e["message"] + " " + e["host"]).lower() for k in kws)]
    events.sort(key=lambda e: (e["epoch"], e["source"]))
    return events, skipped


def _md_cell(text: str, limit: int = 220) -> str:
    text = text.replace("|", "\\|").replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def render(events: List[Dict], skipped: Dict[str, int], fmt: str) -> str:
    if fmt == "json":
        return json.dumps({"count": len(events), "sources": sorted(skipped), "skipped": skipped,
                           "events": events}, indent=2)
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["time_utc", "source", "host", "message", "raw_time"])
        for e in events:
            w.writerow([e["time"], e["source"], e["host"], e["message"], e["raw_time"]])
        return buf.getvalue().rstrip("\n")
    lines = ["| Time (UTC) | Source | Host | Event |", "|---|---|---|---|"]
    for e in events:
        lines.append(f"| {e['time']} | {_md_cell(e['source'], 40)} | {_md_cell(e['host'], 40)} | {_md_cell(e['message'])} |")
    lines.append("")
    lines.append(f"{len(events)} event(s) from {len(skipped)} source(s)")
    return "\n".join(lines)


def parse_bound(text: Optional[str], tz: timezone) -> Optional[datetime]:
    if not text:
        return None
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        text += "T00:00:00"
    dt = parse_timestamp(text, default_tz=tz)
    if dt is None:
        raise ParseError(f"cannot parse time bound {text!r}")
    return dt


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Merge logs into one UTC-sorted incident timeline (read-only).")
    ap.add_argument("inputs", nargs="+", help="log files (CSV, JSON / JSON lines, syslog, access logs); '-' for stdin")
    ap.add_argument("--format", choices=["md", "csv", "json"], default="md", help="output format (default md table)")
    ap.add_argument("--input-format", choices=["auto", "csv", "json", "text"], default="auto",
                    help="force how inputs are parsed (default: detect per file)")
    ap.add_argument("--from", dest="start", help="keep events at or after this time (ISO 8601, UTC unless offset)")
    ap.add_argument("--to", dest="end", help="keep events at or before this time")
    ap.add_argument("--keyword", action="append", default=[], help="keep events containing this text (repeatable, any match)")
    ap.add_argument("--year", type=int, help="year for syslog lines without one (default: current UTC year)")
    ap.add_argument("--tz-offset", default="+00:00", help="offset of naive timestamps, e.g. +04:00 (default UTC)")
    ap.add_argument("--dayfirst", action="store_true", help="read 4/3/2026 as 4 March, not April 3")
    ap.add_argument("--time-field", help="CSV/JSON field holding the timestamp (default: auto-detect)")
    ap.add_argument("--output", help="write the timeline here instead of stdout")
    args = ap.parse_args(argv)

    try:
        tz = parse_offset(args.tz_offset)
        start, end = parse_bound(args.start, tz), parse_bound(args.end, tz)
        inputs = []
        for path in args.inputs:
            if path == "-":
                inputs.append(("stdin", sys.stdin.read()))
            else:
                inputs.append((Path(path).name, Path(path).read_text(encoding="utf-8", errors="replace")))
        opts = {"year": args.year, "tz": tz, "dayfirst": args.dayfirst, "time_field": args.time_field}
        events, skipped = build_timeline(inputs, opts, start, end, args.keyword, args.input_format)
    except (OSError, ParseError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    if not events and not any(skipped.values()) and not (start or end or args.keyword):
        print("error: no events found in input", file=sys.stderr)
        return 2
    for name, count in skipped.items():
        if count:
            print(f"note: {name}: {count} line(s) without a readable timestamp were skipped", file=sys.stderr)

    out = render(events, skipped, args.format)
    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
        print(f"wrote {len(events)} event(s) to {args.output}", file=sys.stderr)
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
