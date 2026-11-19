#!/usr/bin/env python3
"""Read-only macOS baseline audit: FileVault, Gatekeeper, SIP, firewall, updates, screen lock, sharing.

Runs a handful of read-only system commands (status queries only, never a setter) and
parses their output. Saved outputs can be graded offline with --from-dir, so a user can
collect on one Mac and audit anywhere.

Usage:
  macos_audit.py                         # this Mac, read-only commands
  macos_audit.py --output saved/         # also save each raw output to saved/<check>.txt
  macos_audit.py --from-dir saved/ --json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"
NEEDS_ADMIN = re.compile(r"administrator access|must be run as root|operation not permitted|requires root", re.I)

Result = Tuple[str, str, List[Dict[str, str]]]  # (status, detail, findings)


def finding(fid, severity, title, detail, fix):
    return {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}


# ---------------------------------------------------------------- parsers (pure, fed canned output in tests)

def parse_filevault(text: str) -> Result:
    t = text.lower()
    if "filevault is on" in t:
        return "pass", "FileVault is on", []
    if "decryption in progress" in t:
        return "fail", "FileVault is being turned off", [finding(
            "MAC-001", "high", "FileVault is being decrypted",
            "The disk is on its way to being readable by anyone who takes the Mac.",
            "System Settings > Privacy & Security > FileVault > Turn On, and find out who turned it off.")]
    if "encryption in progress" in t:
        return "pass", "FileVault encryption in progress", []
    if "filevault is off" in t:
        return "fail", "FileVault is off", [finding(
            "MAC-001", "high", "FileVault disk encryption is off",
            "A lost or stolen Mac gives full access to every file, saved session and keychain backup on disk.",
            "System Settings > Privacy & Security > FileVault > Turn On (or `sudo fdesetup enable`). Escrow the recovery key via MDM.")]
    return "unknown", text.strip()[:120] or "no output", []


def parse_gatekeeper(text: str) -> Result:
    t = text.lower()
    if "assessments enabled" in t:
        return "pass", "Gatekeeper is on", []
    if "assessments disabled" in t:
        return "fail", "Gatekeeper is off", [finding(
            "MAC-002", "high", "Gatekeeper is disabled",
            "Unsigned and un-notarized apps run without any check, which is how most Mac malware gets in.",
            "`sudo spctl --global-enable` (older macOS: `sudo spctl --master-enable`).")]
    return "unknown", text.strip()[:120] or "no output", []


def parse_sip(text: str) -> Result:
    t = text.lower()
    if "custom configuration" in t or "unknown" in t:
        return "fail", "SIP is partly disabled", [finding(
            "MAC-003", "medium", "System Integrity Protection has a custom configuration",
            "Some SIP protections are switched off, so malware with root can tamper with parts of the system.",
            "Boot to Recovery, run `csrutil clear` (or `csrutil enable`), restart.")]
    if "status: enabled" in t:
        return "pass", "SIP is on", []
    if "status: disabled" in t:
        return "fail", "SIP is off", [finding(
            "MAC-003", "high", "System Integrity Protection is disabled",
            "Root (and malware running as root) can modify system files, kernel extensions and protected apps.",
            "Boot to Recovery (hold power on Apple silicon), Terminal: `csrutil enable`, restart.")]
    return "unknown", text.strip()[:120] or "no output", []


def parse_firewall(text: str) -> Result:
    t = text.lower()
    m = re.search(r"state\s*=\s*(\d)", t)
    if (m and m.group(1) in ("1", "2")) or "firewall is enabled" in t or "blocking all" in t:
        return "pass", "Application firewall is on", []
    if (m and m.group(1) == "0") or "firewall is disabled" in t:
        return "fail", "Application firewall is off", [finding(
            "MAC-004", "medium", "macOS application firewall is off",
            "Any app or service that listens on the network is reachable from the local network (cafe, hotel, office Wi-Fi).",
            "System Settings > Network > Firewall > On (or `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on`).")]
    return "unknown", text.strip()[:120] or "no output", []


def parse_stealth(text: str) -> Result:
    t = text.lower()
    if re.search(r"stealth mode (is )?(on|enabled)", t):
        return "pass", "Stealth mode is on", []
    if re.search(r"stealth mode (is )?(off|disabled)", t):
        return "fail", "Stealth mode is off", [finding(
            "MAC-005", "low", "Firewall stealth mode is off",
            "The Mac answers pings and probes to closed ports, which makes it easy to find on a network.",
            "System Settings > Network > Firewall > Options > Enable stealth mode.")]
    return "unknown", text.strip()[:120] or "no output", []


def parse_defaults_dict(text: str) -> Dict[str, str]:
    """Pull top-level `Key = value;` pairs out of `defaults read` output."""
    return {m.group(1): m.group(2).strip('"') for m in re.finditer(r"^\s{4}\"?([A-Za-z]+)\"?\s*=\s*([^;{(]+);", text, re.M)}


def parse_autoupdate(text: str) -> Result:
    if "does not exist" in text:
        return "pass", "No overrides; macOS defaults (automatic checks on)", []
    values = parse_defaults_dict(text)
    if not values:
        return "unknown", text.strip()[:120] or "no output", []
    out = []
    if values.get("AutomaticCheckEnabled") == "0":
        out.append(finding("MAC-006", "medium", "Automatic update checks are off",
                           "The Mac will not even notice that security updates exist.",
                           "System Settings > General > Software Update > Automatic Updates: turn on Check for updates."))
    if values.get("CriticalUpdateInstall") == "0":
        out.append(finding("MAC-013", "medium", "Security responses and system files are not installed automatically",
                           "Rapid security fixes (XProtect, background security updates) wait for a manual install.",
                           "Automatic Updates: turn on Install Security Responses and system files."))
    if values.get("ConfigDataInstall") == "0":
        out.append(finding("MAC-014", "low", "Security configuration data updates are off",
                           "XProtect and malware-removal definitions do not update automatically.",
                           "`sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true`"))
    if values.get("AutomaticDownload") == "0":
        out.append(finding("MAC-015", "low", "Updates are not downloaded automatically",
                           "Patches sit unapplied longer because users have to start the download.",
                           "Automatic Updates: turn on Download new updates when available."))
    if values.get("AutomaticallyInstallMacOSUpdates") == "0":
        out.append(finding("MAC-016", "low", "macOS updates are not installed automatically",
                           "Downloaded macOS point releases (which carry most security fixes) wait for someone to "
                           "click Install. CIS macOS benchmarks expect this on.",
                           "Automatic Updates: turn on Install macOS updates."))
    status = "fail" if out else "pass"
    on = ", ".join(f"{k}={values[k]}" for k in ("AutomaticCheckEnabled", "AutomaticDownload", "CriticalUpdateInstall",
                                                 "ConfigDataInstall", "AutomaticallyInstallMacOSUpdates") if k in values)
    return status, on or "keys at defaults", out


def parse_screenlock(text: str) -> Result:
    t = text.lower()
    if "screenlock is off" in t:
        return "fail", "Screen lock is off", [finding(
            "MAC-007", "medium", "No password required after sleep or screen saver",
            "Anyone at an unattended Mac gets the logged-in session.",
            "System Settings > Lock Screen > Require password after screen saver begins or display is turned off: Immediately.")]
    if "delay is immediate" in t:
        return "pass", "Password required immediately", []
    m = re.search(r"delay is (\d+) seconds", t)
    if m:
        secs = int(m.group(1))
        if secs <= 5:
            return "pass", f"Password required after {secs}s", []
        return "fail", f"Password required after {secs}s", [finding(
            "MAC-007", "low", f"Screen lock grace period is {secs} seconds",
            "The session stays open that long after the screen saver starts.",
            "Lock Screen > Require password: Immediately (or within 5 seconds).")]
    if NEEDS_ADMIN.search(text):
        return "needs sudo", "Run with sudo to read this setting", []
    return "unknown", text.strip()[:120] or "no output", []


def parse_remotelogin(text: str) -> Result:
    t = text.lower()
    if NEEDS_ADMIN.search(text):
        return "needs sudo", "systemsetup needs admin rights; the sharing check covers this partly", []
    if "remote login: on" in t:
        return "fail", "Remote Login (SSH) is on", [finding(
            "MAC-008", "medium", "Remote Login (SSH) is on",
            "The Mac accepts SSH logins from the network. Fine on a managed build box, risky on a laptop.",
            "System Settings > General > Sharing > Remote Login: off, or limit it to specific users and keys only.")]
    if "remote login: off" in t:
        return "pass", "Remote Login is off", []
    return "unknown", text.strip()[:120] or "no output", []


SHARING_SERVICES = {
    "com.apple.screensharing": ("MAC-009", "medium", "Screen Sharing", "Remote screen control over VNC."),
    "com.openssh.sshd": ("MAC-008", "medium", "Remote Login (SSH)", "SSH logins from the network."),
    "com.apple.smbd": ("MAC-011", "low", "File Sharing (SMB)", "Shared folders reachable over SMB."),
    "com.apple.AEServer": ("MAC-012", "medium", "Remote Apple Events", "Other Macs can send Apple Events to apps on this Mac."),
}


def parse_sharing(text: str) -> Result:
    """`launchctl print-disabled system`: lists overrides. `=> enabled` (or old-style `=> false`) means switched on."""
    if "disabled services" not in text and "=>" not in text:
        return "unknown", text.strip()[:120] or "no output", []
    out, on = [], []
    for m in re.finditer(r'"([^"]+)"\s*=>\s*(\w+)', text):
        label, state = m.group(1), m.group(2).lower()
        if label in SHARING_SERVICES and state in ("enabled", "false"):
            fid, sev, name, what = SHARING_SERVICES[label]
            on.append(name)
            out.append(finding(fid, sev, f"{name} is on", f"{what} Turn off if nobody needs it on this Mac.",
                               f"System Settings > General > Sharing > {name.split(' (')[0]}: off."))
    return ("fail" if out else "pass"), ("On: " + ", ".join(on)) if on else "No sharing services switched on", out


def parse_guest(text: str) -> Result:
    t = text.strip().lower()
    if t == "1" or t == "true":
        return "fail", "Guest account is on", [finding(
            "MAC-010", "low", "Guest account is enabled",
            "Anyone can log in without a password (data is wiped at logout, but the Mac and network are reachable).",
            "System Settings > Users & Groups > Guest User: off.")]
    if t in ("0", "false") or "does not exist" in t:
        return "pass", "Guest account is off", []
    return "unknown", text.strip()[:120] or "no output", []


CHECKS = [
    # key, label, command, parser
    ("filevault", "FileVault", ["fdesetup", "status"], parse_filevault),
    ("gatekeeper", "Gatekeeper", ["spctl", "--status"], parse_gatekeeper),
    ("sip", "System Integrity Protection", ["csrutil", "status"], parse_sip),
    ("firewall", "Application firewall", [SOCKETFILTERFW, "--getglobalstate"], parse_firewall),
    ("stealth", "Firewall stealth mode", [SOCKETFILTERFW, "--getstealthmode"], parse_stealth),
    ("autoupdate", "Automatic updates", ["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate"], parse_autoupdate),
    ("screenlock", "Screen lock", ["sysadminctl", "-screenLock", "status"], parse_screenlock),
    ("remotelogin", "Remote Login", ["systemsetup", "-getremotelogin"], parse_remotelogin),
    ("sharing", "Sharing services", ["launchctl", "print-disabled", "system"], parse_sharing),
    ("guest", "Guest account", ["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"], parse_guest),
]


def run_command(cmd: List[str], timeout: float = 15.0) -> Optional[str]:
    """Run a read-only status command, return stdout+stderr (some tools print status on stderr)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return (proc.stdout or "") + (proc.stderr or "")


def collect_live(save_dir: Optional[str] = None) -> Dict[str, Optional[str]]:
    outputs = {}
    for key, _, cmd, _ in CHECKS:
        outputs[key] = run_command(cmd)
        if save_dir and outputs[key] is not None:
            with open(os.path.join(save_dir, f"{key}.txt"), "w", encoding="utf-8") as fh:
                fh.write(outputs[key])
    return outputs


def collect_dir(directory: str) -> Dict[str, Optional[str]]:
    outputs = {}
    for key, _, _, _ in CHECKS:
        path = os.path.join(directory, f"{key}.txt")
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                outputs[key] = fh.read()
        except OSError:
            outputs[key] = None
    return outputs


def audit(outputs: Dict[str, Optional[str]]) -> Dict[str, object]:
    checks, findings, seen = [], [], set()
    for key, label, cmd, parser in CHECKS:
        text = outputs.get(key)
        if text is None:
            checks.append({"check": key, "label": label, "status": "not collected", "detail": "no output"})
            continue
        status, detail, found = parser(text)
        if status == "unknown" and NEEDS_ADMIN.search(text):
            status, detail = "needs sudo", "needs admin rights"
        checks.append({"check": key, "label": label, "status": status, "detail": detail})
        for f in found:
            sig = (f["id"], f["title"])
            if sig not in seen:  # Remote Login can show up in two checks
                seen.add(sig)
                findings.append(f)
    findings.sort(key=lambda f: -SEVERITY_ORDER.index(f["severity"]))
    return {"checks": checks, "findings": findings}


def render_text(res, source) -> str:
    lines = [f"macOS audit ({source}): {len(res['findings'])} finding(s)", ""]
    for c in res["checks"]:
        lines.append(f"  {c['status'].upper():13} {c['label']}: {c['detail']}")
    lines.append("")
    if not res["findings"]:
        lines.append("No issues found.")
    for f in res["findings"]:
        lines.append(f"[{f['severity'].upper():8}] {f['id']}  {f['title']}")
        lines.append(f"           {f['detail']}")
        lines.append(f"           fix: {f['fix']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Read-only macOS hardening audit.")
    ap.add_argument("--from-dir", help="grade saved outputs (<check>.txt files) instead of running commands")
    ap.add_argument("--output", help="live mode: also save each raw command output to this directory")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)

    if args.from_dir:
        if not os.path.isdir(args.from_dir):
            print(f"error: {args.from_dir} is not a directory", file=sys.stderr)
            return 2
        outputs, source = collect_dir(args.from_dir), args.from_dir
        if all(v is None for v in outputs.values()):
            print(f"error: no <check>.txt files in {args.from_dir}", file=sys.stderr)
            return 2
    else:
        if sys.platform != "darwin":
            print("error: live mode needs macOS; use --from-dir with saved outputs", file=sys.stderr)
            return 2
        if args.output:
            os.makedirs(args.output, exist_ok=True)
        outputs, source = collect_live(args.output), "this Mac"

    res = audit(outputs)
    print(json.dumps({"source": source, **res}, indent=2) if args.json else render_text(res, source))
    if args.fail_on != "never":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= threshold for f in res["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
