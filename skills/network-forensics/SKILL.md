---
name: network-forensics
description: Offline network forensics on saved packet captures and connection logs, no tshark or scapy needed. Summarizes pcap/pcapng files (top talkers, conversations, protocols, ports, DNS queries and NXDOMAINs, HTTP Host and User-Agent, TLS SNI) and flags DNS tunneling or DGA-looking names, suspicious ports like 4444, HTTP straight to an IP, scripted clients and port scans. Scores Zeek conn.log, CSV or JSON connection records for C2 beaconing (regular intervals, steady sizes). Use whenever someone shares a .pcap/.pcapng, Zeek or firewall/NetFlow export, asks "what is this host talking to", "is this C2", "find beacons", "is someone exfiltrating over DNS", "what happened on the wire", or needs network IOCs for an incident.
---

# Network Forensics

Turn a capture or a connection log into "who talked to whom, how, and what looks wrong", with the evidence to back each claim.

## When to use

- An incident responder hands over a pcap from a sensor, a laptop or a cloud mirror
- A host is suspected of command-and-control (C2) and someone exported Zeek, firewall or flow logs
- Checking for DNS tunneling, DGA lookups, scans or cleartext downloads
- Pulling network IOCs (IPs, domains, SNI, User-Agents) for blocking and hunting

## Ground rules

- Analyze saved files only. Both scripts read a file or stdin; neither captures, replays nor sends packets. Live capture (tcpdump, Wireshark) needs the network owner's approval and the user runs it, not you
- Captures can hold passwords, cookies, session tokens and personal data. Keep them in the case folder, share hashes and summaries rather than the file, and mask any credential you quote to its first 4 chars
- Findings are leads, not verdicts. CDNs, anti-virus cloud lookups, NTP, update checks and monitoring agents all look odd at times. Confirm with a second source (EDR process data, DNS logs, proxy logs) before calling something malicious
- Do not contact suspicious infrastructure to "check" it (no browsing, curling or port scanning the C2 IP). Use passive sources: threat intel, passive DNS, WHOIS through the user's tools
- Encrypted traffic stays encrypted. Do not suggest decrypting TLS without keys the organization legitimately holds (for example its own SSLKEYLOGFILE or a TLS inspection proxy)
- Note the capture's time span and vantage point in every report: a 10-minute pcap from one switch port proves little about a week of activity elsewhere

## Workflow

1. Ask for the file, where it was captured (host, span port, cloud mirror), the time zone and the question (which host, which window, what alert)
2. Record the SHA-256 of the evidence file before you start (`shasum -a 256 file.pcap`) so the summary can be tied to it
3. Run `pcap_summary.py` on captures. Read the time span and packet count first, then the findings, then the tables
4. Work through findings by type:
   - DNS (NET-001..004): long or random subdomains under one base domain, many TXT/NULL lookups and bursts of NXDOMAIN point to tunneling or DGA
   - Ports (NET-010..011): known backdoor or Tor ports, then rare ports talking to public IPs
   - HTTP (NET-020..022): cleartext requests to a bare IP, tool User-Agents (curl, PowerShell, python-requests) and HTTP on odd ports often carry stage two downloads
   - Scans (NET-030) and odd SNI (NET-040)
5. For long windows use connection logs instead of full captures: run `beacon_detect.py` on Zeek `conn.log`, a firewall CSV or flow JSON. Add `--allow` for known updaters and resolvers and run again
6. Pivot: for each lead, name the internal host, the remote endpoint, first and last seen, and what else that host did around those times
7. Write the report (below) and list IOCs for blocking and for a wider hunt across other hosts

## Tools

### pcap_summary.py

```bash
python3 scripts/pcap_summary.py capture.pcap
python3 scripts/pcap_summary.py capture.pcapng --top 20 --json
python3 scripts/pcap_summary.py capture.pcap --fail-on medium     # exit 1 at medium or above
cat capture.pcap | python3 scripts/pcap_summary.py -
```

Reads classic pcap (micro and nanosecond, either byte order) and pcapng (SHB, IDB with `if_tsresol`, EPB, SPB). Link types: Ethernet with VLAN tags, Linux cooked v1/v2, raw IP, BSD loopback. IPv4 and IPv6 (extension headers), TCP, UDP, DNS over UDP and TCP, HTTP requests in one segment, TLS ClientHello SNI. It does not reassemble TCP streams, so data split across segments is missed.

| ID | Severity | Finding |
|---|---|---|
| NET-001 | medium, high at 5+ names | odd DNS names: over 100 chars, a label of 40+ chars, or a long high-entropy subdomain |
| NET-002 | medium | 30+ unique names under one base domain |
| NET-003 | low | 10+ TXT or NULL queries |
| NET-004 | medium | 20+ NXDOMAIN answers |
| NET-010 | medium | traffic on a known backdoor/Tor/IRC/telnet port (4444, 1337, 31337, 6667, 9001, 9050, ...) |
| NET-011 | info | uncommon ports below 49152 |
| NET-020 | medium | cleartext HTTP with a bare IP as Host to a non-internal address |
| NET-021 | low | scripted User-Agent (curl, wget, python-requests, PowerShell, Go, empty) |
| NET-022 | low | HTTP request on a non-standard port |
| NET-030 | high | one source sent SYNs to 20+ ports on one target |
| NET-040 | low | odd TLS SNI (same rules as NET-001) |

`--json` keys: `format`, `linktypes`, `packets`, `bytes`, `undecoded`, `first_ts`, `last_ts`, `duration_s`, `protocols`, `top_talkers`, `top_conversations`, `ports`, `dns_queries` `[{name, type, count}]`, `dns_nxdomain` (top names), `dns_nxdomain_total`, `http_requests` `[{host, user_agent, method, dst, port, count}]`, `tls_sni` `[{server_name, dst, port, count}]`, `findings`.
Exit `0` nothing at/above `--fail-on` (default `high`), `1` findings at/above it, `2` unreadable, empty or non-capture input. RFC 5737 / 3849 documentation addresses count as external so the samples behave like internet traffic.

### beacon_detect.py

```bash
python3 scripts/beacon_detect.py conn.log
python3 scripts/beacon_detect.py firewall.csv --min-conns 10 --allow 192.0.2.53 --allow 10.20.0.0/16
python3 scripts/beacon_detect.py flows.jsonl --json --fail-on medium
```

Groups connections by (source, destination, destination port) and scores each group with at least `--min-conns` (default 6) connections from 0 to 100:

| Part | Weight | Measures |
|---|---|---|
| Interval regularity | 50% | MAD-based jitter of the gaps (robust to a few missed check-ins) and the coefficient of variation |
| Size regularity | 20% | coefficient of variation of bytes sent (neutral when sizes are missing) |
| Count | 15% | full marks at 31+ connections |
| Coverage | 15% | share of the whole log window between first and last connection |

Score 80+ is high, 65+ medium, 50+ low, all as `BCN-001`. Inputs: Zeek `conn.log` (TSV with `#fields`, `-` = unset), CSV with a header, JSON array or JSON lines; column names are listed in the script's help text. Times may be epoch (s, ms, us, ns) or ISO 8601.
`--json` keys: `format`, `records`, `skipped`, `ignored_by_allow`, `groups`, `window_s`, `candidates` (per-flow stats and score), `findings`. Exit codes as above.

Things that beacon and are not malware: NTP, update checkers, EDR/AV heartbeats, monitoring agents, mail clients polling, chat apps, cloud sync. Allow-list them once confirmed. Malware that sleeps with large random jitter or talks rarely (hours apart) will score low; widen the window and lower `--min-conns` when hunting for slow beacons.

## Output

1. One-line answer to the user's question, with the capture span and vantage point
2. Evidence: file name, SHA-256, packet/connection count, first and last timestamp (UTC)
3. Findings table:

| Severity | ID | Internal host | Remote | Evidence | Next step |
|---|---|---|---|---|---|

4. IOCs, defanged: IPs, domains, SNI, User-Agents, ports
5. ATT&CK mapping where it fits (see the references), and what this data cannot show (encrypted content, other segments, other time ranges)

## References

- `references/protocol-cheatsheet.md` ports, DNS record types, tunneling and DGA tells, HTTP and TLS fields worth reading, capture formats and link types
- `references/beacon-hunting.md` how beacon scoring works, tuning, common false positives, C2 triage steps and ATT&CK IDs for network findings
