# Beacon hunting and C2 triage

## What a beacon looks like

An implant on a compromised host checks in with its controller on a timer: "any work for me?". On the wire that gives:

- One internal host, one remote host (or a small set), one port
- Gaps between connections that cluster around a sleep value (60 s, 5 min, 1 h), with some jitter
- Small, similar request sizes when there is no work; bigger replies when commands or files come down
- Activity around the clock, including nights and weekends when the user is away

Operators add jitter (a random +/- percentage on the sleep) and use common ports (443) to blend in. Jitter widens the spread of gaps but the median stays put, which is why `beacon_detect.py` relies on median absolute deviation (MAD) rather than the plain standard deviation alone.

## How beacon_detect.py scores a flow

For each (source, destination, destination port) with enough connections:

1. Sort the connection start times and take the gaps between them
2. Interval regularity (50%): `jitter = MAD(gaps) / median(gaps)`; 0 is a perfect metronome, 0.3 or more scores zero. The coefficient of variation (stdev / mean) adds a smaller part so a flow with a few long pauses still ranks lower than a perfect one
3. Size regularity (20%): coefficient of variation of bytes sent; 0.5 or more scores zero. Missing sizes give a neutral half score
4. Count (15%): more check-ins mean more confidence; full marks at 31 connections
5. Coverage (15%): how much of the whole log window the flow spans; a beacon runs all day, a burst of downloads does not

Score 80+ high, 65+ medium, 50+ low. These thresholds are starting points; tune them on a known-clean day of your own logs.

## Tuning

- `--min-conns`: raise it (20+) on noisy networks, lower it (4) when hunting slow beacons over a long window
- `--allow`: add resolvers, NTP servers, update and telemetry endpoints, monitoring collectors once you have confirmed them. Keep the allow-list in the case notes so others can review it
- Window: one hour catches fast beacons; slow ones (hourly or daily) need days of logs
- Aggregate by destination domain (from DNS or SNI) instead of IP when the C2 rotates through CDN or cloud addresses; rename the column to `dst` in a CSV export to do that

## Common false positives

| Source | Tell |
|---|---|
| NTP | UDP 123, tiny fixed sizes, intervals of 64 to 1024 s |
| OS and app update checks | vendor domains, intervals of hours |
| EDR / AV heartbeats | vendor cloud, very steady, every host in the fleet does it |
| Monitoring agents, log shippers | to an internal collector or SaaS endpoint, every host |
| Mail and chat clients | IMAP 993 polling, websocket keep-alives |
| Cloud sync (backup, file sync) | regular small check-ins, bursts when files change |

The fleet test helps most: if 500 hosts all beacon to the same place, it is probably software everyone runs. One host doing it alone is the interesting case.

## Triage steps for a candidate

1. Who: map the source IP to a host and user for that time (DHCP leases, EDR inventory)
2. What: find the process that owns the connection (EDR network events, Sysmon event ID 3, `lsof -i`/`ss -tp` on a live Linux host, `netstat -ano` plus the PID on Windows) and hash the binary
3. Where: destination reputation, passive DNS, WHOIS age, certificate details, the SNI or Host it used
4. When: first seen; what happened on the host just before (download, email attachment opened, new service or scheduled task)
5. How much: total bytes out over the life of the flow (exfiltration?) and any big replies (tools or payloads coming down)
6. Scope: search every host's logs for the same destination, SNI, User-Agent or JA3/JA4 fingerprint
7. Decide with the incident lead: watch, block at the egress, or isolate the host. Collect volatile evidence before isolating if the plan allows it

## ATT&CK techniques for network findings

| Finding | Technique |
|---|---|
| C2 over HTTP/HTTPS | T1071.001 Application Layer Protocol: Web Protocols |
| C2 or tunneling over DNS | T1071.004 Application Layer Protocol: DNS |
| Encrypted C2 channel | T1573 Encrypted Channel |
| Unusual port for the protocol | T1571 Non-Standard Port |
| DGA lookups | T1568.002 Dynamic Resolution: Domain Generation Algorithms |
| Exfiltration over DNS or another non-C2 protocol | T1048 Exfiltration Over Alternative Protocol |
| Exfiltration over the C2 channel | T1041 Exfiltration Over C2 Channel |
| Data sent on a schedule | T1029 Scheduled Transfer |
| Tor or chained proxies | T1090.003 Proxy: Multi-hop Proxy |
| Payload download (curl, certutil, PowerShell) | T1105 Ingress Tool Transfer |
| Port scan from an internal host | T1046 Network Service Discovery |

## Report snippet

```
192.0.2.10 -> 203.0.113.50:443, score 96 (high)
90 connections between 08:00 and 09:29 UTC on 2026-03-04, every ~60 s (jitter 2%),
~310 bytes out each. Owning process: unknown (EDR data requested).
Destination: no reputation hits, certificate self-signed (to confirm).
ATT&CK: T1071.001, T1573. Next: identify the process, then decide on block or isolate.
```
