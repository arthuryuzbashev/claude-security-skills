# Security policy

## Reporting a problem in Claude Security Skills

If a script in this repo can be tricked into doing something unsafe (running code from a file it reads, writing outside its output, leaking a secret it was meant to mask), please report it privately through GitHub's "Report a vulnerability" button on this repo instead of a public issue. You will get a reply within a week.

## Responsible use

Claude Security Skills is built for defenders, developers and authorized testers.

- Point the live-target tools (header, TLS, DNS checks) only at systems you own or have written permission to test
- The scripts are read-only by design: they parse files, send at most ordinary requests, and never exploit, crack or change anything
- Findings can contain sensitive details about your systems. Treat reports like any other security document

Pull requests that add exploit payloads, credential cracking, evasion techniques or anything destructive will be closed.
