# Recon scope and evidence checklist

Passive recon finds what is already public. The value is in the inventory and the decisions it triggers, not in clever tricks.

## Before collecting anything

- [ ] Who owns each domain? Registrar/WHOIS org, DNS provider account, or a written statement from the client
- [ ] Written authorization (engagement letter, bug bounty policy, internal ticket) with the in-scope domains listed
- [ ] Exclusions written down: third-party SaaS on your subdomains (status pages, help desks, marketing tools) usually belongs to the vendor and needs their rules
- [ ] Allowed techniques: passive only, or are live DNS lookups, port scans or app testing agreed?
- [ ] Rate limits and quiet hours for anything live
- [ ] Where findings go and who gets told immediately about a critical (a live takeover, an exposed database)

## Passive sources

| Source | What you get | How |
|---|---|---|
| Certificate Transparency | Every name ever put in a public certificate | crt.sh JSON: `https://crt.sh/?q=%25.example.com&output=json` |
| Your DNS provider | The real zone, including names never in a certificate | Zone export / API (best source for your own domains) |
| Cloud inventory | Load balancers, buckets, CDN endpoints, public IPs | Cloud asset inventory or config export |
| Public DNS | Current answers for known names | `dig` A/AAAA/CNAME/MX/TXT/NS |
| Search engines and archives | Old URLs, forgotten paths | `site:example.com`, web archive listings |
| Code hosting | Hostnames and endpoints in public repos | Search your org's public repos for the domain |

CT logs keep names forever. A name in CT with no DNS answer today is usually retired; it becomes interesting when DNS still has a CNAME for it.

## Triage order

1. Dangling CNAMEs to services where names can be re-claimed (subdomain takeover)
2. Data stores, admin panels and CI/CD systems reachable from the internet
3. Public names resolving to private, loopback or link-local addresses (leaks internal layout)
4. Non-production and legacy hosts: fewer patches, test accounts, debug modes
5. Email authentication gaps (spoofing of the main domain hurts customers directly)
6. Everything else goes into the inventory for the next review

## Verifying a takeover candidate (your own domain)

- `dig CNAME host.example.com` and `dig A <target>`: the target returns NXDOMAIN or no address
- Open the host in a browser: providers show telltale errors ("NoSuchBucket", "There isn't a GitHub Pages site here", "No such app")
- Check the provider console of your own account: is the resource gone?
- Fix: delete the CNAME, or re-create the resource in your own account. Do not leave it "for later"
- On a domain you do not own (bug bounty), report the candidate with the evidence above. Claiming the resource is out of bounds unless the program explicitly allows it, and even then serve nothing but a harmless proof page

## Evidence to keep

- Input files (CT export, zone export, host list) with collection date
- Exact commands and tool versions
- Raw DNS answers for every finding
- Screenshots of provider error pages for takeover candidates

## Report checklist

- [ ] Scope: domains, exclusions, dates, sources, passive or active
- [ ] Summary numbers: hosts found, by category, number of high findings
- [ ] Each finding: host, evidence, why it matters in one line, exact fix, owner
- [ ] Email auth: current records and the exact records to publish
- [ ] Not covered: no port scan, no authenticated testing, DKIM selectors not found, names only seen in CT
- [ ] Internal hostnames only in the restricted version of the report
