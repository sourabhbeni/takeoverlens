# 🎯 TakeoverLens

**Subdomain takeover verification workbench** — enumerate → resolve → fingerprint → verdict.

Type a domain. TakeoverLens pulls its subdomains from certificate transparency
(crt.sh), resolves DNS for each (CNAME hunt via DNS-over-HTTPS), matches CNAME
targets against 24 known-takeoverable services, and fingerprints candidates over
HTTP. Every subdomain gets a verdict:

| Verdict | Meaning |
|---|---|
| 🔴 VULNERABLE | Service's *unclaimed* fingerprint matched — reportable evidence |
| 🟡 REVIEW | Unknown external CNAME or dangling target — investigate manually |
| 🟢 CLAIMED | Service target is live and claimed — safe |
| ⚪ OK | No CNAME vector |

**Passive recon only.** The tool observes; it never claims third-party resources.
The bounty rules are baked into the UI: verify, don't claim; policy decides;
a 404 alone is never proof.

## Quick start

```bash
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8001
```

Open `http://localhost:8001`, tick the authorization box, scan.

## How verification works

```
domain → crt.sh (subdomains) → DoH CNAME/A per subdomain
  → service match (suffix list) → HTTP fetch → fingerprint match
  → verdict + evidence
```

A subdomain is flagged VULNERABLE **only** when its response body contains the
service's known unclaimed fingerprint (e.g. GitHub Pages'
*"There isn't a GitHub Pages site here."*). Fingerprint dataset is a curated
subset of [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz).

## API

- `POST /api/scans` → `{domain, extra_subdomains[], authorized}` → `{scan_id}`
- `GET /api/scans/{scan_id}` → `{status, total, done, results[]}` (poll while scanning)

## License

MIT
