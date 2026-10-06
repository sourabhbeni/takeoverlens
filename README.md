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
- `GET /api/scans/{scan_id}` → `{status, total, done, discovered[], results[]}` (poll while scanning)
- `GET /api/probe` → `{engines[]}` — which probe engines this deployment supports
- `POST /api/probe` → `{url, authorized, engine?, include_time?}` → `{findings[]}`
  — active SQLi/XSS indicator probe on query params. Two engines: `quick`
  (reflected-XSS canary + DB error fingerprints, ships everywhere) and `aegis`
  (the full [Aegis](https://github.com/sourabhbeni/aegis) engine: error/boolean/
  time-based SQLi with 9 evasion transforms + 24-probe context-aware reflected
  XSS; Python backend only, needs `pip install git+https://github.com/sourabhbeni/aegis.git`).
  Findings are indicators, verify manually. Same authorization bar.

## SQLi / XSS probe

Below the scan results, each subdomain has a **probe SQLi/XSS** button that fills
the probe card — paste a URL with query params (e.g.
`https://site.example/search?q=test`) and run it. GET-only, max 10 params,
loopback blocked, authorization required. The engine dropdown picks **Quick**
(triage, everywhere) or **Aegis deep** (Python backend only; optional
time-based-SQLi checkbox since it's slow). Covered by `worker/test.mjs`.

## Deploy

**Cloudflare Tunnel** (easiest, free) — run the Python app on your machine and
expose it: full guide in [docs/TUNNEL.md](docs/TUNNEL.md), including a stable
`takeoverlens.beniwal.me` hostname and locking it down with Cloudflare Access.

**Cloudflare Workers** (serverless) — `worker/` is a complete port: the same
scan engine in JavaScript, chunked polling (each poll processes a few
subdomains to respect Worker CPU limits), scan state in KV, and the same UI as
static assets. Enumeration merges crt.sh and hackertarget so one flaky source
doesn't blank the results, and the UI shows a live "discovered subdomains" feed
with per-subdomain status as checks complete.

```bash
cd worker
npx wrangler kv namespace create SCANS   # paste the id into wrangler.toml
npx wrangler deploy
```

Live deployment: **https://takeoverlens.b3ni.workers.dev** (deployed 2026-10-05
via the Cloudflare API).

The Workers verdict logic is covered by `worker/test.mjs` (5/5 cases green).
`worker/build-api-bundle.mjs` reproduces the API-deployed bundle (esbuild +
inlined UI) without wrangler.

## License

MIT
