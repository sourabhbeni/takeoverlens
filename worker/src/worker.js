// TakeoverLens on Cloudflare Workers — serverless subdomain takeover verification.
//
// Same API as the Python app: POST /api/scans returns a scan_id immediately,
// GET /api/scans/{id} is polled. Enumeration happens on the first poll and each
// poll then processes a small chunk of subdomains (Workers have limited
// per-request CPU), with scan state in KV. Passive recon only.

import { matchService } from "./services.js";

const CHUNK = 2;               // subdomains processed per poll — raise cautiously
const HTTP_TIMEOUT_MS = 10000;
const CRTSH_TIMEOUT_MS = 15000;
const SCAN_TTL = 3600;         // scan state expires after 1h

const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;
const DOH = ["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"];
const VERDICT_ORDER = { vulnerable: 0, review: 1, claimed: 2, ok: 3 };

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json" } });

async function doh(name, type) {
  for (const ep of DOH) {
    try {
      const r = await fetch(`${ep}?name=${encodeURIComponent(name)}&type=${type}`, {
        headers: { Accept: "application/dns-json", "User-Agent": "takeoverlens/0.1" },
        signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
      });
      if (!r.ok) continue;
      const j = await r.json();
      return (j.Answer || []).map((a) => a.data).filter(Boolean);
    } catch {
      /* try next endpoint */
    }
  }
  return [];
}

async function enumerateCrtsh(domain) {
  const r = await fetch(`https://crt.sh/?q=%25.${domain}&output=json`, {
    headers: { "User-Agent": "takeoverlens/0.1" },
    signal: AbortSignal.timeout(CRTSH_TIMEOUT_MS),
  });
  if (!r.ok) throw new Error(`crt.sh: HTTP ${r.status}`);
  const subs = new Set();
  for (const e of await r.json()) {
    for (let n of String(e.name_value || "").split("\n")) {
      n = n.trim().toLowerCase().replace(/\.$/, "");
      if (n && !n.includes("*") && (n === domain || n.endsWith("." + domain))) subs.add(n);
    }
  }
  return [...subs].sort();
}

async function fetchBody(sub) {
  for (const scheme of ["https", "http"]) {
    try {
      const r = await fetch(`${scheme}://${sub}/`, {
        headers: { "User-Agent": "takeoverlens/0.1" },
        redirect: "follow",
        signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
      });
      return [r.status, (await r.text()).slice(0, 100000)];
    } catch {
      /* try next scheme */
    }
  }
  return [null, ""];
}

export async function checkSubdomain(sub) {
  const result = {
    subdomain: sub, cname: null, a_records: [], service: null,
    http_status: null, verdict: "ok", evidence: [],
  };
  const [cnames, aRecs] = await Promise.all([doh(sub, "CNAME"), doh(sub, "A")]);
  result.a_records = aRecs.slice(0, 4);
  if (!cnames.length) {
    result.evidence.push("No CNAME record — not a takeover vector via CNAME.");
    return result;
  }
  const target = cnames[0].replace(/\.$/, "");
  result.cname = target;
  const svc = matchService(target);
  if (!svc) {
    result.verdict = "review";
    result.evidence.push(`CNAME points to external host ${target} (unknown service) — check manually.`);
    return result;
  }
  result.service = svc.name;
  const [status, body] = await fetchBody(sub);
  result.http_status = status;
  const lower = body.toLowerCase();
  const matched = svc.fingerprints.filter((fp) => lower.includes(fp.toLowerCase()));
  if (matched.length) {
    result.verdict = "vulnerable";
    result.evidence.push(`Unclaimed fingerprint matched (${svc.name}): "${matched[0]}" (HTTP ${status}).`);
    result.evidence.push("This is proof-of-concept evidence. Do NOT claim the resource — report it per program policy.");
    return result;
  }
  if (!(await doh(target, "A")).length) {
    result.verdict = "review";
    result.evidence.push(`CNAME target ${target} does not resolve (dangling?) — investigate manually, do not attempt to claim it.`);
    return result;
  }
  result.verdict = "claimed";
  result.evidence.push(`${svc.name} target is live and claimed (HTTP ${status}, no unclaimed fingerprint).`);
  return result;
}

async function createScan(req, env) {
  let body;
  try {
    body = await req.json();
  } catch {
    return json({ detail: "Invalid JSON" }, 400);
  }
  const domain = String(body.domain || "").trim().toLowerCase()
    .replace(/\.$/, "").replace(/^https?:\/\//, "").split("/")[0];
  if (!DOMAIN_RE.test(domain)) return json({ detail: "Invalid domain (e.g. example.com)" }, 400);
  if (!body.authorized) return json({ detail: "Confirm you are authorized to test this domain" }, 400);

  const extra = [
    ...new Set(
      (body.extra_subdomains || [])
        .map((s) => String(s).trim().toLowerCase().replace(/\.$/, ""))
        .filter((s) => s === domain || s.endsWith("." + domain))
    ),
  ];
  const id = crypto.randomUUID().replace(/-/g, "").slice(0, 12);
  // Enumeration runs on the first poll so POST returns instantly.
  const scan = {
    id, domain, extra, status: "enumerating", total: 0, done: 0,
    results: [], queue: [], enum_note: null, error: null,
  };
  await env.SCANS.put(id, JSON.stringify(scan), { expirationTtl: SCAN_TTL });
  return json({ scan_id: id });
}

async function pollScan(id, env) {
  const raw = await env.SCANS.get(id);
  if (!raw) return json({ detail: "Unknown scan id" }, 404);
  const scan = JSON.parse(raw);

  try {
    if (scan.status === "enumerating") {
      let subs = [];
      try {
        subs = await enumerateCrtsh(scan.domain);
      } catch (e) {
        scan.enum_note = `crt.sh unavailable (${String(e.message || e).slice(0, 120)}); using manual list + apex.`;
      }
      const all = [...new Set([...subs, ...scan.extra, scan.domain])].sort();
      scan.queue = all;
      scan.total = all.length;
      scan.status = "scanning";
      delete scan.extra;
    }

    if (scan.status === "scanning") {
      const chunk = scan.queue.splice(0, CHUNK);
      for (const sub of chunk) {
        scan.results.push(await checkSubdomain(sub));
        scan.done++;
      }
      if (!scan.queue.length) {
        scan.status = "done";
        scan.results.sort(
          (a, b) => VERDICT_ORDER[a.verdict] - VERDICT_ORDER[b.verdict] ||
            (a.subdomain < b.subdomain ? -1 : 1)
        );
      }
    }

    await env.SCANS.put(id, JSON.stringify(scan), { expirationTtl: SCAN_TTL });
  } catch (e) {
    scan.status = "error";
    scan.error = String(e.message || e).slice(0, 300);
    await env.SCANS.put(id, JSON.stringify(scan), { expirationTtl: SCAN_TTL });
  }

  const { queue, extra, ...pub } = scan;
  return json(pub);
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === "/api/scans" && req.method === "POST") return createScan(req, env);
    const m = url.pathname.match(/^\/api\/scans\/([A-Za-z0-9]+)$/);
    if (m && req.method === "GET") return pollScan(m[1], env);
    return env.ASSETS.fetch(req);
  },
};
