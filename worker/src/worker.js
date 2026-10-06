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

export async function checkSubdomain(sub, domain) {
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
  // Internal CNAME: points at the scanned domain itself (apex or sub).
  // Only the domain owner's DNS controls that zone — not takeoverable.
  if (target === domain || target.endsWith("." + domain)) {
    result.evidence.push(`CNAME points inside ${domain} itself — internal alias, not takeoverable.`);
    return result;
  }
  const svc = matchService(target);
  if (!svc) {
    // Unknown service — fetch once and look for definitive not-takeoverable
    // signals before falling back to manual review.
    const [status, body] = await fetchBody(sub);
    result.http_status = status;
    if (body.includes("error code: 1014")) {
      result.evidence.push(
        `CNAME points to ${target}, but Cloudflare rejected it (error 1014: CNAME Cross-User Banned) — the target zone doesn't serve this hostname and it isn't self-service claimable.`
      );
      return result;
    }
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

async function enumerateHackertarget(domain) {
  const r = await fetch(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, {
    headers: { "User-Agent": "takeoverlens/0.1" },
    signal: AbortSignal.timeout(CRTSH_TIMEOUT_MS),
  });
  if (!r.ok) throw new Error(`hackertarget: HTTP ${r.status}`);
  const text = await r.text();
  if (/error/i.test(text) && text.length < 200)
    throw new Error(`hackertarget: ${text.trim().slice(0, 80)}`);
  const subs = new Set();
  for (const line of text.split("\n")) {
    const n = line.split(",")[0].trim().toLowerCase().replace(/\.$/, "");
    if (n && !n.includes("*") && (n === domain || n.endsWith("." + domain))) subs.add(n);
  }
  return [...subs].sort();
}

async function enumerateAll(domain) {
  // Merge crt.sh + hackertarget; either source may fail — notes say which.
  const found = new Set();
  const notes = [];
  try {
    for (const s of await enumerateCrtsh(domain)) found.add(s);
  } catch (e) {
    notes.push(`crt.sh failed (${String(e.message || e).slice(0, 60)})`);
  }
  try {
    for (const s of await enumerateHackertarget(domain)) found.add(s);
  } catch (e) {
    notes.push(`hackertarget failed (${String(e.message || e).slice(0, 60)})`);
  }
  return { subs: [...found].sort(), notes };
}

async function pollScan(id, env) {
  const raw = await env.SCANS.get(id);
  if (!raw) return json({ detail: "Unknown scan id" }, 404);
  const scan = JSON.parse(raw);

  try {
    if (scan.status === "enumerating") {
      const { subs, notes } = await enumerateAll(scan.domain);
      if (notes.length) {
        scan.enum_note = subs.length
          ? "Partial enumeration: " + notes.join("; ")
          : "Enumeration sources failed (" + notes.join("; ") + "); using manual list + apex.";
      }
      const all = [...new Set([...subs, ...scan.extra, scan.domain])].sort();
      scan.all = all;          // full ordered list, for live discovery display
      scan.queue = [...all];
      scan.total = all.length;
      scan.status = "scanning";
      delete scan.extra;
    }

    if (scan.status === "scanning") {
      const chunk = scan.queue.splice(0, CHUNK);
      for (const sub of chunk) {
        scan.results.push(await checkSubdomain(sub, scan.domain));
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

  const { queue, extra, all, ...pub } = scan;
  // Live discovery: every known subdomain with its check status, so the UI can
  // render them in real time as results land.
  const verdictBySub = new Map(scan.results.map((r) => [r.subdomain, r.verdict]));
  pub.discovered = (all || []).map((s) => ({
    subdomain: s,
    status: verdictBySub.has(s) ? "done" : "pending",
    verdict: verdictBySub.get(s) || null,
  }));
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
