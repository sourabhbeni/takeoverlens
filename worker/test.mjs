// Tests for the TakeoverLens worker: verdict matrix + live-discovery flow.
import { checkSubdomain } from './src/worker.js';
import worker from './src/worker.js';
import { matchService } from './src/services.js';

// ---- Mock DNS + HTTP ----
const DNS = {
  'vuln.example.com':   { CNAME: ['vuln.github.io'], A: [] },
  'claimed.example.com':{ CNAME: ['claimed.github.io'], A: [] },
  'plain.example.com':  { CNAME: [], A: ['93.184.216.34'] },
  'weird.example.com':  { CNAME: ['weird.somehost.net'], A: [] },
  'dangle.example.com': { CNAME: ['gone.herokuapp.com'], A: [] },
  'internal.example.com': { CNAME: ['example.com'], A: [] },
  'internal2.example.com': { CNAME: ['www.example.com'], A: [] },
  'banned.example.com': { CNAME: ['x.pageserve.co'], A: [] },
  'vuln.github.io':     { CNAME: [], A: [] },
  'claimed.github.io':  { CNAME: [], A: ['185.199.108.153'] },
  'gone.herokuapp.com': { CNAME: [], A: [] },
};
const HTTP = {
  'vuln.example.com':    [404, "<html>There isn't a GitHub Pages site here.</html>"],
  'claimed.example.com': [200, "<html>my blog</html>"],
  'banned.example.com':  [403, "error code: 1014"],
};
const kv = new Map();
const env = {
  SCANS: {
    get: async (k) => kv.get(k) ?? null,
    put: async (k, v) => kv.set(k, v),
  },
  ASSETS: { fetch: async () => new Response('ui', { status: 200 }) },
};

globalThis.fetch = async (url, opts) => {
  url = String(url);
  if (url.includes('crt.sh'))
    return { ok: true, json: async () => [{ name_value: 'a.beniwal.me\nwww.beniwal.me' }] };
  if (url.includes('api.hackertarget.com'))
    return { ok: true, text: async () => 'b.beniwal.me,1.2.3.4\n' };
  if (url.includes('/resolve')) {
    const u = new URL(url);
    const qname = u.searchParams.get('name').replace(/\.$/, '');
    const rec = (DNS[qname] || {})[u.searchParams.get('type')] || [];
    return { ok: true, json: async () => ({ Answer: rec.map(d => ({ data: d })) }) };
  }
  const host = new URL(url).hostname;
  const u2 = new URL(url);
  // Probe targets: behavior keyed by path
  if (u2.pathname.startsWith('/probe-vuln')) {
    const q = u2.searchParams.get('q') || '';
    const html = (t) => ({ ok: true, status: 200,
      headers: new Headers({ 'content-type': 'text/html' }), text: async () => t });
    if (q.includes('tlx')) return html(`<p>results for ${q}</p>`);   // verbatim reflection
    if (q.includes("'")) return html(`You have an error in your SQL syntax near '${q}'`);
    return html('<html>clean search page</html>');
  }
  if (u2.pathname.startsWith('/probe-enc')) {
    const q = u2.searchParams.get('q') || '';
    const esc = q.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    return { ok: true, status: 200, headers: new Headers({ 'content-type': 'text/html' }),
      text: async () => `<p>${esc}</p>` };
  }
  if (u2.pathname.startsWith('/probe-clean')) {
    return { ok: true, status: 200, headers: new Headers({ 'content-type': 'text/html' }),
      text: async () => '<html>nothing reflected here</html>' };
  }
  const hit = HTTP[host];
  if (!hit) throw new Error('connection failed');
  return { ok: true, status: hit[0], text: async () => hit[1] };
};

// ---- 1. Verdict matrix ----
const cases = [
  ['vuln.example.com', 'example.com', 'vulnerable'],
  ['claimed.example.com', 'example.com', 'claimed'],
  ['plain.example.com', 'example.com', 'ok'],
  ['weird.example.com', 'example.com', 'review'],
  ['dangle.example.com', 'example.com', 'review'],
  ['internal.example.com', 'example.com', 'ok'],
  ['internal2.example.com', 'example.com', 'ok'],
  ['banned.example.com', 'example.com', 'ok'],
];
let pass = 0;
for (const [sub, domain, want] of cases) {
  const r = await checkSubdomain(sub, domain);
  const ok = r.verdict === want;
  if (ok) pass++;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${sub}: got=${r.verdict} want=${want} svc=${r.service}`);
}
console.log(`matchService: github.io->${matchService('x.github.io.')?.name}, heroku->${matchService('y.herokuapp.com')?.name}, unknown->${matchService('z.example.net')}`);

// ---- 2. Scan flow: instant POST, merged enumeration, live discovered list ----
const postReq = new Request('http://x/api/scans', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ domain: 'beniwal.me', extra_subdomains: [], authorized: true }),
});
const postRes = await worker.fetch(postReq, env);
const { scan_id } = await postRes.json();
let flowOk = postRes.status === 200 && !!scan_id;
console.log(`${flowOk ? 'PASS' : 'FAIL'} POST /api/scans -> instant scan_id=${scan_id}`);

let discoveredSeen = null, discoveredFinal = null, finalStatus = null, doneCount = 0;
for (let i = 0; i < 10; i++) {
  const r = await worker.fetch(new Request(`http://x/api/scans/${scan_id}`), env);
  const s = await r.json();
  if (s.discovered?.length && !discoveredSeen) discoveredSeen = s.discovered;
  if (s.status === 'done' || s.status === 'error') {
    finalStatus = s.status; doneCount = s.done; discoveredFinal = s.discovered; break;
  }
}
const subs = (discoveredSeen || []).map(d => d.subdomain);
const mergedOk = ['a.beniwal.me', 'b.beniwal.me', 'www.beniwal.me', 'beniwal.me'].every(x => subs.includes(x));
console.log(`${mergedOk ? 'PASS' : 'FAIL'} discovered merged crt.sh+hackertarget+apex: [${subs.join(', ')}]`);
const liveOk = (discoveredFinal || []).every(d => d.status === 'done' && d.verdict);
console.log(`${liveOk ? 'PASS' : 'FAIL'} discovered entries carry live verdicts`);
console.log(`${finalStatus === 'done' ? 'PASS' : 'FAIL'} scan reached done (done=${doneCount})`);
if (flowOk) pass += 1;
if (mergedOk) pass += 1;
if (liveOk && finalStatus === 'done') pass += 1;

// ---- 3. Probe engine: XSS canary, SQLi fingerprints, clean, encoded, no-params ----
import { probeUrl } from './src/probe.js';

const p1 = await probeUrl('http://x/probe-vuln?q=hello');
const p1xss = p1.findings.some(f => f.type === 'xss' && f.param === 'q');
const p1sqli = p1.findings.some(f => f.type === 'sqli' && f.param === 'q');
console.log(`${p1xss && p1sqli ? 'PASS' : 'FAIL'} probe vulnerable target -> xss=${p1xss} sqli=${p1sqli} (reqs=${p1.requests})`);
if (p1xss && p1sqli) pass += 1;

const p2 = await probeUrl('http://x/probe-clean?q=hello');
console.log(`${p2.findings.length === 0 ? 'PASS' : 'FAIL'} probe clean target -> ${p2.findings.length} findings`);
if (p2.findings.length === 0) pass += 1;

const p3 = await probeUrl('http://x/probe-enc?q=hello');
const p3info = p3.findings.some(f => f.type === 'xss-info');
const p3xss = p3.findings.some(f => f.type === 'xss');
console.log(`${p3info && !p3xss ? 'PASS' : 'FAIL'} probe encoded reflection -> info=${p3info}, false-positive=${p3xss}`);
if (p3info && !p3xss) pass += 1;

const p4 = await probeUrl('http://x/probe-clean');
console.log(`${p4.findings.length === 0 && /No query parameters/.test(p4.note) ? 'PASS' : 'FAIL'} probe param-less URL -> honest no-params note`);
if (p4.findings.length === 0 && /No query parameters/.test(p4.note)) pass += 1;

// ---- 4. /api/probe route: auth gate + validation ----
const probeReq = (body) => new Request('http://x/api/probe', {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
});
const pr1 = await worker.fetch(probeReq({ url: 'http://x/probe-vuln?q=hello' }), env);
console.log(`${pr1.status === 400 ? 'PASS' : 'FAIL'} POST /api/probe without auth -> ${pr1.status}`);
if (pr1.status === 400) pass += 1;
const pr2 = await worker.fetch(probeReq({ url: 'http://x/probe-vuln?q=hello', authorized: true }), env);
const pr2j = await pr2.json();
const pr2ok = pr2.status === 200 && pr2j.findings.some(f => f.type === 'sqli');
console.log(`${pr2ok ? 'PASS' : 'FAIL'} POST /api/probe authorized -> ${pr2.status}, findings=${pr2j.findings.length}`);
if (pr2ok) pass += 1;
const pr3 = await worker.fetch(probeReq({ url: 'ftp://x/y', authorized: true }), env);
console.log(`${pr3.status === 400 ? 'PASS' : 'FAIL'} POST /api/probe non-http URL -> ${pr3.status}`);
if (pr3.status === 400) pass += 1;

// ---- 5. probe engine routing (Aegis is Python-only) ----
const pr4 = await worker.fetch(new Request('http://x/api/probe'), env);
const pr4j = await pr4.json();
const pr4ok = pr4.status === 200 && JSON.stringify(pr4j.engines) === '["quick"]';
console.log(`${pr4ok ? 'PASS' : 'FAIL'} GET /api/probe -> engines=${JSON.stringify(pr4j.engines)}`);
if (pr4ok) pass += 1;

const pr5 = await worker.fetch(probeReq({ url: 'http://x/y?q=1', authorized: true, engine: 'aegis' }), env);
console.log(`${pr5.status === 501 ? 'PASS' : 'FAIL'} POST /api/probe engine=aegis -> ${pr5.status}`);
if (pr5.status === 501) pass += 1;

const pr6 = await worker.fetch(probeReq({ url: 'http://x/probe-clean?q=1', authorized: true, engine: 'quick' }), env);
const pr6j = await pr6.json();
const pr6ok = pr6.status === 200 && pr6j.engine === 'quick';
console.log(`${pr6ok ? 'PASS' : 'FAIL'} POST /api/probe engine=quick -> ${pr6.status}, engine=${pr6j.engine}`);
if (pr6ok) pass += 1;

const TOTAL = cases.length + 3 + 10;
console.log(`${pass}/${TOTAL} checks passed`);
process.exit(pass === TOTAL ? 0 : 1);
