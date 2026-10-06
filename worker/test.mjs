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
  'vuln.github.io':     { CNAME: [], A: [] },
  'claimed.github.io':  { CNAME: [], A: ['185.199.108.153'] },
  'gone.herokuapp.com': { CNAME: [], A: [] },
};
const HTTP = {
  'vuln.example.com':    [404, "<html>There isn't a GitHub Pages site here.</html>"],
  'claimed.example.com': [200, "<html>my blog</html>"],
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
  const hit = HTTP[host];
  if (!hit) throw new Error('connection failed');
  return { ok: true, status: hit[0], text: async () => hit[1] };
};

// ---- 1. Verdict matrix ----
const cases = [
  ['vuln.example.com', 'vulnerable'],
  ['claimed.example.com', 'claimed'],
  ['plain.example.com', 'ok'],
  ['weird.example.com', 'review'],
  ['dangle.example.com', 'review'],
];
let pass = 0;
for (const [sub, want] of cases) {
  const r = await checkSubdomain(sub);
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

console.log(`${pass}/${cases.length + 3} checks passed`);
process.exit(pass === cases.length + 3 ? 0 : 1);
