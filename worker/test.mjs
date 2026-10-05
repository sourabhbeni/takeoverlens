import { checkSubdomain } from './src/worker.js';
import { matchService } from './src/services.js';

// Mock DNS + HTTP: scenario keyed by subdomain
const DNS = {
  'vuln.example.com':   { CNAME: ['vuln.github.io.'], A: [] },
  'claimed.example.com':{ CNAME: ['claimed.github.io.'], A: [] },
  'plain.example.com':  { CNAME: [], A: ['93.184.216.34'] },
  'weird.example.com':  { CNAME: ['weird.somehost.net.'], A: [] },
  'dangle.example.com': { CNAME: ['gone.herokuapp.com.'], A: [] },
  'vuln.github.io':    { CNAME: [], A: [] },
  'claimed.github.io': { CNAME: [], A: ['185.199.108.153'] },
  'gone.herokuapp.com':{ CNAME: [], A: [] },   // NXDOMAIN target
};
const HTTP = {
  'vuln.example.com':    [404, "<html>There isn't a GitHub Pages site here.</html>"],
  'claimed.example.com': [200, "<html>my blog</html>"],
};
globalThis.fetch = async (url, opts) => {
  url = String(url);
  if (url.includes('/resolve')) {
    const u = new URL(url);
    const rec = (DNS[u.searchParams.get('name').replace(/\.$/, '')] || DNS[u.searchParams.get('name')] || {})[u.searchParams.get('type')] || [];
    return { ok: true, json: async () => ({ Answer: rec.map(d => ({ data: d })) }) };
  }
  const host = new URL(url).hostname;
  const [status, text] = HTTP[host] || [null, ''];
  if (status === null) throw new Error('connection failed');
  return { ok: true, status, text: async () => text };
};

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
console.log(`${pass}/${cases.length} verdict cases passed`);
process.exit(pass === cases.length ? 0 : 1);
