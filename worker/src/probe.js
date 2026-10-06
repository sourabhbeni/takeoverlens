// Active SQLi/XSS indicator probing — GET query parameters only.
//
// Method: reflected-XSS via a unique break-out canary; error-based SQLi via
// classic payloads matched against DB error fingerprints. Findings are
// INDICATORS, not confirmed vulnerabilities — verify manually before reporting.
// Only run against targets you are authorized to test.

const SQLI_PAYLOADS = ["'", '"', "' OR '1'='1", "') OR ('1'='1"];
const SQL_ERROR_FPS = [
  "you have an error in your sql syntax",
  "warning: mysql",
  "mysqli_fetch",
  "mysql_fetch",
  "pg_query()",
  "postgresql",
  "psql:",
  "sqlite3::",
  "sqlite error",
  "ora-01756",
  "quoted string not properly terminated",
  "unterminated quoted string",
  "microsoft ole db",
  "odbc sql server driver",
  "sqlstate",
  "jdbc",
  "sqlexception",
  "odbc_",
];

const MAX_PARAMS = 10;
const REQ_TIMEOUT_MS = 10000;
const MAX_BODY = 200000;

function randHex(n) {
  return [...crypto.getRandomValues(new Uint8Array(n))]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function getBody(url) {
  try {
    const r = await fetch(url, {
      headers: { "User-Agent": "takeoverlens/0.1" },
      redirect: "follow",
      signal: AbortSignal.timeout(REQ_TIMEOUT_MS),
    });
    const ct = (r.headers.get("content-type") || "").toLowerCase();
    if (!ct.includes("text") && !ct.includes("html") && !ct.includes("json")) return "";
    return (await r.text()).slice(0, MAX_BODY);
  } catch {
    return "";
  }
}

export async function probeUrl(targetUrl) {
  const findings = [];
  let requests = 0;
  const u = new URL(targetUrl);
  const params = [...new Set([...u.searchParams.keys()])].slice(0, MAX_PARAMS);

  if (!params.length) {
    return {
      findings, requests,
      note: "No query parameters to test — paste a URL like https://site/search?q=test",
    };
  }

  const canary = "tlx" + randHex(4);

  for (const param of params) {
    // --- Reflected XSS: unique break-out canary ---
    const xssPayload = `'"><${canary}>`;
    const xssUrl = new URL(u);
    xssUrl.searchParams.set(param, xssPayload);
    const xssBody = await getBody(xssUrl.toString());
    requests++;
    if (xssBody && xssBody.includes(xssPayload)) {
      findings.push({
        type: "xss", param, severity: "medium",
        evidence: `Break-out canary reflected verbatim (${xssPayload.length} chars unescaped). Confirm the sink context manually.`,
      });
    } else if (xssBody && xssBody.includes(canary)) {
      findings.push({
        type: "xss-info", param, severity: "info",
        evidence: "Canary reflected but HTML-encoded — not exploitable as-is.",
      });
    }

    // --- Error-based SQLi: one finding per param is enough ---
    for (const p of SQLI_PAYLOADS) {
      const sqliUrl = new URL(u);
      sqliUrl.searchParams.set(param, p);
      const body = await getBody(sqliUrl.toString());
      requests++;
      if (!body) continue;
      const lower = body.toLowerCase();
      const hit = SQL_ERROR_FPS.find((fp) => lower.includes(fp));
      if (hit) {
        findings.push({
          type: "sqli", param, severity: "high",
          evidence: `DB error fingerprint with payload ${JSON.stringify(p)}: "${hit}"`,
        });
        break;
      }
    }
  }

  return {
    findings, requests,
    note: "Indicators only — verify manually before reporting. Same scope rules apply.",
  };
}
