"""Active SQLi/XSS indicator probing — GET query parameters only.

Mirrors worker/src/probe.js. Findings are INDICATORS, not confirmed
vulnerabilities — verify manually before reporting. Only run against targets
you are authorized to test.
"""

import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

SQLI_PAYLOADS = ["'", '"', "' OR '1'='1", "') OR ('1'='1"]
SQL_ERROR_FPS = [
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
]

MAX_PARAMS = 10
REQ_TIMEOUT = 10
MAX_BODY = 200_000


def _get_body(url: str) -> str:
    try:
        r = httpx.get(url, headers={"User-Agent": "takeoverlens/0.1"},
                      timeout=REQ_TIMEOUT, follow_redirects=True)
        ct = r.headers.get("content-type", "").lower()
        if "text" not in ct and "html" not in ct and "json" not in ct:
            return ""
        return r.text[:MAX_BODY]
    except Exception:  # noqa: BLE001
        return ""


def _with_param(url: str, param: str, value: str) -> str:
    parts = urlparse(url)
    q = [(k, v) for k, v in parse_qsl(parts.query) if k != param]
    q.append((param, value))
    return urlunparse(parts._replace(query=urlencode(q)))


def probe_url(target_url: str) -> dict:
    findings: list[dict] = []
    requests = 0
    params = [k for k, _ in parse_qsl(urlparse(target_url).query)]
    params = list(dict.fromkeys(params))[:MAX_PARAMS]

    if not params:
        return {
            "findings": findings, "requests": requests,
            "note": "No query parameters to test — paste a URL like https://site/search?q=test",
        }

    canary = "tlx" + secrets.token_hex(4)

    for param in params:
        # --- Reflected XSS: unique break-out canary ---
        xss_payload = f"'\"><{canary}>"
        xss_body = _get_body(_with_param(target_url, param, xss_payload))
        requests += 1
        if xss_body and xss_payload in xss_body:
            findings.append({
                "type": "xss", "param": param, "severity": "medium",
                "evidence": f"Break-out canary reflected verbatim ({len(xss_payload)} chars unescaped). "
                            "Confirm the sink context manually.",
            })
        elif xss_body and canary in xss_body:
            findings.append({
                "type": "xss-info", "param": param, "severity": "info",
                "evidence": "Canary reflected but HTML-encoded — not exploitable as-is.",
            })

        # --- Error-based SQLi: one finding per param is enough ---
        for p in SQLI_PAYLOADS:
            body = _get_body(_with_param(target_url, param, p))
            requests += 1
            if not body:
                continue
            lower = body.lower()
            hit = next((fp for fp in SQL_ERROR_FPS if fp in lower), None)
            if hit:
                findings.append({
                    "type": "sqli", "param": param, "severity": "high",
                    "evidence": f'DB error fingerprint with payload {p!r}: "{hit}"',
                })
                break

    return {
        "findings": findings, "requests": requests,
        "note": "Indicators only — verify manually before reporting. Same scope rules apply.",
    }
