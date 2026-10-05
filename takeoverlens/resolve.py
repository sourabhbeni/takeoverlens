"""DNS resolution over HTTPS (works anywhere, no system resolver needed)."""

import os

import httpx

DOH_ENDPOINTS = [
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
]


def _sanitize_no_proxy():
    """Drop NO_PROXY entries that break httpx's proxy parsing (bracketed IPv6, etc.)."""
    for var in ("NO_PROXY", "no_proxy"):
        val = os.environ.get(var)
        if not val:
            continue
        kept = [e.strip() for e in val.split(",")
                if e.strip() and "[" not in e and e.count(":") <= 1]
        os.environ[var] = ",".join(kept)


_sanitize_no_proxy()


def resolve(name: str, rtype: str, timeout: int = 15) -> list[str]:
    """Return answer data for name/rtype via DoH. Empty list on NXDOMAIN/error."""
    params = {"name": name.rstrip("."), "type": rtype}
    headers = {"User-Agent": "takeoverlens/0.1", "Accept": "application/dns-json"}
    for endpoint in DOH_ENDPOINTS:
        try:
            r = httpx.get(endpoint, params=params, headers=headers, timeout=timeout)
            r.raise_for_status()
            answers = r.json().get("Answer", [])
            return [a["data"] for a in answers if "data" in a]
        except Exception:  # noqa: BLE001 — try next endpoint
            continue
    return []
