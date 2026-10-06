"""Subdomain enumeration via crt.sh (public certificate transparency data)."""

import time

import httpx

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


def enumerate_hackertarget(domain: str, timeout: int = 20) -> list[str]:
    """Subdomains from hackertarget's free hostsearch API (CSV lines)."""
    r = httpx.get(
        "https://api.hackertarget.com/hostsearch/",
        params={"q": domain},
        headers={"User-Agent": "takeoverlens/0.1"},
        timeout=timeout,
    )
    r.raise_for_status()
    text = r.text
    if len(text) < 200 and "error" in text.lower():
        raise RuntimeError(f"hackertarget: {text.strip()[:80]}")
    subs: set[str] = set()
    for line in text.split("\n"):
        name = line.split(",")[0].strip().lower().rstrip(".")
        if name and "*" not in name and (name == domain or name.endswith("." + domain)):
            subs.add(name)
    return sorted(subs)


def enumerate_all(domain: str) -> tuple[list[str], list[str]]:
    """Merge crt.sh + hackertarget. Returns (subdomains, notes about failures)."""
    found: set[str] = set()
    notes: list[str] = []
    try:
        found.update(enumerate_crtsh(domain))
    except Exception as exc:  # noqa: BLE001
        notes.append(f"crt.sh failed ({str(exc)[:60]})")
    try:
        found.update(enumerate_hackertarget(domain))
    except Exception as exc:  # noqa: BLE001
        notes.append(f"hackertarget failed ({str(exc)[:60]})")
    return sorted(found), notes


def enumerate_crtsh(domain: str, retries: int = 3, timeout: int = 30) -> list[str]:
    """Return sorted unique subdomains of domain from crt.sh. Raises on failure."""
    last_err = None
    for attempt in range(retries):
        try:
            r = httpx.get(
                CRTSH_URL.format(domain=domain),
                headers={"User-Agent": "takeoverlens/0.1"},
                timeout=timeout,
            )
            r.raise_for_status()
            subs: set[str] = set()
            for entry in r.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower().rstrip(".")
                    if name and "*" not in name and (name == domain or name.endswith("." + domain)):
                        subs.add(name)
            return sorted(subs)
        except Exception as exc:  # noqa: BLE001 — retry transient failures
            last_err = exc
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"crt.sh enumeration failed after {retries} attempts: {last_err}")
