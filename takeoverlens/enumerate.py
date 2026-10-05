"""Subdomain enumeration via crt.sh (public certificate transparency data)."""

import time

import httpx

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


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
