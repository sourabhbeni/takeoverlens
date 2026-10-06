"""Per-subdomain verification: DNS -> service match -> fingerprint -> verdict."""

import httpx

from .resolve import resolve
from .services import match_service

HTTP_TIMEOUT = 10
MAX_BODY = 100_000


def fetch_body(subdomain: str) -> tuple[int | None, str]:
    """Fetch the subdomain over HTTPS (fallback HTTP). Returns (status, body)."""
    headers = {"User-Agent": "takeoverlens/0.1"}
    for scheme in ("https", "http"):
        try:
            r = httpx.get(f"{scheme}://{subdomain}/", headers=headers,
                          timeout=HTTP_TIMEOUT, follow_redirects=True)
            return r.status_code, r.text[:MAX_BODY]
        except Exception:  # noqa: BLE001 — try next scheme
            continue
    return None, ""


def check_subdomain(subdomain: str, domain: str) -> dict:
    """Full verification for one subdomain. Never claims anything, only observes."""
    result = {
        "subdomain": subdomain,
        "cname": None,
        "a_records": [],
        "service": None,
        "http_status": None,
        "verdict": "ok",
        "evidence": [],
    }

    cnames = resolve(subdomain, "CNAME")
    result["a_records"] = resolve(subdomain, "A")[:4]
    if not cnames:
        result["evidence"].append("No CNAME record — not a takeover vector via CNAME.")
        return result

    target = cnames[0].rstrip(".")
    result["cname"] = target

    # Internal CNAME: points at the scanned domain itself (apex or sub).
    # Only the domain owner's DNS controls that zone — not takeoverable.
    if target == domain or target.endswith("." + domain):
        result["evidence"].append(
            f"CNAME points inside {domain} itself — internal alias, not takeoverable."
        )
        return result

    svc = match_service(target)

    if not svc:
        result["verdict"] = "review"
        result["evidence"].append(
            f"CNAME points to external host {target} (unknown service) — check manually."
        )
        return result

    result["service"] = svc["name"]
    status, body = fetch_body(subdomain)
    result["http_status"] = status

    matched = [fp for fp in svc["fingerprints"] if fp.lower() in body.lower()]
    if matched:
        result["verdict"] = "vulnerable"
        result["evidence"].append(
            f"Unclaimed fingerprint matched ({svc['name']}): \"{matched[0]}\" (HTTP {status})."
        )
        result["evidence"].append(
            "This is proof-of-concept evidence. Do NOT claim the resource — report it per program policy."
        )
        return result

    target_a = resolve(target, "A")
    if not target_a:
        result["verdict"] = "review"
        result["evidence"].append(
            f"CNAME target {target} does not resolve (dangling?) — investigate manually, "
            "do not attempt to claim it."
        )
        return result

    result["verdict"] = "claimed"
    result["evidence"].append(
        f"{svc['name']} target is live and claimed (HTTP {status}, no unclaimed fingerprint)."
    )
    return result
