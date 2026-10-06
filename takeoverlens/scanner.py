"""Scan orchestrator: enumerate -> check each subdomain, with progress."""

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

from .check import check_subdomain
from .enumerate import enumerate_all

MAX_WORKERS = 5

_scans: dict[str, dict] = {}
_lock = threading.Lock()


def start_scan(domain: str, extra_subdomains: list[str] | None = None) -> str:
    """Kick off a background scan. Returns scan_id; poll get_scan() for progress."""
    scan_id = uuid.uuid4().hex[:12]
    with _lock:
        _scans[scan_id] = {
            "id": scan_id, "domain": domain, "status": "enumerating",
            "total": 0, "done": 0, "results": [], "error": None,
        }
    thread = threading.Thread(target=_run, args=(scan_id, domain, extra_subdomains or []), daemon=True)
    thread.start()
    return scan_id


def get_scan(scan_id: str) -> dict | None:
    with _lock:
        scan = _scans.get(scan_id)
        if not scan:
            return None
        out = dict(scan)
    # Live discovery: every known subdomain with its check status.
    verdict_by_sub = {r["subdomain"]: r["verdict"] for r in out["results"]}
    out["discovered"] = [
        {
            "subdomain": s,
            "status": "done" if s in verdict_by_sub else "pending",
            "verdict": verdict_by_sub.get(s),
        }
        for s in out.get("all", [])
    ]
    return out


def _update(scan_id: str, **fields):
    with _lock:
        _scans[scan_id].update(fields)


def _run(scan_id: str, domain: str, extra: list[str]):
    try:
        subs, notes = enumerate_all(domain)
        enum_note = None
        if notes:
            enum_note = (
                "Partial enumeration: " + "; ".join(notes) if subs
                else "Enumeration sources failed (" + "; ".join(notes) + "); using manual list + apex."
            )

        manual = {s.strip().lower().rstrip(".") for s in extra if s.strip()}
        manual = {s for s in manual if s == domain or s.endswith("." + domain)}
        subs = sorted(set(subs) | manual | {domain})
        _update(scan_id, status="scanning", total=len(subs), all=subs, enum_note=enum_note)

        results: list[dict] = []

        def _one(sub):
            res = check_subdomain(sub, domain)
            with _lock:
                sc = _scans[scan_id]
                sc["results"].append(res)
                sc["done"] += 1
            return res

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            list(pool.map(_one, subs))

        with _lock:
            sc = _scans[scan_id]
            sc["results"].sort(key=lambda r: ({"vulnerable": 0, "review": 1, "claimed": 2, "ok": 3}[r["verdict"]], r["subdomain"]))
            sc["status"] = "done"
    except Exception as exc:  # noqa: BLE001 — never leave a scan hanging
        _update(scan_id, status="error", error=str(exc)[:300])
