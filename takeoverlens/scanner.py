"""Scan orchestrator: enumerate -> check each subdomain, with progress."""

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

from .check import check_subdomain
from .enumerate import enumerate_crtsh

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
        return dict(scan) if scan else None


def _update(scan_id: str, **fields):
    with _lock:
        _scans[scan_id].update(fields)


def _run(scan_id: str, domain: str, extra: list[str]):
    try:
        try:
            subs = enumerate_crtsh(domain)
            enum_note = None
        except Exception as exc:  # noqa: BLE001 — fall back to manual/apex list
            subs, enum_note = [], f"crt.sh unavailable ({exc}); using manual list + apex."

        manual = {s.strip().lower().rstrip(".") for s in extra if s.strip()}
        manual = {s for s in manual if s == domain or s.endswith("." + domain)}
        subs = sorted(set(subs) | manual | {domain})
        if enum_note:
            subs = subs  # note surfaced via error field only if nothing to scan
        _update(scan_id, status="scanning", total=len(subs), enum_note=enum_note)

        results: list[dict] = []

        def _one(sub):
            res = check_subdomain(sub)
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
