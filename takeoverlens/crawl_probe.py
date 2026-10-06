"""Crawl-mode probe: spider a site (same origin only), collect every injection
point (query params + GET/POST forms on every page), and run the Aegis
SQLi/XSS engines over all of them.

Chunked like the scan engine: each get_crawl() call advances the job a
little (a few pages crawled or one point tested), so the UI polls for
progress instead of blocking on a long request.

Guardrails: same-origin only, max_pages cap (default 20, hard 50),
per-path query-URL cap (crawler-trap protection), total point cap,
non-HTML skipped, page-size cap. Indicators only — verify manually.
"""

from __future__ import annotations

import urllib.parse
import uuid
from html.parser import HTMLParser

from aegis import crawler as aegis_crawler, xss
from aegis.http import Session

from .aegis_probe import _normalize, run_sqli_point

MAX_PAGES_HARD = 50
MAX_POINTS = 150
PATH_QUERY_CAP = 10  # distinct query-string URLs per path (trap protection)
PAGE_SIZE_CAP = 1_000_000
CRAWL_PER_POLL = 3
SCAN_PER_POLL = 1

_crawls: dict[str, dict] = {}


class _LinkParser(HTMLParser):
    """All same-page <a href> links (Aegis's extract_links only keeps
    query-string links; the crawler needs every page to find forms)."""

    def __init__(self, base: str):
        super().__init__()
        self.base = base
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(urllib.parse.urljoin(self.base, href))


def _strip_frag(url: str) -> str:
    return urllib.parse.urldefrag(url)[0]


def _same_origin(url: str, origin: str) -> bool:
    p = urllib.parse.urlparse(url)
    return f"{p.scheme}://{p.netloc}".lower() == origin.lower()


def _is_html(resp) -> bool:
    ctype = ""
    for k, v in (resp.headers or {}).items():
        if k.lower() == "content-type":
            ctype = v
            break
    return "html" in ctype.lower()


def start_crawl(url: str, max_pages: int = 20, include_time: bool = False) -> str:
    job_id = uuid.uuid4().hex[:12]
    parsed = urllib.parse.urlparse(url)
    _crawls[job_id] = {
        "job_id": job_id,
        "url": url,
        "origin": f"{parsed.scheme}://{parsed.netloc}",
        "status": "crawling",
        "queue": [_strip_frag(url)],
        "visited": set(),
        "path_qcounts": {},
        "points": [],
        "seen_points": set(),
        "point_idx": 0,
        "pages_crawled": 0,
        "max_pages": max(1, min(max_pages, MAX_PAGES_HARD)),
        "include_time": include_time,
        "findings": [],
        "error": None,
        "session": Session(timeout=10, user_agent="takeoverlens/0.1"),
    }
    return job_id


def get_crawl(job_id: str) -> dict | None:
    job = _crawls.get(job_id)
    if not job:
        return None
    if job["status"] == "crawling":
        _crawl_chunk(job)
    elif job["status"] == "scanning":
        _scan_chunk(job)
    return _public(job)


def _public(job: dict) -> dict:
    return {
        "job_id": job["job_id"],
        "url": job["url"],
        "status": job["status"],
        "pages_crawled": job["pages_crawled"],
        "max_pages": job["max_pages"],
        "points_found": len(job["points"]),
        "points_tested": job["point_idx"],
        "findings": job["findings"],
        "error": job["error"],
        "note": "Aegis engine — indicators only, verify manually before reporting.",
    }


def _queue_url(job: dict, url: str):
    url = _strip_frag(url)
    if not url or url in job["visited"] or url in job["queue"]:
        return
    if not _same_origin(url, job["origin"]):
        return
    p = urllib.parse.urlparse(url)
    if p.query:
        key = p.path or "/"
        if job["path_qcounts"].get(key, 0) >= PATH_QUERY_CAP:
            return
        job["path_qcounts"][key] = job["path_qcounts"].get(key, 0) + 1
    job["queue"].append(url)


def _add_points(job: dict, page_url: str, html: str):
    forms = aegis_crawler.extract_forms(html, page_url)
    for point in aegis_crawler.build_points(page_url, forms, ""):
        key = (point["method"], point["url"], point["name"])
        if key in job["seen_points"] or len(job["points"]) >= MAX_POINTS:
            continue
        job["seen_points"].add(key)
        job["points"].append(point)


def _crawl_chunk(job: dict):
    session = job["session"]
    for _ in range(CRAWL_PER_POLL):
        if not job["queue"] or job["pages_crawled"] >= job["max_pages"]:
            break
        url = job["queue"].pop(0)
        if url in job["visited"]:
            continue
        job["visited"].add(url)
        try:
            resp = session.get(url)
        except Exception:  # noqa: BLE001 — dead page, keep crawling
            continue
        job["pages_crawled"] += 1
        if resp.status == 0 or not _is_html(resp):
            continue
        if len(resp.body or b"") > PAGE_SIZE_CAP:
            continue
        html = resp.text
        parser = _LinkParser(url)
        try:
            parser.feed(html)
        except Exception:  # noqa: BLE001 — malformed HTML, still use points
            pass
        for link in parser.links:
            _queue_url(job, link)
        _add_points(job, url, html)
    if not job["queue"] or job["pages_crawled"] >= job["max_pages"]:
        job["status"] = "scanning" if job["points"] else "done"


def _scan_chunk(job: dict):
    session = job["session"]
    for _ in range(SCAN_PER_POLL):
        if job["point_idx"] >= len(job["points"]):
            break
        point = job["points"][job["point_idx"]]
        job["point_idx"] += 1
        name = point["name"]
        try:
            sqli_hits = run_sqli_point(session, point, name,
                                       include_time=job["include_time"])
            xss_hits = xss.scan_point(session, point, name)
        except Exception:  # noqa: BLE001 — target hiccup, keep scanning
            continue
        for hit in sqli_hits + xss_hits:
            finding = _normalize(hit)
            finding["page"] = point["url"]
            job["findings"].append(finding)
    if job["point_idx"] >= len(job["points"]):
        job["status"] = "done"
