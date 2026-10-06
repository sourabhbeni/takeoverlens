"""TakeoverLens server: scan API, SQLi/XSS probe API, web UI."""

import re
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from takeoverlens import __version__
from takeoverlens.probe import probe_url
from takeoverlens.scanner import get_scan, start_scan

app = FastAPI(title="TakeoverLens", version=__version__)
app.mount("/static", StaticFiles(directory="static"), name="static")

DOMAIN_RE = re.compile(
    r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


class ScanRequest(BaseModel):
    domain: str
    extra_subdomains: list[str] = []
    authorized: bool = False


class ProbeRequest(BaseModel):
    url: str
    authorized: bool = False


@app.get("/")
def index():
    return FileResponse("static/index.html")


@app.post("/api/scans")
def create_scan(req: ScanRequest):
    domain = req.domain.strip().lower().rstrip(".")
    # tolerate pasted URLs: strip scheme/path
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    if not DOMAIN_RE.match(domain):
        raise HTTPException(400, "Invalid domain (e.g. example.com)")
    if not req.authorized:
        raise HTTPException(400, "Confirm you are authorized to test this domain")
    scan_id = start_scan(domain, req.extra_subdomains)
    return {"scan_id": scan_id}


@app.get("/api/scans/{scan_id}")
def scan_status(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Unknown scan id")
    return scan


@app.post("/api/probe")
def probe(req: ProbeRequest):
    # Active probing — indicators only, same authorization bar as scans.
    if not req.authorized:
        raise HTTPException(400, "Confirm you are authorized to test this URL")
    try:
        parts = urlparse(req.url.strip())
    except Exception:  # noqa: BLE001
        raise HTTPException(400, "Invalid URL")
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise HTTPException(400, "Only http(s) URLs")
    host = parts.hostname.lower()
    if host == "localhost" or host.startswith("127.") or host == "::1":
        raise HTTPException(400, "Loopback targets blocked")
    result = probe_url(req.url.strip())
    return {"url": req.url.strip(), **result}
