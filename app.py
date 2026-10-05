"""TakeoverLens server: scan API + web UI. Passive recon only — nothing is claimed."""

import re

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from takeoverlens import __version__
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
