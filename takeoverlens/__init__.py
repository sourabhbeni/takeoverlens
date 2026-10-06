"""TakeoverLens — subdomain takeover verification workbench."""

import os

__version__ = "0.1.0"


def _sanitize_no_proxy():
    """Drop NO_PROXY entries that break httpx's proxy parsing (bracketed IPv6, etc.)."""
    for var in ("NO_PROXY", "no_proxy"):
        val = os.environ.get(var)
        if not val:
            continue
        kept = [e.strip() for e in val.split(",") if e.strip() and "[" not in e and e.count(":") <= 1]
        os.environ[var] = ",".join(kept)


_sanitize_no_proxy()
