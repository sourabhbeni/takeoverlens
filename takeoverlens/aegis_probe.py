"""Aegis engine adapter for the TakeoverLens probe.

Uses the `aegis` package (sourabhbeni/aegis): error/boolean/time-based SQLi +
24-probe reflected XSS with context classification. Findings are normalized to
the TakeoverLens probe shape. Indicators only — verify manually.

Time-based SQLi is opt-in (include_time) because each payload sleeps several
seconds; it is disabled by stubbing sqli.time_payloads to [] rather than
forking the engine.
"""

from aegis import crawler, sqli, xss
from aegis.http import Session

MAX_POINTS = 10


def _normalize(f: dict) -> dict:
    tech = f.get("technique", "")
    payload = f.get("payload", "")
    extra = f.get("evidence", "") or f.get("dbms", "")
    evidence = tech
    if payload:
        evidence += f" — payload {payload!r}"
    if extra:
        evidence += f" ({extra})"
    if f.get("evasion"):
        evidence += f" [evasion: {f['evasion']}]"
    return {
        "type": f.get("type", "unknown"),
        "param": f.get("parameter", "?"),
        "severity": str(f.get("severity", "Medium")).lower(),
        "evidence": evidence[:300],
    }


def run_sqli_point(session: Session, point: dict, name: str, level: int = 1,
                   include_time: bool = False) -> list:
    """Run Aegis error/boolean(/time) SQLi on one injection point."""
    if include_time:
        return sqli.scan_point(session, point, name, level=level)
    orig = sqli.time_payloads
    sqli.time_payloads = lambda delay: []  # noqa: E731 — skip slow phase
    try:
        return sqli.scan_point(session, point, name, level=level)
    finally:
        sqli.time_payloads = orig


def aegis_probe(target_url: str, include_time: bool = False, level: int = 1) -> dict:
    """Run the Aegis SQLi + XSS engines against a URL's query parameters."""
    session = Session(timeout=10, user_agent="takeoverlens/0.1")
    points = crawler.build_points(target_url, [], "")[:MAX_POINTS]
    if not points:
        return {
            "findings": [],
            "points": 0,
            "note": "No query parameters to test — paste a URL like https://site/search?q=test",
        }

    findings: list[dict] = []
    for point in points:
        name = point["name"]
        findings.extend(run_sqli_point(session, point, name, level, include_time))
        findings.extend(xss.scan_point(session, point, name, level=level))

    return {
        "findings": [_normalize(f) for f in findings],
        "points": len(points),
        "note": "Aegis engine — indicators only, verify manually before reporting. "
                "Same scope rules apply.",
    }
