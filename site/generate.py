#!/usr/bin/env python3
"""Build a static, read-only advisory snapshot for GitHub Pages."""
import datetime
import json
import pathlib
import urllib.request

OUTPUT = pathlib.Path(__file__).parent / "public"
OUTPUT.mkdir(parents=True, exist_ok=True)
SOURCES = [
    ("github", "https://api.github.com/advisories?type=reviewed&per_page=100"),
    ("cisa_kev", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
]
status = {}
records = []
for name, url in SOURCES:
    try:
        request = urllib.request.Request(
            url, headers={"Accept": "application/json", "User-Agent": "vulnintel-pages/0.1"}
        )
        with urllib.request.urlopen(request, timeout=40) as response:
            payload = json.load(response)
        if name == "github":
            for item in payload:
                records.append({
                    "id": item.get("ghsa_id", ""),
                    "cve": item.get("cve_id"),
                    "summary": item.get("summary", ""),
                    "severity": item.get("severity"),
                    "published": item.get("published_at"),
                    "url": item.get("html_url"),
                    "source": "GitHub Advisories",
                })
            status[name] = {"ok": True, "count": len(payload)}
        else:
            known = payload.get("vulnerabilities", [])
            for item in known:
                records.append({
                    "id": item.get("cveID", ""),
                    "cve": item.get("cveID"),
                    "summary": item.get("shortDescription", ""),
                    "severity": "known exploited",
                    "published": item.get("dateAdded"),
                    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "source": "CISA KEV",
                })
            status[name] = {"ok": True, "count": len(known)}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        status[name] = {"ok": False, "error": type(exc).__name__}
        print(f"WARNING: {name} unavailable: {exc}", flush=True)

# An empty/error snapshot is not a valid publication. Fail so the previous site stays intact.
if not records or not all(s["ok"] for s in status.values()):
    raise SystemExit("Feed collection incomplete; preserving previously deployed site")
records.sort(key=lambda item: item.get("published") or "", reverse=True)
snapshot = {
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "sources": status,
    "description": "Public advisory samples; not complete coverage and not application exposure analysis.",
    "records": records,
}
(OUTPUT / "advisories.json").write_text(json.dumps(snapshot, ensure_ascii=False), encoding="utf-8")
print(f"Generated {len(records)} public advisory rows")
