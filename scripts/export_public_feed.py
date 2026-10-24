#!/usr/bin/env python3
"""Generate a source-attributed JSON feed using the VulnIntel normalizer."""
import datetime as dt
import json
import subprocess
import urllib.request
from pathlib import Path

def fetch(url):
    headers = {"User-Agent": "VulnIntel-feed", "Accept": "application/vnd.github+json"}
    if url.startswith("https://api.github.com/"):
        import os
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=40) as response:
        return json.load(response)

def main():
    github = fetch("https://api.github.com/advisories?type=reviewed&per_page=100")
    kev = fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    result = subprocess.run(["cargo", "run", "--quiet", "-p", "vulnintel-cli", "--", "normalize", "github"],
                            input=json.dumps(github), capture_output=True, text=True, check=True)
    known = {item["cveID"] for item in kev["vulnerabilities"]}
    advisories = []
    for record in json.loads(result.stdout):
        evidence = record["evidence"][0]
        advisories.append({"id": record["id"], "aliases": record["aliases"], "summary": evidence["summary"] or "",
            "severity": (evidence["severity"] or "unknown").lower(), "published": evidence["published"],
            "known_exploited": record["id"] in known, "source": "GitHub Advisory Database",
            "url": "https://github.com/advisories/" + evidence["source_id"]})
    if not advisories:
        raise RuntimeError("Refusing to publish an empty feed")
    advisories.sort(key=lambda x: x["published"] or "", reverse=True)
    payload = {"schema_version": 1, "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
               "sources": ["GitHub Advisory Database", "CISA KEV"], "count": len(advisories), "advisories": advisories}
    output = Path("public-feed/vulnerabilities.json")
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(payload, indent=2) + "\n")
    print("Generated", len(advisories), "advisories")

if __name__ == "__main__":
    main()
