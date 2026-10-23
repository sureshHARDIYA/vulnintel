# Functional specification v0.1

1. **Collect:** incremental source polling, rate limits, pagination, retry/backoff and checkpoints.
2. **Normalize:** canonical advisory model plus immutable source provenance.
3. **Deduplicate:** exact IDs and validated CVE/GHSA/OSV alias relationships; preserve conflicting source evidence.
4. **Categorize:** ecosystem, vendor, severity, publication window, exploitation status, product family.
5. **Enrich:** CVSS, CISA KEV status and EPSS probability with observation dates.
6. **Publish:** versioned JSON schema, Rust API and CLI; Python bindings optional later.
7. **Match:** SBOM/PURL, CPE, runtime versions, ecosystem-specific version ranges, uncertainty.
8. **Investigate:** only verified affected component/version matches trigger read-only, auditable consumer-owned agents.

## Official endpoints

| Source | URL | Use |
|---|---|---|
| OSV | https://api.osv.dev/v1/querybatch | Package/version matching |
| NVD | https://services.nvd.nist.gov/rest/json/cves/2.0 | CVE metadata |
| CISA KEV | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | Known exploitation |
| FIRST EPSS | https://api.first.org/data/v1/epss | Exploitation probability |
| GitHub | https://api.github.com/advisories | Ecosystem advisories |

Vendor runtime advisories require additional adapters. Source endpoints here are constants; network collectors are not implemented yet.

## Proposed normalized output

```json
{
  "schema_version": "1.0",
  "canonical_id": "CVE-EXAMPLE",
  "aliases": ["GHSA-EXAMPLE"],
  "categories": ["ecosystem:npm", "severity:critical"],
  "sources": [{"name":"osv","url":"https://osv.dev/","retrieved_at":"ISO-8601"}],
  "affected_components": [],
  "kev": false,
  "epss": null,
  "inventory_match": "not_evaluated"
}
```

## Acceptance criteria

- Idempotent collection, no silent provenance loss or mistaken title-based merging.
- Correct ecosystem-specific version boundaries; unknown stays unknown.
- Separate published, modified, first-seen and fetched timestamps.
- Metrics for feed lag, ingestion errors, match quality and agent-trigger decisions.
- No automatic remediation or agent invocation in the intelligence core.
- Test fixtures for withdrawn advisories, contradictory aliases, stale feeds and duplicates.
