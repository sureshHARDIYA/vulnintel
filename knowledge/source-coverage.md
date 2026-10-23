# Source coverage and maturity (October 2026)

## Implemented first-stage clients

`vulnintel-sources` exposes read-only HTTP calls for OSV package/version queries, NVD CVE pages, GitHub reviewed advisories, CISA KEV, and FIRST EPSS per CVE. Requests have a 30-second timeout and bounded retries for HTTP 429/5xx. Responses are returned as **unmodified upstream JSON**, not yet normalized or persisted by collectors. GitHub and NVD functions fetch a **single page**; there is no incremental synchronization yet.

Examples from repository root:

```bash
cargo run -p vulnintel-cli -- fetch github
cargo run -p vulnintel-cli -- fetch nvd
cargo run -p vulnintel-cli -- fetch kev
cargo run -p vulnintel-cli -- fetch epss CVE-2021-44228
cargo run -p vulnintel-cli -- fetch osv npm lodash 4.17.20
cargo run -p vulnintel-cli -- match npm lodash 4.17.20
```

NVD supports optional `NVD_API_KEY` for higher quotas. No token is needed for public GitHub advisories, but unauthenticated limits apply. **Do not use `CARGO_REGISTRY_TOKEN` for feed access**.

`vulnintel-core::matching` exposes an evidence record based on a successful OSV package/version query; empty OSV matches mean only "no known matching advisory", not that a package is safe. `vulnintel-core::storage` provides local JSON snapshots; it is not a multi-writer database or a scheduler. `vulnintel-standards` parses externally supplied ASVS 5 CSV; it does not bundle ASVS data or make automatic vulnerability-to-control claims.

## Additional sources to consider

| Priority | Source | Why |
| --- | --- | --- |
| High | CVE Program / CVE List v5 | CNA-published records and affected-product details; may precede NVD analysis |
| High | ENISA EUVD | EU vulnerability records and exploited-vulnerability intelligence |
| High | Vendor CSAF / VEX (Red Hat, Microsoft, Cisco, etc.) | Product-specific fixed/affected/not-affected statements |
| Medium | OSV ecosystem data (including RustSec, PyPA) | Package-level advisories; **already often covered by OSV**, avoid double counting |
| Medium | GitLab Advisory Database | Additional dependency intelligence; deduplicate overlap with GHSA/NVD |
| Medium | CWE and CAPEC catalogs | Weakness and attack-pattern enrichment, not new vulnerability feeds |
| Optional | OSSF malicious package intelligence | Malware detection is a separate taxonomy from vulnerabilities |

Prefer primary publishers where practical; always preserve origin and licensing metadata. Do not treat republished feeds as independent corroboration. NVD now exposes additional SSVC and affected metadata; preserve these fields rather than overwriting source evidence.

## Remaining production work

- Scheduled incremental pagination and checkpoint-based ingestion; rate-limit-aware retry-after handling
- Normalization to one versioned schema, alias validation and provenance/conflict resolution
- Full SBOM parsing (CycloneDX/SPDX), PURL parsing, ecosystem-aware version range matching, CPE support
- Persistent indexed storage with migrations, transactions, backfills and retention
- KEV/EPSS joins with observation dates and stale-data policy
- ASVS version management and evidence-backed mappings
- Structured tracing, metrics, alerting, fault injection, fixture-based integration tests and API stability

**Do not treat this release as production-ready** until those capabilities and end-to-end tests are in place.
