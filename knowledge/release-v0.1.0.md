# v0.1.0 — Experimental preview

**Status:** experimental prerelease, not production-ready. The initial release is intentionally not a stable release and does not trigger crates.io publication.

## Included
- Rust workspace with reusable core advisory models, conservative deduplication and source-aware normalization.
- Read-only clients for OSV, NVD, GitHub Advisories, CISA KEV and FIRST EPSS.
- Source assertion consolidation using explicit CVE aliases.
- Bounded page-ingestion primitives, SQLite durable records and resumable checkpoints.
- Initial CycloneDX 1.x and SPDX 2.x JSON component extraction and narrowly supported PURL-to-OSV matching.
- Type-safe KEV/EPSS CVE joins and SQLite-backed enrichment imports/queries with timestamps.
- OWASP ASVS CSV parser and static GitHub Pages advisory explorer.
- Workspace CI checks: cargo fmt, clippy, tests and core package validation.

## Known limitations
- No complete automated multi-source incremental synchronization scheduler or full backfill/retry/ETag/Retry-After strategy.
- SBOM matching does not implement full PURL/CPE canonicalization, percent-encoding or ecosystem-aware affected-version ranges.
- Source history is not append-only with withdrawals/conflicts and retention policies.
- Full migrations, PostgreSQL support, operational health/metrics/SLOs, circuit breakers and failure-injection coverage remain outstanding.
- CLI does not yet expose a complete SBOM-to-enriched-vulnerability production workflow.
- No claim of vulnerability exploitability or OWASP ASVS compliance.

See issue #1 for remaining acceptance criteria. This preview is intended for development, evaluation, and contributors only.
