# Phase 6 — operational integration (first vertical slice)

This PR integrates previously isolated components:

1. Fetch CISA KEV or a selected FIRST EPSS CVE using existing read-only HTTP clients.
2. Parse and validate complete provider responses before any SQLite transaction.
3. Upsert typed enrichment evidence and query by exact CVE; replay is idempotent.
4. Parse a CycloneDX/SPDX package inventory, extract conservative supported PURL coordinates, and classify results from a successful exact OSV package-version query.
5. Offline tests cover import/replay/rollback, absent evidence, affected and no-known-advisory semantics.

**Not production complete:** This is an initial Phase 6 vertical slice. HTTP collectors need durable scheduling, Retry-After/ETag/backpressure, historical append-only evidence, freshness expiry, migrations, structured telemetry, health endpoints, and full integration with CLI workflows. PURL parsing is intentionally narrow, does not handle percent encoding or qualifiers, and must not be used as a full ecosystem version-range evaluator. Missing information is always Unknown. Issue #1 stays open.
