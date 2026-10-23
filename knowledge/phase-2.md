# Phase 2: durable ingestion and synchronization

Implementation starts with an independent `vulnintel-sync` crate, storing source-specific raw JSON documents and a page checkpoint in SQLite. `Store::save_page()` writes a validated batch and checkpoint in **one SQLite transaction**, allowing replay after crashes and idempotent updates keyed by provider + source identifier. SQLite is bundled for portability. Tests cover resume, idempotence and transaction rollback.

## Architecture and boundaries

- `vulnintel-sources`: HTTP access to official public feeds
- `vulnintel-sync`: local durable provider records and checkpoints, no network or UI assumptions
- `vulnintel-core`: normalizers/consolidation and matching; consumer-specific exposure is separate

## Remaining within Phase 2

- Provider-specific pagination, safe termination, updated-since window and resumable page selection
- Respect NVD/GitHub rate limits and Retry-After, bounded exponential backoff with jitter, conditional GET and 304 handling
- Transactional database schema migrations, retention policies, raw observation history and conflict provenance
- Integration runner, safe cancellation and multi-process operation constraints
- Offline replay and fault injection; metrics and health reporting
- Tests against NVD / GitHub page fixtures, empty batches, failures and API schema changes

**Status:** This first change is the durable storage foundation, *not* complete continuous feed synchronization or production maturity. OSV is a package/version query API rather than a global latest-CVE stream. Secrets are not required for SQLite storage.
