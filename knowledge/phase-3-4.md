# Phases 3 and 4 — combined implementation PR

This PR combines **initial incremental sync primitives** and **SBOM inventory parsing** into one reviewable change set.

## Phase 3 — implemented foundations
- NVD last-modified-window paginated HTTP client.
- SQLite `sync_windows` watermark table with atomic record upserts and completed-window advancement.
- Reject backward watermark movement, malformed timestamp shapes and empty record identifiers.
- Tests for rollback and monotonic watermark behavior.

**Not yet complete:** This PR does not wire a scheduled end-to-end collector to `finish_window`. A production sync must validate real calendar dates, enforce NVD's maximum date-window interval, fetch all pages before advancing the watermark, retain overlapping windows for late updates, handle GitHub's updated-since and Link pagination, implement ETags/304, Retry-After with jitter and durable backfill scheduling. Current source retry is basic exponential backoff.

## Phase 4 — implemented foundations
- `vulnintel-core::sbom::parse` extracts package inventories from CycloneDX JSON 1.x and SPDX JSON 2.x.
- Extracts names, versions, package URLs and CPE references when supplied.
- Missing or ambiguous exposure evidence remains `Unknown` rather than falsely asserting safety.
- Offline fixture tests for both formats and unsupported documents.

**Not yet complete:** Strict schema validation, SPDX 3.0, canonical PURL/CPE parsing, ecosystem-aware version/range evaluation, OSV matching integration, affected/no-known-match/unknown decisions based on verified evidence, and real SBOM-to-advisory E2E tests.

## Review criteria
This is a combined phases 3+4 **foundation PR**, not a claim that issue #1's complete acceptance criteria have been met. Do not mark either phase production-ready until the missing items above are delivered and CI passes.
