# Phase 2 continuation: resumable NVD and GitHub ingestion

The new `vulnintel-sync::ingestion::run` function fetches at most `max_pages` pages through a caller-provided fetch closure. Each page is validated before it and its checkpoint are committed atomically in SQLite.

- GitHub uses page numbers (1-based); the current stopping condition is a short page. This is a simple snapshot traversal, not yet a complete Link-header-aware crawler.
- NVD uses `startIndex` (0-based) and `totalResults`; SQLite checkpoints encode NVD offsets as offset+1 to retain the existing positive-integer schema.
- Invalid response shapes, missing IDs, unexpected offsets and empty premature NVD pages fail without advancing the checkpoint.
- Unit tests cover successful continuation, completion, idempotent storage and failure rollback.
- The existing `vulnintel-sources::nvd_page` exposes an explicit startIndex API call. Callers can wire it to `run`; a full scheduled sync executable and provider throttling are not yet implemented.

**Important:** Page-based traversal over a changing public feed is not a reliable incremental update strategy by itself. Before production use, implement bounded updated-since windows (NVD), appropriate GitHub pagination semantics, retry-after and rate-limit handling, durable window/watermark state, deletion/withdrawal semantics and integration fixtures. A completed pass currently resets the page cursor to 1, and records are upserted rather than deleted.

This is a reviewed implementation milestone, not a production readiness declaration.
