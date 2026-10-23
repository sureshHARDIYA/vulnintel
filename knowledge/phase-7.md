# Phase 7 — Reliable synchronization (incremental delivery)

## Delivered in this PR

- SQLite `record_observations` append-only journal, with an index by provider, record ID and observation sequence.
- Every successfully validated page appends the original upstream JSON alongside the current materialized record, within the same transaction as its checkpoint.
- Completed incremental windows likewise append observations atomically with the watermark.
- An invalid record rolls back both the materialized record update and any newly appended observations/checkpoint.
- `Store::observation_count` supports verification of evidence retention.

## Important limitations

This is the **first Phase 7 slice**, not the completed phase. It retains committed payload observations, but does not yet track explicit withdrawal events, source request metadata, or content hashes. Replaying the same page intentionally creates another observation. It does not implement a window-bound resumable cursor, Retry-After/ETag handling, rate-limit budgets, a production scheduler, metrics or circuit breakers. Follow-up PRs must cover those capabilities and restart/failure-injection scenarios before Phase 7 can be declared complete.

## Validation

`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and `cargo package -p vulnintel-core --allow-dirty` via CI.
