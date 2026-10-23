# Publish and integrate

## Local checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo package -p vulnintel-core --list
cargo publish -p vulnintel-core --dry-run
```

Check `vulnintel-core` name availability on https://crates.io and verify all manifest metadata. Commit the generated Cargo.lock for reproducible workspace CI.

## Publish

1. Create a crates.io account and API token.
2. Configure GitHub environment `crates-io` with required reviewers.
3. Add repository secret `CARGO_REGISTRY_TOKEN` (never commit credentials).
4. Run the manually triggered Release workflow with the exact crate version.
5. Publishing is irreversible for that version; do not release this skeleton as production-ready.

## LAIS Rust integration

For development:
```toml
[dependencies]
vulnintel-core = { git = "https://github.com/sureshHARDIYA/vulnintel", branch = "main" }
```

After publication:
```toml
[dependencies]
vulnintel-core = "0.1"
```

The current crate only categorizes offline advisories and deduplicates identical IDs. It does **not** fetch live feeds or determine vulnerable versions. Do not use it to make automated security decisions yet.
