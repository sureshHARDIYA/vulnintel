# Normalization and consolidation — first milestone

The `vulnintel-core::normalization` module converts **GitHub global advisories**, **NVD CVE records** and **CISA KEV entries** into a common `UnifiedAdvisory` model.

Each record retains an array of source-specific `Evidence` assertions: source name, original ID, summary, published date, severity (where supplied) and known-exploited flag. No source's summary or severity silently replaces another source's statement.

## Example

```bash
cargo run -q -p vulnintel-cli -- fetch github > github.json
cargo run -q -p vulnintel-cli -- normalize github < github.json > normalized.json
```

The `consolidate` Rust function merges records by identical primary ID. GitHub records explicitly containing `cve_id` are keyed by that CVE, preserving the GHSA as an alias. An unlinked GHSA is not guessed to match any CVE.

**Limits:** This is an initial, in-memory consolidation primitive, not a complete identity graph. It does not yet merge a previously unlinked GHSA after new CVE mapping arrives, reject conflicting alias claims, parse OSV, interpret affected ranges, normalize CVSS, or manage withdrawn advisories. CISA KEV presence does not establish software exposure. Use this only for experimental read-only analysis.

## Next acceptance tests

- Add OSV and CVE List v5 normalization.
- Handle withdrawn/rejected records and aliases with provenance and conflict checks.
- Add a batch CLI for multiple source payloads in one run.
- Preserve affected packages, version ranges, CVSS, references, and modification timestamps.
- Persist immutable raw upstream assertions and rebuild unified records reproducibly.
