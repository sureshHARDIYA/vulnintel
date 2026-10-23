# VulnIntel

Rust-first, language-independent vulnerability intelligence engine for LAIS and RiskForge.

**Status: experimental skeleton; not a production vulnerability scanner.**

Pipeline: **Collect → Normalize → Deduplicate → Categorize → Enrich → Publish**.

Application-specific matching and AI investigation occur only after verified component/version evidence.

Workspace:
- `vulnintel-core`: offline advisory categorization and conservative same-ID deduplication
- `vulnintel-sources`: official source endpoint definitions (live collectors pending)
- `vulnintel-cli`: JSON stdin/stdout processing
- `knowledge/`: architecture, specification, publishing

Try: `cargo test --workspace`

See [architecture](knowledge/architecture.md), [specification](knowledge/specification.md), [publishing](knowledge/publishing.md).
