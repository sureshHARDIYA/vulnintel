# VulnIntel

**VulnIntel** is a Rust-first, reusable toolkit for processing vulnerability intelligence into structured, searchable, and explainable security data. It is designed to help teams combine advisories from multiple sources, remove duplicates conservatively, assign useful categories, and prepare data for security dashboards, inventory correlation, and risk investigation.

It is suitable for software inventory tools, security operations dashboards, dependency-risk platforms, CI pipelines, internal developer portals, and vulnerability research workflows. The core is a Rust library; its CLI exchanges JSON so other languages can integrate without a dedicated service.

> **Project status: early experimental foundation.** The current implementation processes advisory JSON offline and includes first-stage live HTTP queries to official feeds, plus a package/version OSV query and an ASVS CSV parser. It does **not yet run full incremental synchronization**, normalize all upstream feeds, parse SBOMs, prove exploitability, or trigger AI investigations. Do not rely on it as a production vulnerability scanner.

## What it does today

- Represent advisories with IDs, aliases, summaries, ecosystems, severity labels, and source URLs.
- Deduplicate records with the **same primary ID**, preserving and combining aliases and source URLs. Cross-source alias matching is **not yet implemented**.
- Categorize advisories using multi-valued ecosystem and severity labels.
- Process JSON through a Rust library or a command-line tool.
- Query OSV, NVD, GitHub Advisories, CISA KEV and FIRST EPSS directly using the CLI (single requests, raw source JSON).
- Query OSV for a specific ecosystem/package/version and produce basic match evidence.
- Parse externally downloaded OWASP ASVS 5.0 CSV with `vulnintel-standards`.

### Intended processing pipeline

```text
Official sources → Collect → Normalize → Deduplicate → Categorize → Enrich → Publish
                                      ↓
                         Inventory matching (future)
                                      ↓
                     Evidence-based investigation (consumer-owned)
```

Automated incremental collection, cross-source normalization, durable synchronized feed storage and complete SBOM matching remain roadmap capabilities.

## Install and build

**Prerequisites:** Rust stable toolchain and Cargo. Install Rust from [rustup.rs](https://rustup.rs/).

```bash
git clone https://github.com/sureshHARDIYA/vulnintel.git
cd vulnintel
cargo build --workspace
cargo test --workspace
```

Run the CLI locally:

```bash
cargo run -p vulnintel-cli < advisories.json
```

Or install the CLI from the checked-out repository:

```bash
cargo install --path crates/vulnintel-cli
vulnintel-cli < advisories.json
```

**Registry publication:** Not yet confirmed. Until a release is published on crates.io, use a Git dependency or a local path dependency.

## Quick start

Create `advisories.json`:

```json
[
  {
    "id": "CVE-EXAMPLE-0001",
    "aliases": ["GHSA-EXAMPLE"],
    "summary": "Illustrative advisory, not a real CVE",
    "ecosystems": ["npm", "npm"],
    "severity": "HIGH",
    "source_urls": ["https://example.org/advisory"]
  },
  {
    "id": "CVE-EXAMPLE-0001",
    "aliases": [],
    "summary": "Duplicate example record",
    "ecosystems": ["npm"],
    "severity": "HIGH",
    "source_urls": ["https://example.org/second-source"]
  }
]
```

Run:

```bash
cargo run -q -p vulnintel-cli < advisories.json
```

The output is a JSON array containing a single advisory with merged source URLs and aliases, wrapped in a `CategorizedAdvisory` record with categories such as `ecosystem:npm` and `severity:high`. The current duplicate merge retains the first record's summary, ecosystems, and severity; it is **not** a complete conflict-resolution engine.

## Use as a Rust library

Add the core crate as a Git dependency in your application's `Cargo.toml`:

```toml
[dependencies]
vulnintel-core = { git = "https://github.com/sureshHARDIYA/vulnintel", branch = "main" }
```

Then call the offline processing functions:

```rust
use vulnintel_core::{categorize, deduplicate, Advisory};

fn main() {
    let advisories = vec![Advisory {
        id: "EXAMPLE-1".into(),
        aliases: vec![],
        summary: "Illustrative record".into(),
        ecosystems: vec!["PyPI".into()],
        severity: Some("HIGH".into()),
        source_urls: vec![],
    }];
    let results: Vec<_> = deduplicate(advisories)
        .into_iter()
        .map(categorize)
        .collect();
    println!("{results:#?}");
}
```

For Python, JavaScript, or other languages, invoke the CLI as a subprocess and exchange JSON over stdin/stdout. Native Python bindings, WebAssembly bindings, and HTTP adapters are potential future interfaces, **not currently shipped**.

## Configuration

The current core and CLI require **no API keys, network access, database, or environment variables**. Provide a JSON array of advisories using the schema shown above. The current CLI always performs exact-primary-ID deduplication followed by ecosystem/severity categorization; it has no runtime configuration flags yet.

The source crate implements first-stage, read-only HTTP requests against these official endpoints:

| Source | Purpose | Endpoint |
| --- | --- | --- |
| OSV | Package-version vulnerability queries | [OSV API](https://api.osv.dev/) |
| NVD | CVE records and metadata | [NVD API](https://nvd.nist.gov/developers/vulnerabilities) |
| CISA KEV | Known exploited vulnerabilities | [CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) |
| FIRST EPSS | Exploitation probability estimates | [EPSS API](https://www.first.org/epss/api) |
| GitHub Advisories | Public security advisories | [GitHub REST API](https://docs.github.com/en/rest/security-advisories/global-advisories) |

The source clients fetch upstream JSON, but are **not** yet a scheduled, paginated, normalized ingestion engine. A separate GitHub Actions smoke test checks source availability.

## Live feed examples

```bash
cargo run -p vulnintel-cli -- fetch github
cargo run -p vulnintel-cli -- fetch nvd
cargo run -p vulnintel-cli -- fetch kev
cargo run -p vulnintel-cli -- fetch epss CVE-2021-44228
cargo run -p vulnintel-cli -- fetch osv npm lodash 4.17.20
cargo run -p vulnintel-cli -- match npm lodash 4.17.20
```

NVD supports an optional `NVD_API_KEY` environment variable. Feed queries require internet access. See [source coverage and limitations](knowledge/source-coverage.md).

## Repository layout

```text
crates/
  vulnintel-core/       # Models, exact-ID deduplication, categorization
  vulnintel-sources/    # Source endpoint definitions
  vulnintel-cli/        # Offline JSON CLI
knowledge/
  architecture.md
  specification.md
  publishing.md
.github/workflows/
  ci.yml
  feed-smoke.yml
  release.yml
```

## Roadmap

1. Live collectors with pagination, caching, retries, and rate limiting.
2. Source-aware normalization and validated CVE/GHSA/OSV alias resolution.
3. Rich categorization and enrichment (KEV, EPSS, CVSS).
4. SBOM and lockfile matching with ecosystem-aware version semantics and evidence records.
5. Stable cross-language interfaces and optional storage/service adapters.

See [architecture](knowledge/architecture.md), [technical specification](knowledge/specification.md), and [publishing guide](knowledge/publishing.md).

## Security and responsible use

An advisory match is **not proof of exploitability**. A missing match is **not proof of safety**. Preserve source provenance, treat unknown inventory as unknown, and require human review for consequential remediation decisions.

## License

MIT — see [LICENSE-MIT](LICENSE-MIT).
