# Architecture decision

```mermaid
flowchart TD
 A[OSV / NVD / GitHub / CISA / EPSS] --> B[Source adapters]
 B --> C[Normalize with provenance]
 C --> D[Conservative deduplication]
 D --> E[Multi-label categorization]
 E --> F[Enrichment]
 F --> G[Rust crate / CLI / JSON]
 G --> H[LAIS Rust backend]
 G --> I[RiskForge future consumer]
 H --> J[SBOM and runtime matching]
 J --> K{Affected component and version verified?}
 K -- No --> L[Global feed only / inventory gap]
 K -- Yes --> M[Evidence-gated investigation event]
 M --> N[Read-only agent and human review]
```

## Boundaries

- No AI is used for collection, normalization, or categorization.
- A component version match does not prove reachability or exploitability.
- Unknown component versions remain unknown, never safe.
- Keep all source identifiers, URLs, timestamps and original source records.
- Do not deduplicate by title similarity. Alias resolution requires validated identity mappings.
- Categories are multiple tags per canonical advisory, not duplicate records.
- Network, storage, scheduling and credentials stay outside the portable core.
- RiskForge tenant inventory and authorization must remain isolated.
