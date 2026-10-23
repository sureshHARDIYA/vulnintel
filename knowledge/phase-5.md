# Phase 5 — threat intelligence enrichment

This milestone introduces source-specific typed KEV and EPSS observations and conservative exact-CVE joins.

- CISA KEV membership is evidence of known exploitation, with date added, catalog version and observation timestamp.
- FIRST EPSS is a predictive probability and percentile, with model date and observation timestamp. It is **not** proof of exploitation.
- Missing KEV/EPSS data remains absent, not a negative finding or a zero probability.
- Malformed CVE identifiers, duplicate feed records and out-of-range EPSS values fail validation.
- Offline tests cover exact joins, source freshness, missing records and malformed inputs.

Remaining Phase 5 work: connect the typed parser to persisted provider snapshots and scheduled feed retrieval; validate timestamps as dates; capture full immutable source assertions; preserve withdrawn/changed evidence; enforce freshness policies and expose queryable enrichment results. No production readiness claim is made.
