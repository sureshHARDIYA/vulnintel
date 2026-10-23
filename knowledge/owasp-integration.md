# OWASP data integration

OWASP does **not** provide a single official "latest CVEs" feed. VulnIntel should obtain fresh advisories from OSV, NVD, GitHub Advisories and vendor sources; OWASP resources provide standards and application-security context.

## Public OWASP ASVS data

OWASP ASVS 5.0.0 requirements are available as a version-pinned CSV:

```text
https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv
```

Try locally:

```bash
curl --fail --location --show-error \
  https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv \
  -o owasp-asvs-5.csv
head -n 3 owasp-asvs-5.csv
```

The data contains security verification requirements; it is **not** a vulnerability advisory feed. Mapping individual advisories to ASVS controls requires separate, reviewable logic.

## OWASP Dependency-Track

Dependency-Track is a separately deployed system with a REST API. Configure its base URL and an API key for integration tests:

- GitHub Actions repository variable `DTRACK_URL`: e.g. `https://dependency-track.example.com` (HTTPS only).
- GitHub Actions repository secret `DTRACK_API_KEY`: read-only API key authorized to query the instance.

The workflow `.github/workflows/owasp-feed-test.yml` checks the public ASVS CSV and, when both values are configured, queries `GET /api/version` with `X-Api-Key`. That confirms API connectivity, **not** retrieval of project findings. If either value is absent, the Dependency-Track check is explicitly skipped.

Run the workflow manually under GitHub Actions → **OWASP integration feed test** → **Run workflow**. It also runs weekly.

For actual vulnerability ingestion, use the separate official-source feed smoke test `.github/workflows/feed-smoke.yml`. Avoid double counting Dependency-Track findings that originate from those same primary sources.

## Future connector boundaries

- `sources/`: authoritative advisories and exploitation metadata
- `integrations/dependency_track/`: instance-specific projects, components, and findings
- `enrichment/owasp/`: standards and mappings, with provenance and version pinning

These are planned connector boundaries; the current Rust core does not yet implement them.
