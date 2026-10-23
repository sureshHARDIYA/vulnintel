# OWASP public security standards

VulnIntel is a standalone vulnerability intelligence toolkit. It does **not** require a Dependency-Track server, URL, or API key.

OWASP does not operate a general-purpose latest-CVE feed. Use OSV, NVD, GitHub Advisories, vendor advisories, CISA KEV, and FIRST EPSS for advisory and exploitation intelligence.

## OWASP ASVS

OWASP ASVS provides publicly accessible security verification requirements. The version-pinned machine-readable CSV is:

```text
https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv
```

Download a test sample:

```bash
curl -fL https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv -o owasp-asvs.csv
head -n 3 owasp-asvs.csv
```

The GitHub Actions workflow `.github/workflows/owasp-feed-test.yml` validates the CSV structure and requires no credentials. It is a connectivity test, **not** an implemented Rust enrichment adapter.

ASVS is a control catalog, not a vulnerability feed. Any future mappings between advisory findings and ASVS requirements must be evidence-backed and preserve the version of the standard.

## Integration philosophy

The core library must remain self-contained, with no requirement for external application instances. Optional adapters for external products can be added separately if users need them; they must never become prerequisites for the core engine.
