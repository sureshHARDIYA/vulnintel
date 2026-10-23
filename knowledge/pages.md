# Free GitHub Pages documentation and advisory explorer

The repository contains a plain static site in `site/public/`. A scheduled GitHub Action retrieves public GitHub Advisories and CISA KEV data and writes `advisories.json`. It deploys the site to GitHub Pages. The front-end has local search and source filtering, shows report dates and links back to authoritative advisories.

## Enable GitHub Pages (one-time)
1. Open **Repository Settings → Pages**.
2. Set **Build and deployment → Source → GitHub Actions**.
3. Open **Actions → Publish free documentation and advisory snapshot** and select **Run workflow**.
4. After a successful deployment, the expected Pages URL is `https://sureshhardiya.github.io/vulnintel/`. Check the workflow for the actual deployed URL.

The workflow also runs daily, and on changes to `site/**` or the Pages workflow. It does not publish Rust crates. The source feeds are public; no publishing token or paid hosting is needed.

The site is intentionally not a complete historical database. GitHub Advisories fetches the first 100 reviewed items, and CISA KEV provides its catalog. If either feed fails, the workflow fails without replacing the previous successful snapshot. NVD/OSV/EPSS remain directly available through the Rust CLI.

## Trust boundary
Public snapshots only. No secrets, private application inventory, internal findings, or credentials are published. Original URLs are linked for verification. Do not mistake public advisories for confirmed exposure.
