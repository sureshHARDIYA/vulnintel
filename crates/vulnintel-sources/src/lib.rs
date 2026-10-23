//! Read-only vulnerability intelligence clients. No external security platform required.
//! Results preserve the upstream JSON: normalization is a separate responsibility.
use reqwest::blocking::{Client, RequestBuilder};
use serde_json::{json, Value};
use std::{error::Error, thread, time::Duration};

pub const OSV_API: &str = "https://api.osv.dev/v1/query";
pub const NVD_API: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
pub const CISA_KEV_JSON: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
pub const FIRST_EPSS_API: &str = "https://api.first.org/data/v1/epss";
pub const GITHUB_ADVISORIES_API: &str = "https://api.github.com/advisories";

pub type FeedResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

pub fn client() -> FeedResult<Client> {
    Ok(Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("vulnintel/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

/// Retries temporary HTTP 429 and 5xx failures with bounded backoff.
/// Does not retry other client errors or malformed responses.
fn request(mut make: impl FnMut() -> RequestBuilder) -> FeedResult<Value> {
    for attempt in 0..3 {
        let response = make().send()?;
        let status = response.status();
        if (status.as_u16() == 429 || status.is_server_error()) && attempt < 2 {
            thread::sleep(Duration::from_secs(1 << attempt));
            continue;
        }
        return Ok(response.error_for_status()?.json()?);
    }
    unreachable!()
}

pub fn github_advisories(client: &Client, page: u32, per_page: u8) -> FeedResult<Value> {
    let page = page.max(1);
    let per_page = per_page.clamp(1, 100);
    request(|| {
        client
            .get(GITHUB_ADVISORIES_API)
            .query(&[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
            ])
            .header("Accept", "application/vnd.github+json")
    })
}

pub fn nvd_recent(
    client: &Client,
    results_per_page: u16,
    api_key: Option<&str>,
) -> FeedResult<Value> {
    let count = results_per_page.clamp(1, 2000);
    request(|| {
        let req = client.get(NVD_API).query(&[("resultsPerPage", count)]);
        if let Some(key) = api_key {
            req.header("apiKey", key)
        } else {
            req
        }
    })
}

pub fn cisa_kev(client: &Client) -> FeedResult<Value> {
    request(|| client.get(CISA_KEV_JSON))
}

pub fn epss(client: &Client, cve: &str) -> FeedResult<Value> {
    if !valid_cve(cve) {
        return Err("Expected a CVE identifier".into());
    }
    request(|| client.get(FIRST_EPSS_API).query(&[("cve", cve)]))
}

pub fn osv_package(
    client: &Client,
    ecosystem: &str,
    package: &str,
    version: &str,
) -> FeedResult<Value> {
    if ecosystem.is_empty() || package.is_empty() || version.is_empty() {
        return Err("Ecosystem, package and version are required".into());
    }
    let payload = json!({"package":{"ecosystem":ecosystem,"name":package},"version":version});
    request(|| client.post(OSV_API).json(&payload))
}

pub fn valid_cve(id: &str) -> bool {
    let parts: Vec<&str> = id.split('-').collect();
    parts.len() == 3
        && parts[0] == "CVE"
        && parts[1].len() == 4
        && parts[1].chars().all(|c| c.is_ascii_digit())
        && parts[2].len() >= 4
        && parts[2].chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_cve_ids() {
        assert!(valid_cve("CVE-2024-12345"));
        assert!(!valid_cve("not-a-cve"));
    }
}
