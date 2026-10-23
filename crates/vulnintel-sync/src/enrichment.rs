//! Persist verified public threat intelligence from the existing source clients.
//! Fetches occur before transactions; failed downloads never replace prior records.
use crate::{Store, SyncResult};
use serde_json::Value;
use vulnintel_core::enrichment::{parse_epss, parse_kev, ThreatIntel};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportReport {
    pub provider: String,
    pub records: usize,
}

/// Import a complete CISA KEV snapshot. Invalid entries abort before any writes.
pub fn import_kev(store: &mut Store, feed: &Value, observed_at: &str) -> SyncResult<ImportReport> {
    let entries = parse_kev(feed, observed_at)?;
    let records: Vec<_> = entries
        .into_iter()
        .map(|(id, evidence)| Ok((id, serde_json::to_value(evidence)?)))
        .collect::<SyncResult<_>>()?;
    store.save_page("cisa_kev", &records, 1)?;
    Ok(ImportReport {
        provider: "cisa_kev".into(),
        records: records.len(),
    })
}

/// Import a complete or partial EPSS API response. Never interpret omitted CVEs as safe.
pub fn import_epss(store: &mut Store, feed: &Value, observed_at: &str) -> SyncResult<ImportReport> {
    let entries = parse_epss(feed, observed_at)?;
    let records: Vec<_> = entries
        .into_iter()
        .map(|(id, evidence)| Ok((id, serde_json::to_value(evidence)?)))
        .collect::<SyncResult<_>>()?;
    store.save_page("first_epss", &records, 1)?;
    Ok(ImportReport {
        provider: "first_epss".into(),
        records: records.len(),
    })
}

/// Return the persisted evidence for an explicit CVE, without inventing absent values.
pub fn threat_for_cve(store: &Store, cve: &str) -> SyncResult<ThreatIntel> {
    if !vulnintel_sources::valid_cve(cve) {
        return Err("Invalid CVE identifier".into());
    }
    let kev = store
        .read("cisa_kev", cve)?
        .map(serde_json::from_value)
        .transpose()?;
    let epss = store
        .read("first_epss", cve)?
        .map(serde_json::from_value)
        .transpose()?;
    Ok(ThreatIntel {
        cve: cve.into(),
        kev,
        epss,
    })
}

/// Fetch and import CISA KEV using the existing bounded HTTP client.
pub fn sync_kev(
    store: &mut Store,
    client: &reqwest::blocking::Client,
    observed_at: &str,
) -> SyncResult<ImportReport> {
    let feed = vulnintel_sources::cisa_kev(client)?;
    import_kev(store, &feed, observed_at)
}

/// Fetch and import a selected CVE's FIRST EPSS score.
pub fn sync_epss(
    store: &mut Store,
    client: &reqwest::blocking::Client,
    cve: &str,
    observed_at: &str,
) -> SyncResult<ImportReport> {
    let feed = vulnintel_sources::epss(client, cve)?;
    import_epss(store, &feed, observed_at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn offline_import_query_and_replay() {
        let mut store = Store::open(":memory:").unwrap();
        let kev = json!({"catalogVersion":"2026.10","vulnerabilities":[
            {"cveID":"CVE-2026-12345","dateAdded":"2026-10-20"}
        ]});
        let epss = json!({"data":[
            {"cve":"CVE-2026-12345","epss":"0.03","percentile":"0.7","date":"2026-10-22"}
        ]});
        import_kev(&mut store, &kev, "2026-10-23T08:00:00Z").unwrap();
        import_epss(&mut store, &epss, "2026-10-23T08:01:00Z").unwrap();
        import_kev(&mut store, &kev, "2026-10-23T08:00:00Z").unwrap();
        assert_eq!(store.count("cisa_kev").unwrap(), 1);
        let found = threat_for_cve(&store, "CVE-2026-12345").unwrap();
        assert!(found.kev.is_some());
        assert_eq!(found.epss.unwrap().probability, 0.03);
        assert!(threat_for_cve(&store, "CVE-2026-99999")
            .unwrap()
            .kev
            .is_none());
        let invalid = json!({"vulnerabilities":[{"cveID":"bad","dateAdded":"2026-10-20"}]});
        assert!(import_kev(&mut store, &invalid, "2026-10-23T08:02:00Z").is_err());
        assert_eq!(store.count("cisa_kev").unwrap(), 1);
    }
}
