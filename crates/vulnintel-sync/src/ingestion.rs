//! Bounded, resumable page ingestion. Store advances only after a validated response.
use crate::{Store, SyncResult};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Github,
    Nvd,
}

impl Provider {
    fn key(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Nvd => "nvd",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReport {
    pub provider: String,
    pub pages: u32,
    pub records: usize,
    pub next_cursor: u32,
    pub complete: bool,
}

type ParsedPage = (Vec<(String, Value)>, u32, bool);

fn parse_page(
    provider: Provider,
    data: &Value,
    cursor: u32,
    limit: u32,
) -> SyncResult<ParsedPage> {
    match provider {
        Provider::Github => {
            let items = data
                .as_array()
                .ok_or("GitHub API response must be an array")?;
            if items.len() > limit as usize {
                return Err("GitHub page exceeds requested limit".into());
            }
            let mut records = Vec::with_capacity(items.len());
            for item in items {
                let id = item
                    .get("ghsa_id")
                    .and_then(Value::as_str)
                    .ok_or("Missing ghsa_id")?;
                if !id.starts_with("GHSA-") {
                    return Err("Invalid ghsa_id".into());
                }
                records.push((id.to_owned(), item.clone()));
            }
            let complete = items.len() < limit as usize;
            let next = if complete {
                1
            } else {
                cursor.checked_add(1).ok_or("Page overflow")?
            };
            Ok((records, next, complete))
        }
        Provider::Nvd => {
            let items = data
                .get("vulnerabilities")
                .and_then(Value::as_array)
                .ok_or("NVD response missing vulnerabilities")?;
            let total = data
                .get("totalResults")
                .and_then(Value::as_u64)
                .ok_or("NVD response missing totalResults")?;
            let offset = data
                .get("startIndex")
                .and_then(Value::as_u64)
                .ok_or("NVD response missing startIndex")?;
            if offset != u64::from(cursor) || items.len() > limit as usize {
                return Err("Unexpected NVD pagination response".into());
            }
            let mut records = Vec::with_capacity(items.len());
            for item in items {
                let cve = item.get("cve").ok_or("NVD record missing cve")?;
                let id = cve
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or("NVD record missing id")?;
                if !vulnintel_sources::valid_cve(id) {
                    return Err("Invalid NVD CVE identifier".into());
                }
                records.push((id.to_owned(), item.clone()));
            }
            let next_offset = offset
                .checked_add(items.len() as u64)
                .ok_or("NVD offset overflow")?;
            if next_offset < total && items.is_empty() {
                return Err("NVD returned empty page before totalResults".into());
            }
            let complete = next_offset >= total;
            let next = if complete {
                1
            } else {
                u32::try_from(next_offset)?
            };
            Ok((records, next, complete))
        }
    }
}

/// Ingest at most `max_pages` pages using an injected fetcher (testable without HTTP).
/// GitHub uses 1-based page numbers; NVD uses 0-based startIndex internally,
/// encoded in storage as offset+1 to satisfy the existing checkpoint schema.
pub fn run<F>(
    store: &mut Store,
    provider: Provider,
    limit: u32,
    max_pages: u32,
    mut fetch: F,
) -> SyncResult<SyncReport>
where
    F: FnMut(u32, u32) -> SyncResult<Value>,
{
    if limit == 0 || max_pages == 0 || limit > 100 {
        return Err("limit must be 1..=100 and max_pages positive".into());
    }
    let key = provider.key();
    let mut cursor = store.page(key)?;
    let mut total_records = 0;
    let mut pages = 0;
    let mut complete = false;
    for _ in 0..max_pages {
        let api_cursor = if provider == Provider::Nvd {
            cursor - 1
        } else {
            cursor
        };
        let data = fetch(api_cursor, limit)?;
        let (records, next, finished) = parse_page(provider, &data, api_cursor, limit)?;
        let checkpoint = if provider == Provider::Nvd && !finished {
            next.checked_add(1).ok_or("NVD checkpoint overflow")?
        } else {
            next
        };
        store.save_page(key, &records, checkpoint)?;
        total_records += records.len();
        pages += 1;
        cursor = checkpoint;
        complete = finished;
        if complete {
            break;
        }
    }
    Ok(SyncReport {
        provider: key.to_owned(),
        pages,
        records: total_records,
        next_cursor: cursor,
        complete,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn github_resume_and_completion() {
        let mut store = Store::open(":memory:").unwrap();
        let first = run(&mut store, Provider::Github, 1, 1, |page, _| {
            assert_eq!(page, 1);
            Ok(json!([{"ghsa_id":"GHSA-aaaa-bbbb-cccc"}]))
        })
        .unwrap();
        assert!(!first.complete);
        assert_eq!(store.page("github").unwrap(), 2);
        let second = run(&mut store, Provider::Github, 1, 2, |page, _| {
            assert_eq!(page, 2);
            Ok(json!([]))
        })
        .unwrap();
        assert!(second.complete);
        assert_eq!(store.page("github").unwrap(), 1);
        assert_eq!(store.count("github").unwrap(), 1);
    }

    #[test]
    fn nvd_offset_and_transaction_rollback() {
        let mut store = Store::open(":memory:").unwrap();
        run(&mut store, Provider::Nvd, 1, 1, |offset, _| {
            assert_eq!(offset, 0);
            Ok(json!({"startIndex":0,"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2024-12345"}}]}))
        })
        .unwrap();
        assert_eq!(store.page("nvd").unwrap(), 2);
        let failed = run(&mut store, Provider::Nvd, 1, 1, |offset, _| {
            assert_eq!(offset, 1);
            Ok(
                json!({"startIndex":1,"totalResults":2,"vulnerabilities":[{"cve":{"id":"invalid"}}]}),
            )
        });
        assert!(failed.is_err());
        assert_eq!(store.page("nvd").unwrap(), 2);
        assert_eq!(store.count("nvd").unwrap(), 1);
        let last = run(&mut store, Provider::Nvd, 1, 1, |offset, _| {
            assert_eq!(offset, 1);
            Ok(json!({"startIndex":1,"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2024-12346"}}]}))
        })
        .unwrap();
        assert!(last.complete);
        assert_eq!(store.count("nvd").unwrap(), 2);
    }
}
