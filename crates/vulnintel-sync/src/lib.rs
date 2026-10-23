//! Durable, transaction-based storage for public advisory snapshots and pagination state.
//! A successful page commit atomically saves source records and the next page cursor.

pub mod enrichment;
pub mod ingestion;
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde_json::Value;
use std::path::Path;

pub type SyncResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> SyncResult<Self> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS records (
                provider TEXT NOT NULL,
                record_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                observed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                PRIMARY KEY(provider, record_id)
             );
             CREATE TABLE IF NOT EXISTS sync_windows (
                provider TEXT PRIMARY KEY,
                completed_through TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
             );
             CREATE TABLE IF NOT EXISTS checkpoints (
                provider TEXT PRIMARY KEY,
                page INTEGER NOT NULL CHECK (page >= 1),
                updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
             );",
        )?;
        Ok(Self { conn })
    }

    pub fn page(&self, provider: &str) -> SyncResult<u32> {
        let page: Option<i64> = self
            .conn
            .query_row(
                "SELECT page FROM checkpoints WHERE provider = ?1",
                [provider],
                |row| row.get(0),
            )
            .optional()?;
        Ok(page.unwrap_or(1).try_into()?)
    }

    /// Commit a validated provider page with a checkpoint atomically.
    /// The caller must validate identifiers and calculate the next page from the API response.
    pub fn save_page(
        &mut self,
        provider: &str,
        records: &[(String, Value)],
        next_page: u32,
    ) -> SyncResult<()> {
        if provider.is_empty() || next_page == 0 {
            return Err("Invalid provider or checkpoint".into());
        }
        let tx = self.conn.transaction()?;
        persist(&tx, provider, records, next_page)?;
        tx.commit()?;
        Ok(())
    }

    /// Latest fully committed UTC window end, or None for an initial backfill.
    pub fn completed_through(&self, provider: &str) -> SyncResult<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT completed_through FROM sync_windows WHERE provider = ?1",
                [provider],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Atomically commit a completed incremental window and all its validated records.
    /// Incomplete windows must never advance this watermark.
    pub fn finish_window(
        &mut self,
        provider: &str,
        records: &[(String, Value)],
        completed_through: &str,
    ) -> SyncResult<()> {
        if provider.is_empty() || !valid_utc_timestamp(completed_through) {
            return Err("Provider and RFC3339 UTC timestamp required".into());
        }
        if let Some(previous) = self.completed_through(provider)? {
            if completed_through < previous.as_str() {
                return Err("Window watermark cannot move backwards".into());
            }
        }
        let tx = self.conn.transaction()?;
        for (id, payload) in records {
            if id.is_empty() {
                return Err("Record ID cannot be empty".into());
            }
            tx.execute(
                "INSERT INTO records(provider, record_id, payload) VALUES (?1, ?2, ?3)
                 ON CONFLICT(provider, record_id) DO UPDATE SET
                    payload = excluded.payload,
                    observed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
                params![provider, id, serde_json::to_string(payload)?],
            )?;
        }
        tx.execute(
            "INSERT INTO sync_windows(provider, completed_through) VALUES (?1, ?2)
             ON CONFLICT(provider) DO UPDATE SET
                completed_through = excluded.completed_through,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
            params![provider, completed_through],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn count(&self, provider: &str) -> SyncResult<u64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM records WHERE provider = ?1",
            [provider],
            |row| row.get(0),
        )?)
    }

    pub fn read(&self, provider: &str, record_id: &str) -> SyncResult<Option<Value>> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT payload FROM records WHERE provider = ?1 AND record_id = ?2",
                params![provider, record_id],
                |row| row.get(0),
            )
            .optional()?;
        raw.map(|text| serde_json::from_str(&text).map_err(Into::into))
            .transpose()
    }
}

fn valid_utc_timestamp(value: &str) -> bool {
    value.len() == 20
        && value.ends_with('Z')
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value.as_bytes()[10] == b'T'
        && value.as_bytes()[13] == b':'
        && value.as_bytes()[16] == b':'
        && value
            .bytes()
            .enumerate()
            .all(|(i, b)| matches!(i, 4 | 7 | 10 | 13 | 16 | 19) || b.is_ascii_digit())
}

fn persist(
    tx: &Transaction<'_>,
    provider: &str,
    records: &[(String, Value)],
    next_page: u32,
) -> SyncResult<()> {
    for (id, payload) in records {
        if id.is_empty() {
            return Err("Record ID cannot be empty".into());
        }
        tx.execute(
            "INSERT INTO records (provider, record_id, payload) VALUES (?1, ?2, ?3)
             ON CONFLICT(provider, record_id) DO UPDATE SET
                payload = excluded.payload,
                observed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
            params![provider, id, serde_json::to_string(payload)?],
        )?;
    }
    tx.execute(
        "INSERT INTO checkpoints(provider, page) VALUES (?1, ?2)
         ON CONFLICT(provider) DO UPDATE SET
            page = excluded.page,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        params![provider, next_page],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn window_watermark_commits_atomically() {
        let mut store = Store::open(":memory:").unwrap();
        let records = vec![("CVE-2026-1234".into(), json!({"id":"CVE-2026-1234"}))];
        store
            .finish_window("nvd", &records, "2026-10-23T00:00:00Z")
            .unwrap();
        assert_eq!(
            store.completed_through("nvd").unwrap().as_deref(),
            Some("2026-10-23T00:00:00Z")
        );
        let invalid = vec![("".into(), json!({}))];
        assert!(store
            .finish_window("nvd", &invalid, "2026-10-24T00:00:00Z")
            .is_err());
        assert_eq!(
            store.completed_through("nvd").unwrap().as_deref(),
            Some("2026-10-23T00:00:00Z")
        );
        assert!(store
            .finish_window("nvd", &records, "2026-10-22T00:00:00Z")
            .is_err());
    }

    #[test]
    fn idempotent_storage_and_resume() {
        let mut store = Store::open(":memory:").unwrap();
        let page = vec![("CVE-2024-12345".into(), json!({"id":"CVE-2024-12345"}))];
        store.save_page("nvd", &page, 2).unwrap();
        store.save_page("nvd", &page, 2).unwrap();
        assert_eq!(store.count("nvd").unwrap(), 1);
        assert_eq!(store.page("nvd").unwrap(), 2);
        assert!(store.read("nvd", "CVE-2024-12345").unwrap().is_some());
    }

    #[test]
    fn rejects_empty_id_without_advancing_checkpoint() {
        let mut store = Store::open(":memory:").unwrap();
        let invalid = vec![("".into(), json!({"error":true}))];
        assert!(store.save_page("nvd", &invalid, 4).is_err());
        assert_eq!(store.page("nvd").unwrap(), 1);
        assert_eq!(store.count("nvd").unwrap(), 0);
    }
}
