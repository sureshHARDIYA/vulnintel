//! Persist the identity of an incremental source window with its page cursor.
//! A resumed run must use exactly the same bounds to avoid silently skipping pages.
use crate::{persist, valid_utc_timestamp, Store, SyncResult};
use rusqlite::{params, OptionalExtension};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveWindow {
    pub start: String,
    pub end: String,
    pub next_cursor: u32,
}

impl Store {
    /// Create a new window or resume the existing one. Never silently replace its bounds.
    pub fn begin_window(&mut self, provider: &str, start: &str, end: &str) -> SyncResult<ActiveWindow> {
        if provider.is_empty() || !valid_utc_timestamp(start) || !valid_utc_timestamp(end) || start >= end {
            return Err("Valid provider and ordered UTC window bounds required".into());
        }
        if let Some(existing) = self.active_window(provider)? {
            if existing.start != start || existing.end != end {
                return Err("Unfinished source window must be resumed or explicitly recovered".into());
            }
            return Ok(existing);
        }
        if let Some(previous) = self.completed_through(provider)? {
            if start < previous.as_str() {
                return Err("Window cannot start before completed watermark".into());
            }
        }
        self.conn.execute(
            "INSERT INTO active_windows(provider, window_start, window_end, next_cursor) VALUES (?1, ?2, ?3, 1)",
            params![provider, start, end],
        )?;
        Ok(ActiveWindow { start: start.into(), end: end.into(), next_cursor: 1 })
    }

    pub fn active_window(&self, provider: &str) -> SyncResult<Option<ActiveWindow>> {
        let raw: Option<(String, String, i64)> = self.conn.query_row(
            "SELECT window_start, window_end, next_cursor FROM active_windows WHERE provider = ?1",
            [provider],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional()?;
        raw.map(|(start, end, cursor)| Ok(ActiveWindow { start, end, next_cursor: cursor.try_into()? })).transpose()
    }

    /// Commit source observations and the in-progress cursor in one SQLite transaction.
    pub fn save_window_page(&mut self, provider: &str, records: &[(String, Value)], expected_cursor: u32, next_cursor: u32) -> SyncResult<()> {
        if next_cursor <= expected_cursor {
            return Err("Window cursor must advance".into());
        }
        let tx = self.conn.transaction()?;
        let current: Option<i64> = tx.query_row(
            "SELECT next_cursor FROM active_windows WHERE provider = ?1",
            [provider], |row| row.get(0),
        ).optional()?;
        if current != Some(i64::from(expected_cursor)) {
            return Err("Window cursor changed or no active window exists".into());
        }
        persist(&tx, provider, records, next_cursor)?;
        tx.execute(
            "UPDATE active_windows SET next_cursor = ?2, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE provider = ?1",
            params![provider, next_cursor],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Mark a fully processed window complete. No page may be omitted.
    /// The caller must establish upstream completion before invoking this method.
    pub fn complete_active_window(&mut self, provider: &str, expected_cursor: u32) -> SyncResult<()> {
        let window = self.active_window(provider)?.ok_or("No active window")?;
        if window.next_cursor != expected_cursor {
            return Err("Window completion cursor mismatch".into());
        }
        if let Some(previous) = self.completed_through(provider)? {
            if window.end.as_str() < previous.as_str() {
                return Err("Window watermark cannot move backwards".into());
            }
        }
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO sync_windows(provider, completed_through) VALUES (?1, ?2)
             ON CONFLICT(provider) DO UPDATE SET completed_through = excluded.completed_through,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
            params![provider, window.end],
        )?;
        tx.execute("DELETE FROM active_windows WHERE provider = ?1 AND next_cursor = ?2",
            params![provider, expected_cursor])?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resumes_same_window_without_advancing_watermark() {
        let mut store = Store::open(":memory:").unwrap();
        let start = "2026-10-22T00:00:00Z";
        let end = "2026-10-23T00:00:00Z";
        assert_eq!(store.begin_window("nvd", start, end).unwrap().next_cursor, 1);
        store.save_window_page("nvd", &[("CVE-2026-1234".into(), json!({"v":1}))], 1, 2).unwrap();
        assert_eq!(store.begin_window("nvd", start, end).unwrap().next_cursor, 2);
        assert!(store.begin_window("nvd", start, "2026-10-24T00:00:00Z").is_err());
        assert_eq!(store.completed_through("nvd").unwrap(), None);
        assert!(store.complete_active_window("nvd", 1).is_err());
        store.complete_active_window("nvd", 2).unwrap();
        assert_eq!(store.completed_through("nvd").unwrap().as_deref(), Some(end));
        assert!(store.active_window("nvd").unwrap().is_none());
    }

    #[test]
    fn invalid_page_does_not_advance_active_window() {
        let mut store = Store::open(":memory:").unwrap();
        store.begin_window("github", "2026-10-22T00:00:00Z", "2026-10-23T00:00:00Z").unwrap();
        assert!(store.save_window_page("github", &[("CVE-2026-1234".into(), json!({})), ("".into(), json!({}))], 1, 2).is_err());
        assert_eq!(store.active_window("github").unwrap().unwrap().next_cursor, 1);
        assert_eq!(store.observation_count("github").unwrap(), 0);
        assert_eq!(store.count("github").unwrap(), 0);
    }
}
