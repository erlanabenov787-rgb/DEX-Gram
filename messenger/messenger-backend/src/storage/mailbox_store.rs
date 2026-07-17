//! Персистентное хранилище mailbox-сообщений. В исходном плоском
//! `network/mailbox.rs` было явно написано "продакшн-версия должна
//! писать это на диск" — вот эта версия. In-memory кэш поверх этого
//! живёт в `network/mailbox/storage.rs` (горячий путь), эта таблица —
//! источник истины, переживающий рестарт процесса.

use async_trait::async_trait;
use rusqlite::{params, Connection};
use std::sync::Mutex;

use crate::errors::Result;
use crate::identity::UserId;

pub struct StoredMailboxEntry {
    pub id: i64,
    pub encrypted_blob: Vec<u8>,
    pub stored_at_unix: u64,
    pub expires_at_unix: u64,
}

#[async_trait]
pub trait MailboxStore: Send + Sync {
    async fn insert(&self, recipient: &UserId, blob: Vec<u8>, ttl_secs: u64) -> Result<()>;
    async fn fetch_all(&self, recipient: &UserId) -> Result<Vec<StoredMailboxEntry>>;
    async fn delete(&self, recipient: &UserId, ids: &[i64]) -> Result<()>;
    async fn count_for_user(&self, recipient: &UserId) -> Result<usize>;
    /// Удаляет все записи с `expires_at_unix` в прошлом — вызывается
    /// периодически из `mailbox/cleanup.rs`, а не при каждом fetch,
    /// чтобы не платить эту цену на каждом запросе получателя.
    async fn delete_expired(&self, now_unix: u64) -> Result<usize>;
}

pub struct SqliteMailboxStore {
    conn: Mutex<Connection>,
}

impl SqliteMailboxStore {
    pub fn open(conn: Connection) -> Result<Self> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS mailbox_entries (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient       TEXT NOT NULL,
                encrypted_blob  BLOB NOT NULL,
                stored_at_unix  INTEGER NOT NULL,
                expires_at_unix INTEGER NOT NULL
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_mailbox_recipient ON mailbox_entries(recipient)",
            [],
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

#[async_trait]
impl MailboxStore for SqliteMailboxStore {
    async fn insert(&self, recipient: &UserId, blob: Vec<u8>, ttl_secs: u64) -> Result<()> {
        let now = now_unix();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO mailbox_entries (recipient, encrypted_blob, stored_at_unix, expires_at_unix)
             VALUES (?1, ?2, ?3, ?4)",
            params![recipient, blob, now as i64, (now + ttl_secs) as i64],
        )?;
        Ok(())
    }

    async fn fetch_all(&self, recipient: &UserId) -> Result<Vec<StoredMailboxEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, encrypted_blob, stored_at_unix, expires_at_unix
             FROM mailbox_entries WHERE recipient = ?1 ORDER BY stored_at_unix ASC",
        )?;
        let rows = stmt.query_map(params![recipient], |row| {
            Ok(StoredMailboxEntry {
                id: row.get(0)?,
                encrypted_blob: row.get(1)?,
                stored_at_unix: row.get::<_, i64>(2)? as u64,
                expires_at_unix: row.get::<_, i64>(3)? as u64,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    async fn delete(&self, recipient: &UserId, ids: &[i64]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock().unwrap();
        // rusqlite не поддерживает биндинг Vec напрямую в IN (...),
        // собираем плейсхолдеры вручную — ids приходят из наших же
        // fetch_all результатов, не от сети, так что инъекции тут нет.
        let placeholders: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        let query = format!(
            "DELETE FROM mailbox_entries WHERE recipient = ?1 AND id IN ({})",
            placeholders.join(",")
        );
        conn.execute(&query, params![recipient])?;
        Ok(())
    }

    async fn count_for_user(&self, recipient: &UserId) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM mailbox_entries WHERE recipient = ?1",
            params![recipient],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    async fn delete_expired(&self, now_unix: u64) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let deleted = conn.execute(
            "DELETE FROM mailbox_entries WHERE expires_at_unix <= ?1",
            params![now_unix as i64],
        )?;
        Ok(deleted)
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
