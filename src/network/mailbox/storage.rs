//! In-memory реализация `storage::mailbox_store::MailboxStore` —
//! то, чем был весь старый плоский `network/mailbox.rs` до разбивки.
//! Оставлена как облегчённый вариант для тестов и для узлов, которые
//! осознанно не хотят писать mailbox-данные на диск (например
//! transit-only relay без выделенного хранилища). Продакшн-путь —
//! `storage::mailbox_store::SqliteMailboxStore`.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::errors::Result;
use crate::identity::UserId;
use crate::storage::mailbox_store::{MailboxStore, StoredMailboxEntry};

struct InMemoryEntry {
    id: i64,
    encrypted_blob: Vec<u8>,
    stored_at_unix: u64,
    expires_at_unix: u64,
}

pub struct InMemoryMailboxStore {
    entries: Mutex<HashMap<UserId, Vec<InMemoryEntry>>>,
    next_id: Mutex<i64>,
}

impl InMemoryMailboxStore {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            next_id: Mutex::new(1),
        }
    }
}

impl Default for InMemoryMailboxStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MailboxStore for InMemoryMailboxStore {
    async fn insert(&self, recipient: &UserId, blob: Vec<u8>, ttl_secs: u64) -> Result<()> {
        let now = now_unix();
        let id = {
            let mut next_id = self.next_id.lock().unwrap();
            let id = *next_id;
            *next_id += 1;
            id
        };

        let mut entries = self.entries.lock().unwrap();
        entries.entry(recipient.clone()).or_default().push(InMemoryEntry {
            id,
            encrypted_blob: blob,
            stored_at_unix: now,
            expires_at_unix: now + ttl_secs,
        });
        Ok(())
    }

    async fn fetch_all(&self, recipient: &UserId) -> Result<Vec<StoredMailboxEntry>> {
        let entries = self.entries.lock().unwrap();
        Ok(entries
            .get(recipient)
            .map(|bucket| {
                bucket
                    .iter()
                    .map(|e| StoredMailboxEntry {
                        id: e.id,
                        encrypted_blob: e.encrypted_blob.clone(),
                        stored_at_unix: e.stored_at_unix,
                        expires_at_unix: e.expires_at_unix,
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn delete(&self, recipient: &UserId, ids: &[i64]) -> Result<()> {
        let mut entries = self.entries.lock().unwrap();
        if let Some(bucket) = entries.get_mut(recipient) {
            bucket.retain(|e| !ids.contains(&e.id));
            if bucket.is_empty() {
                entries.remove(recipient);
            }
        }
        Ok(())
    }

    async fn count_for_user(&self, recipient: &UserId) -> Result<usize> {
        let entries = self.entries.lock().unwrap();
        Ok(entries.get(recipient).map(|b| b.len()).unwrap_or(0))
    }

    async fn delete_expired(&self, now_unix: u64) -> Result<usize> {
        let mut entries = self.entries.lock().unwrap();
        let mut deleted = 0;
        for bucket in entries.values_mut() {
            let before = bucket.len();
            bucket.retain(|e| e.expires_at_unix > now_unix);
            deleted += before - bucket.len();
        }
        entries.retain(|_, bucket| !bucket.is_empty());
        Ok(deleted)
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_and_fetch_roundtrip() {
        let store = InMemoryMailboxStore::new();
        let bob = "bob".to_string();

        store.insert(&bob, b"1".to_vec(), 3600).await.unwrap();
        store.insert(&bob, b"2".to_vec(), 3600).await.unwrap();

        let fetched = store.fetch_all(&bob).await.unwrap();
        assert_eq!(fetched.len(), 2);

        let ids: Vec<i64> = fetched.iter().map(|e| e.id).collect();
        store.delete(&bob, &ids).await.unwrap();

        let after = store.fetch_all(&bob).await.unwrap();
        assert_eq!(after.len(), 0);
    }
}
