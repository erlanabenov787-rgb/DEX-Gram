//! Высокоуровневая точка входа для mailbox-операций — то, что
//! `network/dispatcher.rs` вызывает когда приходит `PacketType::MAILBOX_STORE`
//! или `MAILBOX_FETCH` (см. protocol/message.proto). Знает про лимиты
//! (constants::MAILBOX_MAX_MESSAGES_PER_USER) и TTL, не знает про SQL —
//! это делегировано `storage::mailbox_store::MailboxStore`.

use std::sync::Arc;

use crate::constants::{MAILBOX_MAX_MESSAGES_PER_USER, MAILBOX_MESSAGE_TTL_DAYS};
use crate::errors::{MessengerError, Result};
use crate::identity::UserId;
use crate::storage::mailbox_store::MailboxStore;

pub struct MailboxService {
    store: Arc<dyn MailboxStore>,
}

impl MailboxService {
    pub fn new(store: Arc<dyn MailboxStore>) -> Self {
        Self { store }
    }

    /// Кладёт сообщение в mailbox получателя. Вызывается ОТПРАВИТЕЛЕМ
    /// через onion-цепочку (exit-узел = mailbox), не самим получателем.
    /// Проверяет лимит ПЕРЕД вставкой, а не после — иначе атакующий
    /// может завалить конкретного пользователя параллельными запросами
    /// быстрее, чем успеет сработать проверка (race condition), так что
    /// count_for_user + insert должны в идеале быть одной транзакцией;
    /// здесь это две операции — TODO при переходе на реальную
    /// многопоточную нагрузку обернуть в SQLite-транзакцию на уровне
    /// SqliteMailboxStore, сейчас это не атомарно.
    pub async fn store_message(&self, recipient: &UserId, encrypted_blob: Vec<u8>) -> Result<()> {
        let current_count = self.store.count_for_user(recipient).await?;
        if current_count >= MAILBOX_MAX_MESSAGES_PER_USER {
            return Err(MessengerError::MailboxFull {
                user: recipient.clone(),
                limit: MAILBOX_MAX_MESSAGES_PER_USER,
            });
        }

        let ttl_secs = (MAILBOX_MESSAGE_TTL_DAYS as u64) * 24 * 60 * 60;
        self.store.insert(recipient, encrypted_blob, ttl_secs).await
    }

    /// Получатель приходит онлайн и забирает свои сообщения. В отличие
    /// от старой in-memory версии (`fetch_and_clear`, которая сразу
    /// удаляла), здесь fetch и delete разделены на уровне вызывающего
    /// кода: dispatcher должен подтвердить доставку получателю
    /// (например успешная отправка по локальному соединению) прежде
    /// чем звать `acknowledge_delivered` — иначе сообщение теряется,
    /// если соединение с получателем оборвётся посреди передачи.
    pub async fn fetch_pending(&self, recipient: &UserId) -> Result<Vec<Vec<u8>>> {
        let entries = self.store.fetch_all(recipient).await?;
        Ok(entries.into_iter().map(|e| e.encrypted_blob).collect())
    }

    /// Вызывается ПОСЛЕ того как dispatcher подтвердил, что получатель
    /// реально получил сообщения из fetch_pending — тогда и только
    /// тогда они удаляются из mailbox.
    pub async fn acknowledge_delivered(&self, recipient: &UserId) -> Result<()> {
        let entries = self.store.fetch_all(recipient).await?;
        let ids: Vec<i64> = entries.iter().map(|e| e.id).collect();
        self.store.delete(recipient, &ids).await
    }
}

/// Свободная функция-обёртка для network/dispatcher.rs — тот вызывает
/// её когда onion-цепочка доходит до exit-узла и `DestinationHint`
/// говорит "получатель оффлайн, клади в mailbox". dispatcher не должен
/// сам решать про лимиты/TTL, поэтому просто зовёт готовый сервис.
pub async fn store_for_user(
    mailbox_service: &MailboxService,
    recipient: &UserId,
    encrypted_blob: Vec<u8>,
) -> Result<()> {
    mailbox_service.store_message(recipient, encrypted_blob).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::mailbox_store::SqliteMailboxStore;
    use rusqlite::Connection;

    fn test_service() -> MailboxService {
        let conn = Connection::open_in_memory().unwrap();
        let store = Arc::new(SqliteMailboxStore::open(conn).unwrap());
        MailboxService::new(store)
    }

    #[tokio::test]
    async fn store_and_fetch_roundtrip() {
        let service = test_service();
        let bob = "bob".to_string();

        service.store_message(&bob, b"msg1".to_vec()).await.unwrap();
        service.store_message(&bob, b"msg2".to_vec()).await.unwrap();

        let pending = service.fetch_pending(&bob).await.unwrap();
        assert_eq!(pending.len(), 2);

        // Ещё не acknowledge — должны остаться на месте.
        let pending_again = service.fetch_pending(&bob).await.unwrap();
        assert_eq!(pending_again.len(), 2);

        service.acknowledge_delivered(&bob).await.unwrap();
        let pending_after_ack = service.fetch_pending(&bob).await.unwrap();
        assert_eq!(pending_after_ack.len(), 0);
    }

    #[tokio::test]
    async fn rejects_over_limit() {
        let service = test_service();
        let bob = "bob".to_string();

        for i in 0..MAILBOX_MAX_MESSAGES_PER_USER {
            service
                .store_message(&bob, format!("msg{i}").into_bytes())
                .await
                .unwrap();
        }

        let result = service.store_message(&bob, b"overflow".to_vec()).await;
        assert!(matches!(result, Err(MessengerError::MailboxFull { .. })));
    }
}
