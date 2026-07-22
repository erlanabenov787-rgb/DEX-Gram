//! Периодическая уборка протухших mailbox-сообщений. Вызывается из
//! `services/background.rs` (когда появится) через `run_periodic`, но
//! логика вынесена сюда отдельно, чтобы её можно было тестировать без
//! поднятия целого tokio::spawn-цикла.

use std::sync::Arc;
use std::time::Duration;

use crate::storage::mailbox_store::MailboxStore;

/// Один проход уборки — удаляет все записи с истёкшим TTL.
/// Возвращает сколько записей удалено (для логов/метрик).
pub async fn cleanup_once(store: &Arc<dyn MailboxStore>) -> crate::errors::Result<usize> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    store.delete_expired(now).await
}

/// Бесконечный цикл уборки с заданным интервалом. Предполагается
/// запуск через `tokio::spawn(cleanup::run_periodic(store, interval))`
/// один раз при старте узла. Не паникует при единичной ошибке
/// хранилища (например временная блокировка SQLite) — логирует и
/// продолжает цикл, потому что одна пропущенная уборка не критична
/// (следующий проход всё равно доберёт протухшие записи), а вот
/// падение всего фонового таска из-за одной ошибки — критично.
pub async fn run_periodic(store: Arc<dyn MailboxStore>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        match cleanup_once(&store).await {
            Ok(deleted) if deleted > 0 => {
                tracing::info!("mailbox cleanup: удалено {deleted} протухших сообщений");
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("mailbox cleanup: ошибка при уборке, пропускаем проход: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::mailbox::storage::InMemoryMailboxStore;

    #[tokio::test]
    async fn cleanup_removes_only_expired() {
        let store: Arc<dyn MailboxStore> = Arc::new(InMemoryMailboxStore::new());

        // Уже протухшее (ttl_secs = 0 -> expires_at_unix = now)
        store.insert(&"bob".to_string(), b"old".to_vec(), 0).await.unwrap();
        // Ещё живое
        store
            .insert(&"bob".to_string(), b"fresh".to_vec(), 3600)
            .await
            .unwrap();

        // Небольшая пауза чтобы "old" гарантированно оказался в прошлом
        // относительно now() внутри cleanup_once.
        tokio::time::sleep(Duration::from_millis(1100)).await;

        let deleted = cleanup_once(&store).await.unwrap();
        assert_eq!(deleted, 1);

        let remaining = store.fetch_all(&"bob".to_string()).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].encrypted_blob, b"fresh");
    }
}
