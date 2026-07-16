//! Синхронизация при старте нода: немедленный mailbox fetch у всех known
//! relay + переопубликовка DHT-записи (на случай если мы были оффлайн и
//! запись устарела за время простоя).
//!
//! ВАЖНО: к моменту вызова `sync_on_startup` NodeHandle уже передан в
//! `run_with_commands(cmd_rx)`, поэтому взаимодействие идёт только через
//! `cmd_tx` — тот же паттерн, что и в services/background.rs.

use std::sync::Arc;

use crate::network::relay::RelayRegistry;
use crate::network::NodeCommand;
use tokio::sync::mpsc::UnboundedSender;

/// Выполняет немедленную синхронизацию при старте нода:
///
/// 1. Отправляет `NodeCommand::FetchMailbox` каждому relay из реестра —
///    чтобы получить сообщения, накопившиеся пока нод был оффлайн.
///    Если реестр пуст (bootstrap ещё не ответил), шаг пропускается —
///    задачи подхватят relay позже через периодический фоновый fetch.
///
/// 2. Отправляет `NodeCommand::RepublishDht` — переопубликуем DhtRecord
///    и PreKeyBundle немедленно, т.к. при долгом простое запись могла
///    вымыться из Kademlia (TTL = 24ч).
///
/// Вызывается из main.rs / src-tauri/lib.rs после `run_background_tasks`
/// но до `node.run_with_commands(cmd_rx)` — т.е. NodeHandle ещё не занят
/// event loop-ом, команды просто встанут в очередь и выполнятся сразу
/// после старта.
pub fn sync_on_startup(cmd_tx: &UnboundedSender<NodeCommand>, registry: &Arc<RelayRegistry>) {
    let relay_ids = registry.relay_ids();

    // 1. Немедленный mailbox fetch у всех known relay
    for relay_id in &relay_ids {
        let (respond_to, _rx) = tokio::sync::oneshot::channel();
        if cmd_tx
            .send(NodeCommand::FetchMailbox {
                relay_id: relay_id.clone(),
                respond_to,
            })
            .is_err()
        {
            tracing::warn!(
                "sync_on_startup: NodeCommand канал уже закрыт при FetchMailbox \
                 (relay {})",
                relay_id
            );
            return;
        }
        tracing::debug!("sync_on_startup: MAILBOX_FETCH поставлен в очередь для relay {}", relay_id);
    }

    if relay_ids.is_empty() {
        tracing::info!(
            "sync_on_startup: реестр relay пуст (bootstrap ещё не ответил), \
             MAILBOX_FETCH пропущен — подхватится при обновлении реестра"
        );
    }

    // 2. Немедленный DHT republish
    if cmd_tx.send(NodeCommand::RepublishDht).is_err() {
        tracing::warn!("sync_on_startup: NodeCommand канал закрыт при RepublishDht");
        return;
    }

    tracing::info!(
        "sync_on_startup: MAILBOX_FETCH поставлен для {} relay(s), RepublishDht в очереди",
        relay_ids.len()
    );
}
