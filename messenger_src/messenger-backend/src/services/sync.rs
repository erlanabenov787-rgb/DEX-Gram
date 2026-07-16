//! Синхронизация при старте нода: немедленный mailbox fetch у всех known
//! relay + переопубликовка DHT-записи (на случай если мы были оффлайн и
//! запись устарела за время простоя).
//!
//! ВАЖНО: к моменту вызова `sync_on_startup` NodeHandle уже передан в
//! `run_with_commands(cmd_rx)`, поэтому взаимодействие идёт только через
//! `cmd_tx` — тот же паттерн, что и в services/background.rs.

use crate::config::StaticRelay;
use crate::network::NodeCommand;
use tokio::sync::mpsc::UnboundedSender;

/// Выполняет немедленную синхронизацию при старте нода:
///
/// 1. Отправляет `NodeCommand::FetchMailbox` каждому known relay — чтобы
///    получить сообщения, накопившиеся пока нод был оффлайн, не ждя
///    первого срабатывания периодической задачи (30 сек из background.rs).
///
/// 2. Отправляет `NodeCommand::RepublishDht` — переопубликуем DhtRecord
///    и PreKeyBundle немедленно, т.к. при долгом простое запись могла
///    вымыться из Kademlia (TTL = 24ч).
///
/// Вызывается из main.rs / src-tauri/lib.rs после `run_background_tasks`
/// но до `node.run_with_commands(cmd_rx)` — т.е. NodeHandle ещё не занят
/// event loop-ом, команды просто встанут в очередь и выполнятся сразу
/// после старта.
pub fn sync_on_startup(cmd_tx: &UnboundedSender<NodeCommand>, static_relays: &[StaticRelay]) {
    // 1. Немедленный mailbox fetch у всех known relay
    for relay in static_relays {
        let (respond_to, _rx) = tokio::sync::oneshot::channel();
        if cmd_tx
            .send(NodeCommand::FetchMailbox {
                relay_id: relay.relay_id.clone(),
                respond_to,
            })
            .is_err()
        {
            // Канал закрыт раньше чем мы успели запустить — не должно
            // происходить при нормальном порядке инициализации.
            tracing::warn!(
                "sync_on_startup: NodeCommand канал уже закрыт при FetchMailbox \
                 (relay {})",
                relay.relay_id
            );
            return;
        }
        tracing::debug!("sync_on_startup: MAILBOX_FETCH поставлен в очередь для relay {}", relay.relay_id);
    }

    // 2. Немедленный DHT republish
    if cmd_tx.send(NodeCommand::RepublishDht).is_err() {
        tracing::warn!("sync_on_startup: NodeCommand канал закрыт при RepublishDht");
        return;
    }

    tracing::info!(
        "sync_on_startup: MAILBOX_FETCH поставлен для {} relay(s), RepublishDht в очереди",
        static_relays.len()
    );
}
